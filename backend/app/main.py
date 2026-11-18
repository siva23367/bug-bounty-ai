import asyncio
import hmac
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sqlalchemy import select

from . import ai, integrations, reports
from .config import cipher, persistent_secret, settings
from .db import Audit, Base, Callback, Finding, Program, Scan, Session, audit, engine, now
from .scanner.engine import launch, load_policy, tasks
from .scanner.scope import ScopeError, canonical, ensure_scope, origin
from .scanner.transport import safe_url
from .schemas import Policy, Review, StartScan, Submission

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logging.getLogger('httpx').setLevel(logging.WARNING)
token = persistent_secret('api-token', settings.api_token, lambda: secrets.token_urlsafe(32))
start_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with Session.begin() as db:
        for scan in db.scalars(select(Scan).where(Scan.status.in_(['queued', 'running']))):
            scan.status, scan.finished_at = 'interrupted', now()
            scan.error = 'Server restarted. Scan was not resumed; inspect cleanup logs before starting again.'
    yield
    active = list(tasks.values())
    for task in active:
        task.cancel()
    await asyncio.gather(*active, return_exceptions=True)


app = FastAPI(title='Bug Bounty AI', version='1.0.0', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware('http')
async def security_headers(request, call_next):
    try:
        length = int(request.headers.get('content-length', '0') or 0)
    except ValueError:
        return Response('Invalid Content-Length', status_code=400)
    if length > 150000:
        return Response('Request too large', status_code=413)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


async def authorized(request: Request):
    supplied = request.headers.get('authorization', '')
    if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
        raise HTTPException(401, 'A valid local API token is required')


api = APIRouter(prefix='/api', dependencies=[Depends(authorized)])


def row_json(row):
    return jsonable_encoder({column.name: getattr(row, column.name) for column in row.__table__.columns})


def get_or_404(db, model, key):
    obj = db.get(model, key)
    if obj is None:
        raise HTTPException(404, 'Record not found')
    return obj


@app.get('/health')
def health():
    return {'status': 'ok'}


@api.get('/settings')
def configuration():
    return {'llm_configured': bool(settings.llm_base_url and settings.llm_model),
            'llm_local': urlsplit(settings.llm_base_url).hostname in {'127.0.0.1', '::1', 'localhost'},
            'callback_configured': bool(settings.callback_base_url), 'loopback_enabled': settings.allow_loopback_targets,
            'providers': {'hackerone': bool(settings.hackerone_token and settings.hackerone_username),
                          'bugcrowd': bool(settings.bugcrowd_token), 'intigriti': bool(settings.intigriti_token)}}


@api.post('/programs', status_code=201)
def create_program(policy: Policy):
    if policy.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(422, 'Permission must expire in the future')
    try:
        for entry in policy.scope:
            canonical(entry.origin.replace('://*.', '://'))
        for account in policy.accounts:
            if canonical(account.origin).rstrip('/') != origin(account.origin):
                raise ScopeError('Account origin must not include a path or query')
            allowed = False
            for entry in policy.scope:
                try:
                    ensure_scope(origin(account.origin) + entry.path_prefix, policy)
                    allowed = True
                    break
                except ScopeError:
                    continue
            if not allowed:
                raise ScopeError('Test account origin is outside approved scope')
        for case in policy.access_cases:
            ensure_scope(case.url, policy)
        for case in policy.stored_cases:
            ensure_scope(case.write_url, policy)
            ensure_scope(case.read_url, policy)
        for case in policy.ssrf_cases:
            ensure_scope(case.url, policy)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    data = policy.model_dump(mode='json')
    secret_data = {key: data.pop(key) for key in ('accounts', 'access_cases', 'stored_cases', 'ssrf_cases')}
    data['test_configuration'] = {key: len(value) for key, value in secret_data.items()}
    encrypted = cipher().encrypt(json.dumps(secret_data).encode()).decode()
    with Session.begin() as db:
        program = Program(name=policy.name, policy=data, secrets=encrypted)
        db.add(program)
        db.flush()
        result = {'id': program.id, 'name': program.name, 'policy': data, 'revoked': False}
    audit('program_approved', {'program_id': result['id'], 'source': policy.source_url})
    return result


@api.get('/programs')
def programs():
    with Session() as db:
        return [{'id': p.id, 'name': p.name, 'policy': p.policy, 'revoked': p.revoked}
                for p in db.scalars(select(Program).order_by(Program.id.desc()))]


@api.post('/programs/{program_id}/revoke')
async def revoke(program_id: int):
    with Session.begin() as db:
        get_or_404(db, Program, program_id).revoked = True
        ids = list(db.scalars(select(Scan.id).where(Scan.program_id == program_id, Scan.status.in_(['queued', 'running']))))
    for scan_id in ids:
        if scan_id in tasks:
            tasks[scan_id].cancel()
    audit('program_revoked', {'program_id': program_id})
    return {'revoked': True}


@api.post('/scans', status_code=202)
async def start_scan(options: StartScan):
    async with start_lock:
        with Session.begin() as db:
            program = get_or_404(db, Program, options.program_id)
            policy = load_policy(program)
            if program.revoked or policy.expires_at <= now():
                raise HTTPException(403, 'Authorization is revoked or expired')
            try:
                target = ensure_scope(options.target, policy)
            except ValueError as exc:
                raise HTTPException(403, str(exc)) from exc
            if set(options.active_modules) - set(policy.allowed_active):
                raise HTTPException(403, 'Active modules exceed approved program rules')
            for module, cases in [('access', policy.access_cases), ('stored', policy.stored_cases), ('ssrf', policy.ssrf_cases)]:
                if module in options.active_modules and not cases:
                    raise HTTPException(422, f'{module} requires explicitly configured test cases')
            if 'ssrf' in options.active_modules and not settings.callback_base_url.startswith('https://'):
                raise HTTPException(422, 'Configure your own HTTPS callback endpoint first')
            if db.scalar(select(Scan.id).where(Scan.status.in_(['queued', 'running'])).limit(1)):
                raise HTTPException(409, 'Only one scan may run at a time; stop or finish the current scan')
            scan = Scan(program_id=program.id, target=target, options=options.model_dump())
            db.add(scan)
            db.flush()
            scan_id = scan.id
        audit('scan_approved', {'active_modules': options.active_modules, 'approval_note': options.approval_note,
                                'target': safe_url(target)}, scan_id)
        launch(scan_id)
        return {'id': scan_id, 'status': 'queued'}


@api.get('/scans')
def scans():
    with Session() as db:
        return [row_json(s) for s in db.scalars(select(Scan).order_by(Scan.id.desc()).limit(200))]


@api.get('/scans/{scan_id}')
def scan_details(scan_id: int):
    with Session() as db:
        return {**row_json(get_or_404(db, Scan, scan_id)),
                'findings': [row_json(f) for f in db.scalars(select(Finding).where(Finding.scan_id == scan_id))],
                'logs': [row_json(a) for a in db.scalars(select(Audit).where(Audit.scan_id == scan_id).order_by(Audit.id))]}


@api.post('/scans/{scan_id}/stop')
async def stop_scan(scan_id: int):
    with Session.begin() as db:
        scan = get_or_404(db, Scan, scan_id)
        if scan.status not in {'queued', 'running'}:
            return {'status': scan.status}
        scan.status, scan.finished_at = 'stopped', now()
    task = tasks.get(scan_id)
    if task:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        tasks.pop(scan_id, None)
    audit('operator_stop', {}, scan_id)
    return {'status': 'stopped'}


@api.patch('/findings/{finding_id}/review')
def review(finding_id: int, body: Review):
    with Session.begin() as db:
        finding = get_or_404(db, Finding, finding_id)
        finding.status, finding.review_note, finding.severity, finding.cvss = body.status, body.note, body.severity, body.cvss
        scan_id = finding.scan_id
    audit('human_review', {'finding_id': finding_id, **body.model_dump()}, scan_id)
    return {'status': body.status}


@api.patch('/findings/{finding_id}/submission')
def submission(finding_id: int, body: Submission):
    with Session.begin() as db:
        finding = get_or_404(db, Finding, finding_id)
        if body.status != 'draft' and finding.status != 'confirmed':
            raise HTTPException(409, 'Confirm the finding through human review before recording a submission')
        finding.submission, finding.submission_url = body.status, body.url
        finding.reward_currency, finding.earned_cents, finding.pending_cents = body.currency, body.earned_cents, body.pending_cents
        scan_id = finding.scan_id
    audit('submission_recorded', {'finding_id': finding_id, **body.model_dump()}, scan_id)
    return {'status': body.status}


@api.post('/findings/{finding_id}/analyze')
async def analyze_finding(finding_id: int):
    with Session() as db:
        finding = get_or_404(db, Finding, finding_id)
    try:
        result = await ai.analyze(finding)
    except (ValueError, KeyError, IndexError, httpx.HTTPError, ValidationError) as exc:
        audit('ai_error', {'finding_id': finding_id, 'error_type': type(exc).__name__}, finding.scan_id)
        raise HTTPException(502, 'AI unavailable or returned invalid data. Check the local model/API configuration.') from exc
    with Session.begin() as db:
        db.get(Finding, finding_id).ai_analysis = result
    audit('ai_advisory_generated', {'finding_id': finding_id, 'target_data_sent_to_remote_provider': False,
                                    'scope': result['scope']}, finding.scan_id)
    return result


@api.get('/findings/{finding_id}/report/{format}')
def report(finding_id: int, format: Literal['md', 'html', 'pdf']):
    with Session() as db:
        finding = get_or_404(db, Finding, finding_id)
        content, media = reports.export(finding, format)
    audit('report_exported', {'finding_id': finding_id, 'format': format}, finding.scan_id)
    return Response(content, media_type=media, headers={'Content-Disposition': f'attachment; filename="finding-{finding_id}.{format}"'})


@api.get('/dashboard')
def dashboard():
    with Session() as db:
        findings = list(db.scalars(select(Finding)))
        all_scans = list(db.scalars(select(Scan.id)))
    totals = {name: sum(f.status == name for f in findings) for name in ('potential', 'confirmed', 'false_positive')}
    severities = {name: sum(f.severity == name and f.status != 'false_positive' for f in findings)
                  for name in ('Critical', 'High', 'Medium', 'Low', 'Info')}
    submissions = {name: sum(f.submission == name for f in findings) for name in ('submitted', 'accepted', 'rejected', 'duplicate')}
    submissions['submitted'] = sum(f.submission != 'draft' for f in findings)
    rewards = {}
    for f in findings:
        if f.earned_cents or f.pending_cents:
            amount = rewards.setdefault(f.reward_currency, {'earned_cents': 0, 'pending_cents': 0})
            amount['earned_cents'] += f.earned_cents
            amount['pending_cents'] += f.pending_cents
    return {'scans': len(all_scans), 'findings': len(findings), **totals, 'severities': severities,
            'submissions': submissions, 'rewards': rewards}


@api.get('/integrations/{provider}/{identifier}')
async def integration(provider: Literal['hackerone', 'bugcrowd', 'intigriti'], identifier: str):
    try:
        result = await integrations.program_details(provider, identifier)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, 'Provider request failed. Check credentials, access level, identifier and rate limits.') from exc
    audit('provider_lookup', {'provider': provider, 'identifier': identifier})
    return result


@api.get('/programs/{program_id}/subdomains')
async def subdomains(program_id: int, domain: str):
    with Session() as db:
        program = get_or_404(db, Program, program_id)
        policy = load_policy(program)
        if program.revoked or policy.expires_at <= now():
            raise HTTPException(403, 'Authorization is revoked or expired')
    try:
        result = await integrations.passive_subdomains(policy, domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, 'Certificate Transparency service unavailable') from exc
    audit('passive_lookup', {'program_id': program_id, 'domain': domain})
    return result


@app.get('/api/callback/{callback_token}', status_code=204)
def callback(callback_token: str):
    with Session.begin() as db:
        record = db.get(Callback, callback_token)
        if not record or record.expires_at.replace(tzinfo=timezone.utc) < now():
            raise HTTPException(404, 'Unknown or expired callback')
        scan = db.get(Scan, record.scan_id)
        program = db.get(Program, scan.program_id)
        if program.revoked or scan.status not in {'running', 'completed', 'limited'}:
            raise HTTPException(410, 'Scan is no longer accepting callbacks')
        if not record.received_at:
            record.received_at = now()
            db.add(Finding(scan_id=record.scan_id, category='ssrf', title='Controlled outbound callback received',
                endpoint=safe_url(record.endpoint), severity='Low',
                description='The operator-controlled callback endpoint received a valid, short-lived scan nonce.',
                impact='Outbound fetching is observed, not proof of exploitable SSRF; expected fetch features and security middleware can trigger callbacks.',
                remediation='Validate URL destinations, block internal networks, and constrain outbound connections.',
                evidence={'parameter': record.parameter, 'callback_received_at': record.received_at.isoformat()},
                steps=['Review the configured URL parameter and callback timestamp.', 'Confirm the request originated from the intended target workflow.',
                       'Do not probe internal networks, metadata services or other users\' data.'],
                eligibility='In approved scan scope; bounty eligibility unverified'))
            scan_id = record.scan_id
        else:
            return Response(status_code=204)
    audit('controlled_callback_received', {'parameter': record.parameter}, scan_id)
    return Response(status_code=204)


app.include_router(api)
if settings.frontend_dir.is_dir():
    app.mount('/assets', StaticFiles(directory=settings.frontend_dir / 'assets'), name='assets')

    @app.get('/')
    def index():
        return FileResponse(settings.frontend_dir / 'index.html')
