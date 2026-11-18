import asyncio
import json
import logging
from dataclasses import asdict
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

import httpx
from sqlalchemy import select

from ..config import cipher
from ..db import Finding, Program, Scan, Session, audit, now
from ..schemas import Policy
from .detectors import PASSIVE, access, cors, exposure, redirect, reflection, sqli, ssrf, stored
from .recon import discover
from .scope import ScopeError, ensure_scope
from .transport import BudgetReached, Transport, safe_url

logger = logging.getLogger(__name__)
tasks: dict[int, asyncio.Task] = {}


def load_policy(program):
    data = dict(program.policy)
    if program.secrets:
        data.update(json.loads(cipher().decrypt(program.secrets.encode())))
    return Policy.model_validate(data)


def save_findings(scan_id, observations, policy):
    with Session.begin() as db:
        existing = {(f.category, f.endpoint, f.title) for f in db.scalars(select(Finding).where(Finding.scan_id == scan_id))}
        for observation in observations:
            key = (observation.category, observation.endpoint, observation.title)
            if key in existing:
                continue
            existing.add(key)
            db.add(Finding(scan_id=scan_id, **asdict(observation), eligibility=(
                'Excluded category: not bounty eligible' if observation.category in policy.excluded_categories
                else 'In approved scan scope; bounty eligibility unverified')))


def finish(scan_id, status, error=None):
    with Session.begin() as db:
        scan = db.get(Scan, scan_id)
        scan.status, scan.error, scan.finished_at = status, error, now()
    audit('scan_' + status, {'reason': error}, scan_id)


async def run(scan_id):
    try:
        with Session.begin() as db:
            scan = db.get(Scan, scan_id)
            if scan.status != 'queued':
                return
            policy = load_policy(db.get(Program, scan.program_id))
            target, active = scan.target, set(scan.options['active_modules'])
            scan.status = 'running'
        transport = Transport(scan_id, policy)
        audit('scan_running', {'active_modules': sorted(active)}, scan_id)
        inventory = {'pages': [], 'excluded_urls': [], 'forms': [], 'technologies': [], 'policy_links': [], 'notes': []}
        robots = RobotFileParser()
        robots.parse([])
        for path in ('/robots.txt', '/.well-known/security.txt'):
            url = urljoin(target, path)
            try:
                ensure_scope(url, policy)
            except ScopeError:
                audit('recon_path_skipped', {'url': safe_url(url), 'reason': 'outside scope'}, scan_id)
                continue
            response = await transport.request(url)
            if path == '/robots.txt' and response.status == 200:
                robots.parse(response.text.splitlines())
                transport.robots = robots
                crawl_delay = robots.crawl_delay('BugBountyAI')
                if crawl_delay and crawl_delay > 1 / policy.requests_per_second:
                    transport.policy.requests_per_second = 1 / crawl_delay
            elif response.status == 200:
                inventory['policy_links'] = [line.split(':', 1)[1].strip()[:2000] for line in response.text.splitlines()
                                             if line.lower().startswith('policy:')][:20]
        queue, visited = [target], set()
        page_probes = {'reflection': reflection.probe, 'sqli': sqli.probe, 'redirect': redirect.probe, 'cors': cors.probe}
        while queue and len(visited) < policy.max_pages:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            if not robots.can_fetch('BugBountyAI', url):
                audit('robots_disallowed', {'url': safe_url(url)}, scan_id)
                continue
            response = await transport.request(url)
            for detect in PASSIVE:
                save_findings(scan_id, detect(response), policy)
            recon = discover(response, policy)
            inventory['pages'].append({'url': safe_url(url), 'status': response.status, 'parameters': recon['parameters'],
                                       'sha256': response.digest, 'truncated': response.truncated})
            inventory['excluded_urls'] = list(dict.fromkeys(inventory['excluded_urls'] + recon['excluded']))[:500]
            inventory['forms'].extend(recon['forms'])
            inventory['technologies'] = sorted(set(inventory['technologies'] + recon['technologies']))
            with Session.begin() as db:
                db.get(Scan, scan_id).inventory = dict(inventory)
            for module in sorted(active & page_probes.keys()):
                save_findings(scan_id, await page_probes[module](transport, response), policy)
            if response.status in {301, 302, 303, 307, 308} and response.headers.get('location'):
                redirected = urljoin(url, response.headers['location'])
                try:
                    recon['links'].append(ensure_scope(redirected, policy))
                except ScopeError:
                    audit('redirect_blocked', {'destination': safe_url(redirected)}, scan_id)
            queue.extend(link for link in recon['links'] if link not in visited and link not in queue)
            queue = queue[:300]
        if not inventory['pages']:
            raise ScopeError('No target pages could be scanned under the approved scope and robots policy')
        if 'exposure' in active:
            save_findings(scan_id, await exposure.probe(transport, target), policy)
        for module, probe in (('access', access.probe), ('stored', stored.probe), ('ssrf', ssrf.probe)):
            if module in active:
                save_findings(scan_id, await probe(transport, policy), policy)
        finish(scan_id, 'completed')
    except asyncio.CancelledError:
        finish(scan_id, 'stopped', 'Stopped by operator; review cleanup logs for any stored-marker test.')
        raise
    except BudgetReached as exc:
        finish(scan_id, 'limited', str(exc))
    except (ScopeError, ValueError) as exc:
        finish(scan_id, 'failed', str(exc))
    except httpx.HTTPError as exc:
        finish(scan_id, 'failed', f'HTTP transport failure: {type(exc).__name__}')
    except Exception as exc:
        logger.error('Scan %s failed: %s', scan_id, type(exc).__name__)
        finish(scan_id, 'failed', f'Unexpected scan error: {type(exc).__name__}; inspect server diagnostics.')
    finally:
        tasks.pop(scan_id, None)


def launch(scan_id):
    tasks[scan_id] = asyncio.create_task(run(scan_id))
