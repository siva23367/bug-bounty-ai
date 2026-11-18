import json
import time
from datetime import timedelta

import pytest

from app.config import settings
from app.db import Callback, Program, Session, now


def create(client, policy):
    response = client.post('/api/programs', json=policy)
    assert response.status_code == 201, response.text
    return response.json()['id']


def start(client, program_id, target, modules=None):
    response = client.post('/api/scans', json={'program_id': program_id, 'target': target,
                           'active_modules': modules or [], 'active_approved': bool(modules),
                           'approval_note': 'Explicit approval for disposable local fixture tests.' if modules else ''})
    assert response.status_code == 202, response.text
    return response.json()['id']


def wait(client, scan_id):
    for _ in range(200):
        response = client.get(f'/api/scans/{scan_id}')
        assert response.status_code == 200
        result = response.json()
        if result['status'] not in {'queued', 'running'}:
            return result
        time.sleep(.05)
    pytest.fail('Scan failed to finish within 10 seconds')


def test_auth_scope_approval_and_encrypted_accounts(client, policy, target):
    assert client.get('/api/dashboard', headers={'Authorization': ''}).status_code == 401
    policy['accounts'] = [{'name': 'owner', 'origin': target, 'headers': {'Authorization': 'Bearer secret-not-logged'}}]
    pid = create(client, policy)
    assert 'secret-not-logged' not in client.get('/api/programs').text
    with Session() as db:
        program = db.get(Program, pid)
        assert 'secret-not-logged' not in program.secrets
        assert 'secret-not-logged' not in json.dumps(program.policy)
    assert client.post('/api/scans', json={'program_id': pid, 'target': 'http://127.0.0.1:1/'}).status_code == 403
    assert client.post('/api/scans', json={'program_id': pid, 'target': target, 'active_modules': ['reflection']}).status_code == 422
    client.post(f'/api/programs/{pid}/revoke')
    assert client.post('/api/scans', json={'program_id': pid, 'target': target}).status_code == 403


def test_real_scan_review_and_all_report_formats(client, policy, target):
    pid = create(client, policy)
    result = wait(client, start(client, pid, target, ['reflection']))
    assert result['status'] == 'completed', result
    assert any(f['category'] == 'reflection' for f in result['findings'])
    assert all(f['status'] == 'potential' for f in result['findings'])
    assert result['inventory']['excluded_urls']
    assert any(e['event'] == 'robots_disallowed' for e in result['logs'])
    assert 'secret-cookie' not in json.dumps(result)
    finding = next(f for f in result['findings'] if f['category'] == 'reflection')
    fid = finding['id']
    for format, prefix in [('md', b'## Title'), ('html', b'<!doctype html>'), ('pdf', b'%PDF')]:
        response = client.get(f'/api/findings/{fid}/report/{format}')
        assert response.status_code == 200
        assert response.content.startswith(prefix)
    assert client.patch(f'/api/findings/{fid}/submission', json={'status': 'submitted', 'url': 'https://example.invalid/report/1'}).status_code == 409
    response = client.patch(f'/api/findings/{fid}/review', json={'status': 'confirmed', 'severity': 'Low', 'note': 'Verified local test marker behavior and its intentionally limited impact.', 'cvss': '3.1'})
    assert response.status_code == 200
    assert client.patch(f'/api/findings/{fid}/submission', json={'status': 'accepted', 'url': 'https://example.invalid/report/1', 'earned_cents': 12345}).status_code == 200
    dashboard = client.get('/api/dashboard').json()
    assert dashboard['confirmed'] == 1
    assert dashboard['rewards'] == {'USD': {'earned_cents': 12345, 'pending_cents': 0}}


@pytest.mark.parametrize('path,module,category', [('/database?q=abc', 'sqli', 'sqli'), ('/go?next=/', 'redirect', 'redirect'), ('/cors', 'cors', 'cors'), ('/', 'exposure', 'exposure')])
def test_active_modules_use_real_requests(client, policy, target, path, module, category):
    result = wait(client, start(client, create(client, policy), target + path, [module]))
    assert result['status'] == 'completed', result
    assert any(f['category'] == category for f in result['findings'])


def test_account_checks_stored_marker_and_cleanup_audit(client, policy, target):
    policy['accounts'] = [{'name': name, 'origin': target, 'headers': {'Authorization': 'Bearer ' + name + '-test'}} for name in ['owner', 'other']]
    policy['access_cases'] = [{'url': target + '/owned-resource', 'owner_account': 'owner', 'other_account': 'other',
                              'owned_resource_marker': 'disposable-owned-marker-12345', 'private_resource_attested': True}]
    policy['stored_cases'] = [{'write_url': target + '/stored', 'read_url': target + '/stored', 'account': 'owner', 'field': 'message',
                              'cleanup_instructions': 'Discard the isolated disposable test fixture after the test run.', 'disposable_test_resource_attested': True}]
    result = wait(client, start(client, create(client, policy), target, ['access', 'stored']))
    assert result['status'] == 'completed', result
    assert {'access', 'stored'} <= {f['category'] for f in result['findings']}
    assert any(log['event'] == 'cleanup_required' for log in result['logs'])
    assert 'Bearer owner-test' not in json.dumps(result)


def test_budget_stop_and_concurrent_scan_guard(client, policy, target):
    pid = create(client, policy)
    sid = start(client, pid, target + '/slow')
    assert client.post('/api/scans', json={'program_id': pid, 'target': target}).status_code == 409
    time.sleep(.5)
    assert client.post(f'/api/scans/{sid}/stop').status_code == 200
    stopped = wait(client, sid)
    assert stopped['status'] == 'stopped'
    count = stopped['request_count']
    time.sleep(.3)
    assert client.get(f'/api/scans/{sid}').json()['request_count'] == count
    policy['max_requests'] = 2
    result = wait(client, start(client, create(client, policy), target))
    assert result['status'] == 'limited'
    assert result['request_count'] == 2


def test_callback_nonce_expiry_deduplication_and_unverified_status(client, policy, target):
    sid = start(client, create(client, policy), target)
    wait(client, sid)
    with Session.begin() as db:
        db.add(Callback(token='dedicated-test-nonce', scan_id=sid, endpoint=target + '/fetch?url=test', parameter='url', expires_at=now() + timedelta(minutes=1)))
        db.add(Callback(token='expired-test-nonce', scan_id=sid, endpoint=target, parameter='url', expires_at=now() - timedelta(seconds=1)))
    assert client.get('/api/callback/unknown').status_code == 404
    assert client.get('/api/callback/expired-test-nonce').status_code == 404
    for _ in range(2):
        assert client.get('/api/callback/dedicated-test-nonce', headers={'Authorization': ''}).status_code == 204
    findings = [f for f in client.get(f'/api/scans/{sid}').json()['findings'] if f['category'] == 'ssrf']
    assert len(findings) == 1
    assert findings[0]['status'] == 'potential'


def test_unconfigured_ai_and_reward_validation(client, policy, target, monkeypatch):
    monkeypatch.setattr(settings, 'llm_base_url', '')
    result = wait(client, start(client, create(client, policy), target))
    fid = result['findings'][0]['id']
    assert client.post(f'/api/findings/{fid}/analyze').status_code == 502
    assert client.patch(f'/api/findings/{fid}/submission', json={'status': 'draft', 'earned_cents': 100}).status_code == 422


def test_plaintext_rules_never_grant_active_permission(client, policy, target):
    policy['allowed_active'] = []
    pid = create(client, policy)
    response = client.post('/api/scans', json={'program_id': pid, 'target': target, 'active_modules': ['reflection'],
                                             'active_approved': True, 'approval_note': 'This note must not override the approved program policy.'})
    assert response.status_code == 403
