import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

temporary = tempfile.TemporaryDirectory(prefix='bbai-tests-')
os.environ['DATA_DIR'] = temporary.name
os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(temporary.name) / 'tests.db')
os.environ['API_TOKEN'] = 'local-test-token-not-a-real-credential'
os.environ['ALLOW_LOOPBACK_TARGETS'] = 'true'

from app.db import Base, Session, engine
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    with TestClient(app, headers={'Authorization': 'Bearer local-test-token-not-a-real-credential'}) as test_client:
        yield test_client


@pytest.fixture(scope='session')
def target():
    fixture = FastAPI()
    stored = {'value': ''}

    @fixture.get('/robots.txt')
    def robots():
        return PlainTextResponse('User-agent: *\nDisallow: /blocked\n')

    @fixture.get('/.well-known/security.txt')
    def security():
        return PlainTextResponse('Contact: mailto:security@example.invalid\n')

    @fixture.get('/')
    def index():
        return HTMLResponse('<html><title>Owned local test fixture</title><a href="/search?q=hello">Search</a>'
                            '<a href="http://127.0.0.1:1/outside">Out of scope</a>'
                            '<a href="/blocked">Robots excluded</a></html>', headers={'Set-Cookie': 'session=secret-cookie; Path=/'})

    @fixture.get('/search')
    def search(q: str = ''):
        return HTMLResponse('<p>' + q + '</p>')

    @fixture.get('/database')
    def database(q: str = ''):
        return PlainTextResponse('SQLSTATE[42000] syntax error' if "'" in q else 'No errors')

    @fixture.get('/go')
    def redirect(next: str = '/'):
        return RedirectResponse(next)

    @fixture.get('/cors')
    def cors(request: Request):
        return PlainTextResponse('public test fixture', headers={
            'Access-Control-Allow-Origin': request.headers.get('origin', 'https://example.invalid'),
            'Access-Control-Allow-Credentials': 'true'})

    @fixture.get('/.env')
    def config():
        return PlainTextResponse('DB_PASSWORD=not-a-real-secret\n')

    @fixture.get('/.git/HEAD')
    def git_head():
        return PlainTextResponse('ref: refs/heads/test-fixture\n')

    @fixture.get('/owned-resource')
    def resource(request: Request):
        if request.headers.get('authorization') in {'Bearer owner-test', 'Bearer other-test'}:
            return PlainTextResponse('disposable-owned-marker-12345')
        return PlainTextResponse('authentication required', status_code=401)

    @fixture.post('/stored')
    async def write(request: Request):
        from urllib.parse import parse_qs
        stored['value'] = parse_qs((await request.body()).decode()).get('message', [''])[0]
        return PlainTextResponse('saved')

    @fixture.get('/stored')
    def read():
        return HTMLResponse(stored['value'])

    @fixture.get('/slow')
    async def slow():
        import asyncio
        await asyncio.sleep(3)
        return HTMLResponse('slow page')

    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(fixture, log_level='error', lifespan='off'))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(.02)
    assert server.started
    yield f'http://127.0.0.1:{port}'
    server.should_exit = True
    thread.join(timeout=10)
    sock.close()


@pytest.fixture
def policy(target):
    from datetime import datetime, timedelta, timezone
    return {'name': 'Owned local fixture', 'source_url': 'https://example.invalid/written-permission',
            'permission_reference': 'Local fixture owned and operated exclusively by this test suite.',
            'rules_text': 'Only disposable local fixture endpoints; non-destructive automated testing is permitted.',
            'scope': [{'origin': target}], 'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            'permission_attested': True, 'automation_allowed': True, 'rules_reviewed': True,
            'requests_per_second': 5, 'max_requests': 50, 'max_pages': 5,
            'allowed_active': ['reflection', 'sqli', 'cors', 'redirect', 'exposure', 'access', 'stored', 'ssrf']}
