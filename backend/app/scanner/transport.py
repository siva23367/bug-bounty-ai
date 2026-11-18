import asyncio
import hashlib
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

import httpx

from ..config import settings
from ..db import Program, Scan, Session, audit
from ..schemas import Policy
from .scope import ScopeError, ensure_scope, resolve_public


def safe_url(url: str) -> str:
    p = urlsplit(url)
    query = urlencode([(key, '[redacted]') for key, _ in parse_qsl(p.query, keep_blank_values=True)])
    return urlunsplit((p.scheme, p.netloc, p.path, query, ''))


@dataclass
class Response:
    url: str
    status: int
    headers: httpx.Headers
    text: str
    digest: str
    truncated: bool = False


class BudgetReached(Exception):
    pass


class Transport:
    def __init__(self, scan_id: int, policy: Policy):
        self.scan_id = scan_id
        self.policy = policy
        self.last_request = 0.0
        self.robots = None

    async def request(self, url: str, *, method: str = 'GET', headers: dict | None = None,
                      data: dict | None = None) -> Response:
        url = ensure_scope(url, self.policy)
        if method in {'GET', 'HEAD'} and re.search(
            r'(?:^|[/_?&=.-])(logout|logoff|delete|remove|unsubscribe|purchase|checkout|reset|destroy)(?:$|[/_?&=.-])',
            unquote(url), re.I,
        ):
            raise ScopeError('Potentially state-changing GET navigation rejected')
        if self.robots is not None and not self.robots.can_fetch('BugBountyAI', url):
            raise ScopeError('Request prohibited by robots.txt')
        if method not in {'GET', 'HEAD', 'POST'}:
            raise ScopeError('HTTP method not supported')
        if method == 'POST' and not any(ensure_scope(c.write_url, self.policy) == url for c in self.policy.stored_cases):
            raise ScopeError('POST is limited to explicitly configured disposable stored-test resources')
        delay = 1 / self.policy.requests_per_second - (time.monotonic() - self.last_request)
        if delay > 0:
            await asyncio.sleep(delay)
        with Session.begin() as db:
            scan = db.get(Scan, self.scan_id)
            program = db.get(Program, scan.program_id)
            if scan.status != 'running' or program.revoked:
                raise ScopeError('Scan stopped or permission revoked')
            if self.policy.expires_at <= datetime.now(timezone.utc):
                raise ScopeError('Authorization expired')
            if scan.request_count >= self.policy.max_requests:
                raise BudgetReached('Approved request budget exhausted')
            scan.request_count += 1
        self.last_request = time.monotonic()
        audit('request_started', {'method': method, 'url': safe_url(url)}, self.scan_id)
        p = urlsplit(url)
        ip = await resolve_public(p.hostname, p.port or (443 if p.scheme == 'https' else 80), settings.allow_loopback_targets)
        pinned = httpx.URL(url).copy_with(host=ip)
        request_headers = {'User-Agent': 'BugBountyAI/1.0 (authorized research)', 'Accept-Encoding': 'identity'}
        request_headers.update(headers or {})
        request_headers['Host'] = p.netloc
        try:
            # Pin the connection to the validated IP; retain original TLS SNI/certificate validation.
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
                async with client.stream(method, pinned, headers=request_headers, data=data,
                                         extensions={'sni_hostname': p.hostname}) as response:
                    if response.headers.get('content-encoding', 'identity').lower() != 'identity':
                        raise ScopeError('Compressed response rejected to bound decompression resource use')
                    body = bytearray()
                    truncated = False
                    async for chunk in response.aiter_bytes(chunk_size=16384):
                        remaining = 524288 - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    result = Response(url, response.status_code, response.headers,
                                      bytes(body).decode('utf-8', errors='replace'),
                                      hashlib.sha256(body).hexdigest(), truncated)
            audit('request_finished', {'method': method, 'url': safe_url(url), 'status': result.status,
                                      'bytes': len(body), 'sha256': result.digest, 'truncated': truncated}, self.scan_id)
            if result.status == 429:
                raise BudgetReached('Target returned 429; scan stopped instead of retrying')
            return result
        except httpx.HTTPError as exc:
            audit('request_error', {'url': safe_url(url), 'error_type': type(exc).__name__}, self.scan_id)
            raise
