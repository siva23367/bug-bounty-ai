import secrets
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...config import settings
from ...db import Callback, Session, now
from ..scope import ScopeError


async def probe(transport, policy):
    if not settings.callback_base_url.startswith('https://'):
        raise ScopeError('SSRF checks require your own HTTPS CALLBACK_BASE_URL serving this application')
    for case in policy.ssrf_cases:
        token = secrets.token_urlsafe(32)
        with Session.begin() as db:
            db.add(Callback(token=token, scan_id=transport.scan_id, endpoint=case.url,
                            parameter=case.parameter, expires_at=now() + timedelta(minutes=15)))
        p = urlsplit(case.url)
        query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != case.parameter]
        query.append((case.parameter, settings.callback_base_url.rstrip('/') + '/api/callback/' + token))
        await transport.request(urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), '')))
    return []
