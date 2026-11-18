import re
from urllib.parse import urljoin, urlsplit

from ..scope import ScopeError
from .base import finding


def detect(r):
    path = urlsplit(r.url).path
    match = (path.endswith('/.env') and re.search(r'(?m)^(?:DB_PASSWORD|APP_KEY|DATABASE_URL|SECRET_KEY)\s*=', r.text))
    match = match or (path.endswith('/.git/HEAD') and re.fullmatch(r'\s*ref: refs/heads/[^\s]+\s*', r.text))
    if r.status == 200 and match:
        return [finding(r, 'exposure', 'Configuration artifact is publicly readable', 'Medium',
                        'A response matches the structure of a configuration or repository artifact. Contents are not retained.',
                        'Exposure may reveal deployment details or secrets. No repository or credential extraction was attempted.',
                        'Deny access to dotfiles and keep configuration outside the web root.', {'artifact_type': path.rsplit('/', 1)[-1]})]
    return []


async def probe(transport, target):
    results = []
    for path in ('/.env', '/.git/HEAD'):
        try:
            response = await transport.request(urljoin(target, path))
        except ScopeError:
            raise
        results.extend(detect(response))
    return results
