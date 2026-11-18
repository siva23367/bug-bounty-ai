from urllib.parse import parse_qsl, urljoin, urlsplit

from .base import finding
from .reflection import mutate


async def probe(transport, r):
    output = []
    for key in dict(parse_qsl(urlsplit(r.url).query, keep_blank_values=True)):
        if key.lower() not in {'url', 'next', 'redirect', 'redirect_uri', 'return', 'returnurl', 'continue'}:
            continue
        response = await transport.request(mutate(r.url, key, 'https://bbai-redirect.invalid/'))
        location = urljoin(response.url, response.headers.get('location', ''))
        if response.status in {301, 302, 303, 307, 308} and urlsplit(location).hostname == 'bbai-redirect.invalid':
            output.append(finding(response, 'redirect', 'External redirect accepted', 'Low',
                                  'A supplied invalid-domain URL was used in a redirect. The redirect was not followed.',
                                  'Some redirect endpoints are intentional; assess trust-boundary impact and program eligibility.',
                                  'Use a strict destination allowlist or relative redirect paths.', {'parameter': key, 'destination': 'https://bbai-redirect.invalid/'}))
    return output
