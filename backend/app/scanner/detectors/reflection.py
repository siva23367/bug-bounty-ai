import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .base import finding


def mutate(url, key, value):
    p = urlsplit(url)
    pairs = [(k, value if k == key else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), ''))


async def probe(transport, r):
    output = []
    for key in dict(parse_qsl(urlsplit(r.url).query, keep_blank_values=True)):
        marker = '<bbai-' + secrets.token_hex(8) + '>'
        response = await transport.request(mutate(r.url, key, marker))
        if marker in response.text and 'html' in response.headers.get('content-type', ''):
            item = finding(response, 'reflection', 'Unescaped inert HTML marker reflected', 'Low',
                           'An inert custom-element marker was reflected verbatim. No JavaScript was executed.',
                           'This is an HTML-reflection indicator, not proof of executable XSS. Context and browser controls matter.',
                           'Use context-appropriate output encoding and a restrictive CSP.', {'parameter': key, 'marker': marker})
            item.steps.append(f'Replace the {key!r} query value with the inert marker shown in the evidence.')
            output.append(item)
    return output
