from .base import finding


def detect(r):
    if r.headers.get('access-control-allow-origin') != '*':
        return []
    return [finding(r, 'cors', 'Wildcard CORS policy observed', 'Info',
                    'This response permits cross-origin reads without credentials.',
                    'Often intentional for public APIs. Browsers reject wildcard origins with credentials.',
                    'Restrict origins only when the resource is not intended to be public.')]


async def probe(transport, r):
    test_origin = 'https://bbai-untrusted.invalid'
    result = await transport.request(r.url, headers={'Origin': test_origin})
    if result.headers.get('access-control-allow-origin') == test_origin:
        credentials = result.headers.get('access-control-allow-credentials', '').lower() == 'true'
        return [finding(result, 'cors', 'Untrusted Origin reflected in CORS response', 'Medium' if credentials else 'Low',
                        'A controlled invalid Origin was reflected by the server.',
                        'Credentialed exposure requires browser validation and sensitive test-account data.',
                        'Use a strict allowlist for credentialed origins.', {'credentialed': credentials, 'origin': test_origin})]
    return []
