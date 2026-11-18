from .base import finding


def detect(r):
    if 'text/html' not in r.headers.get('content-type', '') or r.status != 200:
        return []
    missing = [h for h in ('content-security-policy', 'x-content-type-options', 'referrer-policy') if h not in r.headers]
    if r.url.startswith('https:') and 'strict-transport-security' not in r.headers:
        missing.append('strict-transport-security')
    if not missing:
        return []
    return [finding(r, 'headers', 'Missing browser security headers', 'Info',
                    'Recommended hardening headers were absent on this response.',
                    'Missing headers alone do not establish an exploitable vulnerability or bounty eligibility.',
                    'Deploy appropriate CSP, HSTS, MIME-sniffing and referrer policies.', {'missing': missing})]
