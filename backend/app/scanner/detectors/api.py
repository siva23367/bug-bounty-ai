import json

from .base import finding


def detect(r):
    if 'json' not in r.headers.get('content-type', '') or r.status != 200:
        return []
    try:
        data = json.loads(r.text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict) and ('openapi' in data or 'swagger' in data):
        return [finding(r, 'api', 'Public API specification discovered', 'Info',
                        'An unauthenticated response contains an API specification.',
                        'Public documentation is normally intentional; specification exposure alone is not a vulnerability.',
                        'Ensure documented endpoints enforce their own authentication and authorization.')]
    return []
