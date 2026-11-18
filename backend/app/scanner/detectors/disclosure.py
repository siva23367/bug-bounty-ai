import re

from .base import finding


PATTERNS = {
    'private-key marker': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'AWS access-key identifier': r'\bAKIA[0-9A-Z]{16}\b',
    'stack trace': r'(Traceback \(most recent call last\)|Exception in thread| at [\w.$]+\([^\n]+:\d+\))',
}


def detect(r):
    signals = [name for name, pattern in PATTERNS.items() if re.search(pattern, r.text)]
    if not signals:
        return []
    return [finding(r, 'disclosure', 'Sensitive information indicators in response', 'Medium',
                    'Pattern matching detected possible debug output or secret material; values are not retained.',
                    'Examples and dummy values can match. Never use or validate discovered credentials.',
                    'Remove sensitive output, disable debug mode, and rotate any genuinely exposed secrets.', {'signals': signals})]
