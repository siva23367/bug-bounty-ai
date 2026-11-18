from bs4 import BeautifulSoup

from .base import finding


def detect(r):
    if 'html' not in r.headers.get('content-type', ''):
        return []
    soup = BeautifulSoup(r.text, 'html.parser')
    count = 0
    for form in soup.find_all('form'):
        if str(form.get('method', 'get')).lower() == 'post':
            names = [str(node.get('name', '')).lower() for node in form.find_all('input')]
            if not any(any(token in name for token in ('csrf', 'xsrf', 'nonce', 'token')) for name in names):
                count += 1
    return [] if not count else [finding(r, 'csrf', 'POST forms without recognizable CSRF fields', 'Low',
        'No recognizable token field was found in some POST forms; no form was submitted.',
        'SameSite cookies, Origin checks or header tokens may already protect these forms.',
        'Verify server-side anti-CSRF checks on authorized state-changing actions.', {'form_count': count})]
