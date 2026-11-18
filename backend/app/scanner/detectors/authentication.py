from bs4 import BeautifulSoup
from urllib.parse import urljoin

from .base import finding


def detect(r):
    if 'html' not in r.headers.get('content-type', ''):
        return []
    soup = BeautifulSoup(r.text, 'html.parser')
    for form in soup.find_all('form'):
        if form.find('input', attrs={'type': 'password'}) and (
            r.url.startswith('http:') or urljoin(r.url, str(form.get('action', ''))).startswith('http:')
        ):
            return [finding(r, 'authentication', 'Password form uses insecure transport', 'Medium',
                            'A password form was observed on HTTP or with an HTTP submission URL. No credentials were submitted.',
                            'Network interception may be possible; browser upgrade policies require verification.',
                            'Serve login pages and form actions exclusively over HTTPS with HSTS.')]
    return []
