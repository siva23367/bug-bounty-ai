import re

from .base import finding


def detect(r):
    if r.status == 200 and re.search(r'<title>\s*Index of\s', r.text, re.I) and re.search(r'(Parent Directory|<a[^>]+href=)', r.text, re.I):
        return [finding(r, 'directory', 'Directory index page observed', 'Low',
                        'The response resembles a web-server directory index.',
                        'Review whether the index reveals non-public files. Links were not downloaded by this detector.',
                        'Disable directory listing where not explicitly intended.')]
    return []
