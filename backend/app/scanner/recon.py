import json
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup

from .scope import ScopeError, ensure_scope
from .transport import safe_url

UNSAFE_NAVIGATION = re.compile(r'(?:^|[/_?&=.-])(logout|logoff|delete|remove|unsubscribe|purchase|checkout|reset|destroy)(?:$|[/_?&=.-])', re.I)


def discover(response, policy):
    links = set()
    forms = []
    technologies = set()
    content_type = response.headers.get('content-type', '')
    if 'html' in content_type:
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.select('a[href], script[src], link[href]')[:300]:
            if tag.name == 'link' and 'stylesheet' not in tag.get('rel', []):
                continue
            links.add(urljoin(response.url, str(tag.get('href') or tag.get('src'))))
        for form in soup.find_all('form')[:30]:
            forms.append({'action': safe_url(urljoin(response.url, str(form.get('action', '')))),
                          'method': str(form.get('method', 'get')).upper(),
                          'parameters': [str(n.get('name')) for n in form.select('[name]')[:50]]})
        if soup.find(id='__next') or '/_next/' in response.text:
            technologies.add('Next.js indicator')
        if '/wp-content/' in response.text:
            technologies.add('WordPress indicator')
    if 'javascript' in content_type or urlsplit(response.url).path.endswith('.js'):
        for match in re.finditer(r'''["'`]((?:/api/|/v[1-9]/)[a-zA-Z0-9_./?=&%-]{1,200})["'`]''', response.text):
            links.add(urljoin(response.url, match.group(1)))
            if len(links) >= 300:
                break
    if 'json' in content_type:
        try:
            spec = json.loads(response.text)
        except json.JSONDecodeError:
            spec = None
        if isinstance(spec, dict) and ('openapi' in spec or 'swagger' in spec) and isinstance(spec.get('paths'), dict):
            for path, methods in list(spec['paths'].items())[:100]:
                if '{' not in path and isinstance(methods, dict) and 'get' in methods:
                    links.add(urljoin(response.url, path))
    server = response.headers.get('server', '').lower()
    for name in ('nginx', 'apache', 'cloudflare', 'caddy', 'uvicorn'):
        if name in server:
            technologies.add(name + ' header indicator')
    permitted, excluded = [], []
    for url in sorted(links):
        try:
            url = ensure_scope(url, policy)
            if UNSAFE_NAVIGATION.search(url):
                raise ScopeError('Potentially state-changing navigation skipped')
            permitted.append(url)
        except (ScopeError, ValueError):
            excluded.append(safe_url(url))
    return {'links': permitted, 'excluded': excluded, 'forms': forms,
            'technologies': sorted(technologies),
            'parameters': list(dict(parse_qsl(urlsplit(response.url).query, keep_blank_values=True)))}
