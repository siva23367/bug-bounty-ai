import asyncio
import fnmatch
import ipaddress
import socket
from urllib.parse import unquote, urlsplit, urlunsplit

from ..schemas import Policy


class ScopeError(ValueError):
    pass


def canonical(url: str) -> str:
    if any(ord(c) < 33 for c in url) or '\\' in url:
        raise ScopeError('Ambiguous URL characters rejected')
    p = urlsplit(url)
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
        raise ScopeError('Only HTTP(S) URLs without embedded credentials are allowed')
    try:
        host = p.hostname.encode('idna').decode().lower().rstrip('.')
        port = p.port
    except (ValueError, UnicodeError) as exc:
        raise ScopeError('Invalid hostname or port') from exc
    path = p.path or '/'
    decoded = unquote(path)
    if '%' in decoded or '\\' in decoded or any(ord(c) < 32 for c in decoded):
        raise ScopeError('Ambiguous encoded path rejected')
    if '..' in decoded.split('/') or '.' in decoded.split('/') or '//' in decoded or '?' in decoded or '#' in decoded:
        raise ScopeError('Ambiguous path rejected')
    if decoded.count('/') != path.count('/'):
        raise ScopeError('Encoded path separators rejected')
    authority = f'[{host}]' if ':' in host else host
    if port and port != (443 if p.scheme == 'https' else 80):
        authority += f':{port}'
    return urlunsplit((p.scheme, authority, path, p.query, ''))


def origin(url: str) -> str:
    p = urlsplit(canonical(url))
    return f'{p.scheme}://{p.netloc}'


def ensure_scope(url: str, policy: Policy) -> str:
    url = canonical(url)
    p = urlsplit(url)
    decoded_url = unquote(url)
    for excluded in policy.excluded_urls:
        if fnmatch.fnmatchcase(url, excluded) or fnmatch.fnmatchcase(decoded_url, excluded):
            raise ScopeError('URL matches an explicit exclusion')
    for entry in policy.scope:
        wildcard = '://*.' in entry.origin
        base = urlsplit(canonical(entry.origin.replace('://*.', '://', 1)))
        same_host = p.hostname == base.hostname if not wildcard else p.hostname.endswith('.' + base.hostname)
        prefix = entry.path_prefix.rstrip('/')
        path = unquote(p.path)
        if (same_host and p.scheme == base.scheme and (p.port or (443 if p.scheme == 'https' else 80)) ==
                (base.port or (443 if base.scheme == 'https' else 80)) and
                (not prefix or path == prefix or path.startswith(prefix + '/'))):
            return url
    raise ScopeError('URL is outside approved origins or path prefixes')


async def resolve_public(host: str, port: int, allow_loopback: bool = False) -> str:
    try:
        results = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError('Target DNS resolution failed') from exc
    addresses = list(dict.fromkeys(row[4][0] for row in results))
    if not addresses:
        raise ScopeError('No target addresses resolved')
    for value in addresses:
        ip = ipaddress.ip_address(value)
        public = ip.is_global and not ip.is_multicast and not ip.is_reserved
        if not public and not (allow_loopback and ip.is_loopback):
            raise ScopeError('Private, metadata, reserved and link-local addresses are prohibited')
    return addresses[0]
