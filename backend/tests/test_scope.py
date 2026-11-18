import socket

import pytest

from app.scanner.scope import ScopeError, canonical, ensure_scope, resolve_public
from app.schemas import Policy


def test_scope_excludes_wildcard_apex_paths_and_ports(policy):
    policy['scope'] = [{'origin': 'https://*.example.com', 'path_prefix': '/app'}]
    policy['excluded_urls'] = ['https://*.example.com/app/admin*']
    p = Policy.model_validate(policy)
    assert ensure_scope('https://shop.example.com/app/search?q=1', p)
    for url in ['https://example.com/app', 'https://example.com.evil.test/app', 'https://shop.example.com/application',
                'https://shop.example.com:444/app', 'https://shop.example.com/app/admin',
                'https://shop.example.com/app/%61dmin', 'http://shop.example.com/app']:
        with pytest.raises(ScopeError):
            ensure_scope(url, p)


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'https://user:password@example.com', 'https://example.com/a/%252e%252e/b',
                               'https://example.com/a%2fb', 'https://example.com/..%2fadmin', 'https://example.com\\evil',
                               'https://example.com/\n', 'https://example.com/%00', 'https://example.com/a//b',
                               'https://example.com/%2561dmin'])
def test_reject_ambiguous_urls(url):
    with pytest.raises(ScopeError):
        canonical(url)


@pytest.mark.asyncio
async def test_private_dns_and_mixed_answers_are_blocked(monkeypatch):
    import asyncio
    async def dns(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
    monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', dns)
    with pytest.raises(ScopeError, match='Private'):
        await resolve_public('example.com', 443)


@pytest.mark.asyncio
async def test_loopback_requires_explicit_lab_setting():
    with pytest.raises(ScopeError):
        await resolve_public('127.0.0.1', 80)
    assert await resolve_public('127.0.0.1', 80, allow_loopback=True) == '127.0.0.1'
