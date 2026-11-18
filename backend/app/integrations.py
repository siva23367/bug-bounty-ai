import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .config import settings
from .scanner.scope import ensure_scope


async def bounded_json(client, url, **kwargs):
    async with client.stream('GET', url, **kwargs) as response:
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes(chunk_size=16384):
            body.extend(chunk)
            if len(body) > 2_000_000:
                raise ValueError('Provider response exceeded the 2 MB limit')
        return json.loads(body)


async def program_details(provider, identifier):
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', identifier):
        raise ValueError('Use the program handle or UUID, not a URL')
    async with httpx.AsyncClient(timeout=20, follow_redirects=False, trust_env=False) as client:
        if provider == 'hackerone':
            if not settings.hackerone_username or not settings.hackerone_token:
                raise ValueError('HACKERONE_USERNAME and HACKERONE_TOKEN are required')
            url = f'https://api.hackerone.com/v1/hackers/programs/{identifier}'
            auth = (settings.hackerone_username, settings.hackerone_token)
            details = await bounded_json(client, url, auth=auth)
            scopes = await bounded_json(client, url + '/structured_scopes', auth=auth, params={'page[size]': 100})
            details['structured_scopes_page'] = scopes
        elif provider == 'bugcrowd':
            if not settings.bugcrowd_token:
                raise ValueError('BUGCROWD_TOKEN (token-id:token-secret) is required; access depends on your role')
            url = f'https://api.bugcrowd.com/programs/{identifier}'
            details = await bounded_json(client, url, headers={'Authorization': 'Token ' + settings.bugcrowd_token,
                                                             'Accept': 'application/vnd.bugcrowd+json'})
        elif provider == 'intigriti':
            if not settings.intigriti_token:
                raise ValueError('INTIGRITI_TOKEN is required')
            url = f'https://api.intigriti.com/external/researcher/v1/programs/{identifier}'
            details = await bounded_json(client, url, headers={'Authorization': 'Bearer ' + settings.intigriti_token})
        else:
            raise ValueError('Unsupported bounty provider')
    return {'provider': provider, 'source': url, 'retrieved_at': datetime.now(timezone.utc).isoformat(),
            'details': details, 'notice': 'Provider data is not authorization. Review all scope pages, exclusions and current rules. '
            'Rewards are shown only if published in the returned provider fields; no earnings are inferred.'}


async def passive_subdomains(policy, domain):
    if not policy.passive_subdomains_allowed:
        raise ValueError('Certificate Transparency lookups were not authorized for this program')
    if not re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}', domain):
        raise ValueError('Use a public DNS hostname')
    if not any(urlsplit(s.origin.replace('*.', '')).hostname == domain for s in policy.scope):
        raise ValueError('Domain must be the exact base of an approved scope entry')
    async with httpx.AsyncClient(timeout=25, follow_redirects=False, trust_env=False) as client:
        data = await bounded_json(client, 'https://crt.sh/', params={'q': '%.' + domain, 'output': 'json'})
    if not isinstance(data, list):
        raise ValueError('Unexpected Certificate Transparency response')
    names = set()
    for row in data:
        for name in str(row.get('name_value', '')).splitlines():
            name = name.lower()
            if '*' not in name and name.endswith('.' + domain):
                names.add(name)
    results = []
    for name in sorted(names)[:1000]:
        try:
            ensure_scope('https://' + name, policy)
            in_scope = True
        except ValueError:
            in_scope = False
        results.append({'hostname': name, 'in_scope': in_scope})
    return {'source': 'https://crt.sh/', 'results': results,
            'notice': 'Passive records only; may be stale. Nothing is automatically scanned.'}
