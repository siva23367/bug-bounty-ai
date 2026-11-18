from ..scope import ScopeError, origin
from .base import finding


def credentials(policy, name, url):
    account = next(a for a in policy.accounts if a.name == name)
    if origin(account.origin) != origin(url):
        raise ScopeError('Test credentials may only be sent to their configured exact origin')
    return account.headers


async def probe(transport, policy):
    output = []
    for case in policy.access_cases:
        owner = await transport.request(case.url, headers=credentials(policy, case.owner_account, case.url))
        if owner.status != 200 or case.owned_resource_marker not in owner.text:
            raise ScopeError('Owner baseline failed: expected dedicated resource marker was not found')
        other = await transport.request(case.url, headers=credentials(policy, case.other_account, case.url))
        anonymous = await transport.request(case.url)
        for response, role in ((other, 'other test account'), (anonymous, 'anonymous')):
            if response.status == 200 and case.owned_resource_marker in response.text:
                output.append(finding(response, 'access', f'Private test-resource marker readable by {role}', 'High',
                                      'A marker in an operator-attested private test resource was readable outside its owner account.',
                                      'Confirm the resource is genuinely private and the accounts do not share intended privileges.',
                                      'Enforce object-level authorization on every resource access.', {'access_context': role, 'owner_baseline_passed': True}))
    return output
