import secrets

from ...db import audit
from .access import credentials
from .base import finding


async def probe(transport, policy):
    output = []
    for case in policy.stored_cases:
        marker = '<bbai-' + secrets.token_hex(8) + '>'
        audit('stored_write_approved', {'cleanup_instructions': case.cleanup_instructions, 'marker': marker}, transport.scan_id)
        audit('cleanup_required', {'marker': marker, 'instructions': case.cleanup_instructions,
                                   'reason': 'Write is about to be attempted; inspect even if cancelled or timed out'}, transport.scan_id)
        write = await transport.request(case.write_url, method='POST', headers=credentials(policy, case.account, case.write_url),
                                        data={**case.fields, case.field: marker})
        if write.status >= 400:
            raise ValueError('Disposable stored-marker write failed; inspect the test resource and cleanup log')
        response = await transport.request(case.read_url, headers=credentials(policy, case.account, case.read_url))
        if marker in response.text and 'html' in response.headers.get('content-type', ''):
            output.append(finding(response, 'stored', 'Stored inert HTML marker rendered unescaped', 'Medium',
                                  'A marker posted to an explicitly configured disposable resource appeared unescaped on the read endpoint.',
                                  'Stored HTML injection indicator only; executable stored XSS is not established.',
                                  'Encode stored input at rendering time; remove the disposable test marker.',
                                  {'marker': marker, 'field': case.field, 'cleanup_required': True}))
    return output
