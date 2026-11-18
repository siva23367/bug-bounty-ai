import hashlib

import httpx
import pytest

from app.scanner.detectors import api, authentication, cookies, csrf, directory, disclosure, exposure, headers
from app.scanner.transport import Response, safe_url


def response(text, content_type='text/html', url='https://example.invalid/'):
    return Response(url, 200, httpx.Headers({'Content-Type': content_type}), text, hashlib.sha256(text.encode()).hexdigest())


@pytest.mark.parametrize('detector,text,type', [
    (csrf.detect, '<form method="post"><input name="message"></form>', 'text/html'),
    (directory.detect, '<title>Index of /</title><a href="../">Parent Directory</a>', 'text/html'),
    (disclosure.detect, '-----BEGIN PRIVATE KEY-----\nnot-a-real-key', 'text/plain'),
    (api.detect, '{"openapi":"3.0.0","paths":{}}', 'application/json'),
])
def test_passive_indicators_are_evidence_based(detector, text, type):
    assert detector(response(text, type))
    assert not detector(response('ordinary page with no signals', type))


def test_no_secret_values_in_disclosure_and_cookie_evidence():
    r = response('AKIA' + 'A' * 16)
    finding = disclosure.detect(r)[0]
    assert 'AKIA' not in str(finding.evidence)
    r.headers['Set-Cookie'] = 'session=super-secret-value; Path=/'
    finding = cookies.detect(r)[0]
    assert 'super-secret-value' not in str(finding.evidence)
    assert finding.evidence['cookies'][0]['cookie'] == 'session'


def test_configuration_soft_404_and_auth_transport():
    assert not exposure.detect(response('<html>Not found</html>', url='https://example.invalid/.env'))
    assert authentication.detect(response('<form><input type="password"></form>', url='http://example.invalid/'))
    assert not authentication.detect(response('<form><input type="password"></form>'))
    assert 'secret' not in safe_url('https://example.invalid/?token=secret')
