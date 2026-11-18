from dataclasses import dataclass, field

from ..transport import Response, safe_url


@dataclass
class Observation:
    category: str
    title: str
    endpoint: str
    severity: str
    description: str
    impact: str
    remediation: str
    evidence: dict = field(default_factory=dict)
    steps: list[str] = field(default_factory=list)


def finding(response: Response, category: str, title: str, severity: str, description: str,
            impact: str, remediation: str, evidence: dict | None = None) -> Observation:
    return Observation(category, title, safe_url(response.url), severity, description, impact, remediation,
                       {'http_status': response.status, 'response_sha256': response.digest,
                        'response_truncated': response.truncated, **(evidence or {})},
                       ['Confirm the endpoint and test are still authorized.',
                        'Send the documented request using only your dedicated test data.',
                        'Inspect the indicated behavior; establish impact before claiming a vulnerability.'])
