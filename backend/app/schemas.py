import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

ACTIVE = {'reflection', 'sqli', 'redirect', 'cors', 'exposure', 'access', 'stored', 'ssrf'}


class ScopeEntry(BaseModel):
    origin: str = Field(max_length=300)
    path_prefix: str = '/'

    @field_validator('origin')
    @classmethod
    def origin_valid(cls, value: str) -> str:
        parts = urlsplit(value.replace('*.', 'wildcard.', 1))
        if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password:
            raise ValueError('Use an HTTP(S) origin, optionally with a leading *. subdomain wildcard')
        if parts.path not in {'', '/'} or parts.query or parts.fragment:
            raise ValueError('Put paths in path_prefix, not origin')
        if '*' in value and not re.match(r'^https?://\*\.[a-zA-Z0-9.-]+(?::\d+)?/?$', value):
            raise ValueError('Only a leading *. hostname wildcard is supported')
        _ = parts.port
        return value.rstrip('/').lower()

    @field_validator('path_prefix')
    @classmethod
    def prefix_valid(cls, value: str) -> str:
        if not value.startswith('/') or any(c in value for c in ('%', '?', '#', '\\')) or '..' in value.split('/'):
            raise ValueError('Use an unencoded absolute path prefix')
        return value


class TestAccount(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    origin: str
    headers: dict[str, str] = Field(min_length=1)

    @field_validator('headers')
    @classmethod
    def headers_valid(cls, value: dict[str, str]) -> dict[str, str]:
        if any(k.lower() not in {'authorization', 'cookie', 'x-api-key'} or '\n' in v or '\r' in v
               for k, v in value.items()):
            raise ValueError('Only Authorization, Cookie and X-API-Key test credentials are allowed')
        return value


class AccessCase(BaseModel):
    url: str
    owner_account: str
    other_account: str
    owned_resource_marker: str = Field(min_length=12, max_length=200)
    private_resource_attested: Literal[True]


class StoredCase(BaseModel):
    write_url: str
    read_url: str
    account: str
    field: str = Field(min_length=1)
    fields: dict[str, str] = Field(default_factory=dict)
    cleanup_instructions: str = Field(min_length=20)
    disposable_test_resource_attested: Literal[True]


class SSRFCase(BaseModel):
    url: str
    parameter: str


class Policy(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    source_url: str = Field(max_length=2000)
    permission_reference: str = Field(min_length=20, max_length=10000)
    rules_text: str = Field(min_length=20, max_length=30000)
    scope: list[ScopeEntry] = Field(min_length=1, max_length=100)
    excluded_urls: list[str] = Field(default_factory=list, max_length=200)
    excluded_categories: list[str] = Field(default_factory=list)
    expires_at: datetime
    requests_per_second: float = Field(default=1, ge=0.1, le=5)
    max_requests: int = Field(default=50, ge=1, le=500)
    max_pages: int = Field(default=15, ge=1, le=100)
    allowed_active: list[Literal['reflection', 'sqli', 'redirect', 'cors', 'exposure', 'access', 'stored', 'ssrf']] = Field(default_factory=list)
    passive_subdomains_allowed: bool = False
    permission_attested: Literal[True]
    automation_allowed: Literal[True]
    rules_reviewed: Literal[True]
    accounts: list[TestAccount] = Field(default_factory=list, max_length=5)
    access_cases: list[AccessCase] = Field(default_factory=list, max_length=10)
    stored_cases: list[StoredCase] = Field(default_factory=list, max_length=5)
    ssrf_cases: list[SSRFCase] = Field(default_factory=list, max_length=10)

    @field_validator('source_url')
    @classmethod
    def source_valid(cls, value: str) -> str:
        p = urlsplit(value)
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
            raise ValueError('Provide a public program URL or a permission-document URL')
        return value

    @field_validator('expires_at')
    @classmethod
    def expiry_valid(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError('Permission expiry must include a timezone')
        return value

    @model_validator(mode='after')
    def references_valid(self):
        names = [a.name for a in self.accounts]
        if len(names) != len(set(names)):
            raise ValueError('Test account names must be unique')
        for case in self.access_cases:
            if case.owner_account not in names or case.other_account not in names or case.owner_account == case.other_account:
                raise ValueError('Access cases require two distinct configured test accounts')
        for case in self.stored_cases:
            if case.account not in names or case.field in case.fields:
                raise ValueError('Stored cases require a configured account and a separate marker field')
        return self


class StartScan(BaseModel):
    program_id: int
    target: str = Field(max_length=2000)
    active_modules: list[str] = Field(default_factory=list)
    active_approved: bool = False
    approval_note: str = Field(default='', max_length=2000)

    @model_validator(mode='after')
    def approval(self):
        if set(self.active_modules) - ACTIVE:
            raise ValueError('Unknown active module')
        if self.active_modules and (not self.active_approved or len(self.approval_note.strip()) < 20):
            raise ValueError('Active tests require explicit approval and a detailed approval note')
        return self


class Review(BaseModel):
    status: Literal['potential', 'confirmed', 'false_positive']
    note: str = Field(min_length=20, max_length=10000)
    severity: Literal['Info', 'Low', 'Medium', 'High', 'Critical']
    cvss: str | None = Field(default=None, pattern=r'^(10\.0|[0-9](\.[0-9])?)$')


class Submission(BaseModel):
    status: Literal['draft', 'submitted', 'accepted', 'rejected', 'duplicate']
    url: str = Field(default='', max_length=2000)
    currency: str = Field(default='USD', pattern=r'^[A-Z]{3}$')
    earned_cents: int = Field(default=0, ge=0, le=1000000000)
    pending_cents: int = Field(default=0, ge=0, le=1000000000)

    @model_validator(mode='after')
    def reward_valid(self):
        if self.status != 'accepted' and (self.earned_cents or self.pending_cents):
            raise ValueError('Rewards can only be recorded for accepted reports')
        if self.status != 'draft' and not self.url.startswith('https://'):
            raise ValueError('Provide an HTTPS submission reference')
        return self
