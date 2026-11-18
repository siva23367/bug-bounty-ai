# Bug Bounty AI

A working, **local single-user research application**: FastAPI, React, Tailwind, Recharts, SQLAlchemy, httpx and BeautifulSoup. Scans make real, bounded HTTP requests; findings contain actual observations, response hashes and audit records. There are no seeded production findings, earnings or simulated AI responses.

**This is an indicator scanner, not an autonomous exploitation or guaranteed-bounty engine.** No detector or LLM automatically confirms vulnerabilities. Human review establishes impact and controls the confirmed / potential / false-positive classification.

## Quick start on Ubuntu

Prerequisites: Python 3.11+ with venv support and Node.js 20.19+ (22 LTS recommended). Ubuntu's older Node packages may need updating from your organization's approved distribution source.

```bash
sudo apt update
sudo apt install python3 python3-venv nodejs npm
cd bug-bounty-ai
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
cp .env.example .env
# Optional: edit .env for integrations, AI and an operator-owned callback origin.
.venv/bin/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

To perform the setup and launch steps with one command, use:

```bash
chmod +x scripts/start-local.sh
./scripts/start-local.sh
```

The script is foreground-based and exits cleanly with `Ctrl+C`. Docker Compose is the recommended persistent deployment:

```bash
docker compose up --build -d
docker compose logs -f app
```

Open **http://127.0.0.1:8000**. In a second terminal, read the generated login token:

```bash
cd bug-bounty-ai
cat data/api-token
```

If you set `API_TOKEN` explicitly, use that value instead. Tokens stay in browser memory; reloading locks the workspace. Generated API tokens and encryption keys are persistent files with mode 0600. Keep the server bound to loopback. This application is not a hardened multi-tenant Internet service.

For frontend development, keep the API on port 8000 and run:

```bash
npm --prefix frontend run dev
```

Vite proxies `/api` to the backend. Production serves built frontend assets directly from FastAPI.

## Workflow

1. **Programs:** enter the official policy or written-permission URL, documentary reference, reviewed rules, exact origins, exclusions, expiry, request limits and permitted active modules. Explicitly attest to written authorization and automation permission.
2. Review and translate **all** prose rules into the enforced scope and settings. The application cannot establish legal permission, prove domain ownership, or reliably interpret every natural-language restriction. If a program's conditions cannot be expressed by these controls, do not scan it.
3. Optionally configure dedicated accounts and disposable test cases below. Credentials and test-case configuration are encrypted at rest using Fernet. Program records are immutable; revoke and recreate them when permission changes.
4. **New scan:** choose the authorization and URL. Baseline mode performs reconnaissance GET requests and passive response checks. Select active modules only when the program permits them and provide per-scan human approval.
5. **Investigations:** inspect actual findings, inventory, exclusions and chronological audit logs. Use **STOP SCAN** to cancel the in-flight operation and prevent further requests. Cancellation cannot undo a request already received by the target.
6. Review each finding's impact and false-positive explanations. Mark it confirmed or false positive with a substantive review note. CVSS is optional and explicitly human-assessed, not invented by an LLM.
7. Export **Markdown, HTML or PDF**. Submit manually to the official platform, then record the real submission URL, outcome and actual/pending reward. Rewards are grouped by currency and are never forecast from findings.

## Detection modules and precise limits

| Category | What actually runs | What it does not prove |
|---|---|---|
| Reflected XSS indicators | Approved GET query mutation using a random inert custom HTML tag; checks unescaped reflection | JavaScript execution or exploitable XSS |
| Stored XSS indicators | Approved form-encoded POST to one configured disposable test resource, followed by an authenticated read | Executable stored XSS; cleanup must be performed manually |
| SQL injection indicators | Approved single-apostrophe query variation, compared with a clean baseline for recognized database errors | Query control, data extraction or write capability |
| IDOR / access control | Compare an operator-owned private resource's unique marker using owner, second test account and anonymous requests | Unauthorized access unless ownership, privacy and account separation are independently verified |
| Authentication | Observe password forms over HTTP and insecure HTTP form actions; no login attempts | Full authentication assurance, password strength, session invalidation or MFA coverage |
| CSRF | Detect POST forms without recognizable token fields; **does not submit them** | Exploitable CSRF; Origin, SameSite or header checks may protect them |
| SSRF indicators | Approved GET URL parameter with a random, expiring nonce on your own callback service | Internal access or exploitable SSRF; intended URL-fetch features and middleboxes can trigger callbacks |
| Open redirects | Approved known redirect parameter with an `.invalid` destination; inspect Location, never follow off-scope | Bounty eligibility or impact in every application |
| CORS | Observe wildcard policies; optionally test reflection of a controlled `.invalid` Origin | Sensitive credentialed browser access without further validation |
| Sensitive information | Match secret/debug patterns in memory; retain signal names and hashes, not secret values | That an apparent secret is real; never use discovered credentials |
| API configuration | Identify publicly returned OpenAPI / Swagger specifications and discovered GET routes | That public documentation is unintended or itself vulnerable |
| Headers, cookies | Inspect actual HTML response headers and Set-Cookie attributes without storing cookie values | Exploitability or bounty eligibility of hardening observations |
| Directory listing | Match directory-index HTML | That listed files are sensitive |
| Exposed configuration | With active permission, request only `/.env` and `/.git/HEAD` and verify structure | Repository reconstruction, secret validity or safe use of any exposed material |

Independent detector modules live under [backend/app/scanner/detectors](backend/app/scanner/detectors). Tests cover their positive/negative behavior and real requests against an owned ephemeral localhost fixture. There is no browser execution, brute force, time-delay payload, exploit chain, credential harvesting, internal-network SSRF, broad path fuzzing or arbitrary code execution.

### Reconnaissance

- Bounded same-scope HTML link/script/style discovery, parameter names and form metadata.
- Static API-path extraction from JavaScript and GET paths from OpenAPI documents. No JavaScript evaluation or headless-browser crawling.
- Selected server/framework indicators; not authoritative technology fingerprinting.
- Scoped `robots.txt` and `/.well-known/security.txt` retrieval; policy links are discovery candidates, not verified authorization.
- User-requested, explicitly permitted Certificate Transparency queries to `crt.sh`; records are potentially stale. Discovered domains are marked in/out of scope and **never automatically scanned**.
- Configured page and request budgets cap work. A `limited` scan is incomplete, not a successful comprehensive assessment.

## Authorization and network boundaries

- Origins include scheme and port. `https://*.example.com` permits subdomains, **not the apex**. Add the apex separately if authorized. Path prefixes are segment-boundary matched.
- Exclusions are case-sensitive full-URL globs, checked against raw and decoded URLs. Example: `https://example.com/admin*`. Use `*` explicitly to include descendants.
- Unsupported or ambiguous encodings, userinfo, path traversal and non-HTTP(S) URLs are rejected. Every network request is scope-checked again.
- DNS answers are validated; **all** answers must be public. Connections are pinned to a validated address while retaining the original Host header, TLS SNI and certificate checks. Proxy environment variables are ignored. Redirects are not automatically followed.
- Private, reserved, link-local and metadata addresses are prohibited. `ALLOW_LOOPBACK_TARGETS=true` permits only loopback in an operator-owned lab; it does not permit private network ranges. Inside Docker, loopback means the container, not your host.
- One scan at a time, one server worker, bounded rate and request count, 10-second per-request timeout, 512 KiB response-body cap, no retries. HTTP 429 stops the scan. Unexpected compressed responses are rejected rather than unboundedly decompressed.
- Robots disallow rules apply to subsequent requests; Crawl-delay can further reduce the configured rate. Robots permission is never a substitute for written authorization.
- Obvious state-changing GET paths are rejected. This heuristic cannot guarantee arbitrary GET endpoints have no side effects; review the target and add all risky paths to exclusions.
- Test-account credentials are sent only to their exact configured origin. Each request has a fresh cookie jar; no cookies leak across hosts or accounts.
- Every request attempt and result is logged with redacted query values and response hashes. Target bodies and discovered secret values are not persisted. The initial operator-entered target URL and approval notes are stored locally; do not put secrets in URLs or notes.
- Revocation/expiry blocks subsequent requests. Server restart marks unfinished scans interrupted and does not resume them. Stored-write intent and cleanup instructions are logged **before** writing, even if a stop or timeout occurs.

## Dedicated test accounts and controlled cases

In **Programs → Dedicated test accounts & controlled test cases**, enter JSON using this structure. Replace all example values with your own dedicated test setup; no example credentials are operational:

```json
{
  "accounts": [
    {"name": "owner", "origin": "https://authorized.example.com", "headers": {"Authorization": "Bearer YOUR_DEDICATED_OWNER_TOKEN"}},
    {"name": "other", "origin": "https://authorized.example.com", "headers": {"Authorization": "Bearer YOUR_DEDICATED_OTHER_TOKEN"}}
  ],
  "access_cases": [
    {
      "url": "https://authorized.example.com/api/test-resources/owned-by-you",
      "owner_account": "owner",
      "other_account": "other",
      "owned_resource_marker": "your-unique-disposable-private-resource-marker",
      "private_resource_attested": true
    }
  ],
  "stored_cases": [
    {
      "write_url": "https://authorized.example.com/disposable-test-form",
      "read_url": "https://authorized.example.com/disposable-test-view",
      "account": "owner",
      "field": "message",
      "fields": {"csrf_token": "YOUR_VALID_TEST_FORM_TOKEN"},
      "cleanup_instructions": "Open the dedicated test resource with the owner account and remove the marker after the scan, including cancelled scans.",
      "disposable_test_resource_attested": true
    }
  ],
  "ssrf_cases": [
    {"url": "https://authorized.example.com/explicitly-permitted-fetch-test", "parameter": "url"}
  ]
}
```

Only `Authorization`, `Cookie` and `X-API-Key` credential headers are supported. There is no automatic login, token refresh, POST JSON mutation or automatic deletion. Stored tests are exactly one form-encoded inert marker write and one read per case. Keep resources disposable and inspect **cleanup_required** logs after every run. Only enable capabilities expressly allowed by the program.

### Controlled callback setup

Set `CALLBACK_BASE_URL=https://callbacks.your-owned-domain.example` and configure your own HTTPS reverse proxy to forward **only** `/api/callback/*` to this app. Route no other paths publicly. Nonces expire after 15 minutes, accept one observation, and stop accepting after revocation or a stopped/failed scan. Do not enable proxy access logging of nonce URLs. The application never calls a third-party callback provider. External TLS/DNS/reverse-proxy provisioning is operator-owned and is not automatically configured.

## AI analysis

Set `LLM_BASE_URL`, `LLM_MODEL`, and optionally `LLM_API_KEY` for an OpenAI-compatible `/chat/completions` API supporting JSON-object output. Example local base: `http://127.0.0.1:11434/v1`. Install/run your chosen model server separately.

- Loopback model endpoints receive the detector description and **redacted finding evidence** for evidence-aware local advisory analysis.
- Remote endpoints receive **only app-authored category, description and severity metadata**. They never receive target endpoints, bodies, credentials, rules, private source code or evidence. Their analysis is generic, not case-specific.
- Model output is schema-validated. Failures are visible and audited; there is no fake fallback response.
- The AI suggests explanations, false-positive considerations, safe validation and remediation. It cannot change status, severity, rewards, scope or execute tests. Review output as untrusted advice.
- No model or API credential is bundled, so AI is disabled until configured. Live model connectivity cannot be verified without your endpoint/credentials.

## Official bounty-program integrations

**Intelligence** performs authenticated, read-only official API requests when credentials are available:

| Platform | Configuration | Read-only endpoints |
|---|---|---|
| HackerOne | `HACKERONE_USERNAME`, `HACKERONE_TOKEN` | `/v1/hackers/programs/{handle}` and first page (up to 100) of `/structured_scopes` |
| Bugcrowd | `BUGCROWD_TOKEN=token-id:token-secret` | `https://api.bugcrowd.com/programs/{id}`; API role must grant access |
| Intigriti | `INTIGRITI_TOKEN` | `https://api.intigriti.com/external/researcher/v1/programs/{programId}` |

Responses retain source and retrieval time. The source JSON shows published policies, scope, eligibility and reward fields **when the provider exposes them**. Absent reward amounts remain unknown. Follow pagination and review the official policy manually before entering an authorization; no partial API response automatically grants permission. Not every program publishes rewards or exposes all data through an API. Private programs require appropriate membership. Program URLs discovered in security.txt are not automatically claimed to be official matches.

No provider credentials were supplied with this project; authenticated live responses are **not certified**. API errors are explicit. External report submission is deliberately manual to prevent accidental disclosures or duplicate submissions. Provider references: [HackerOne](https://api.hackerone.com/hacker-resources/), [Bugcrowd](https://docs.bugcrowd.com/api/getting-started/), [Intigriti OpenAPI](https://api.intigriti.com/external/researcher/swagger/v1/swagger.json).

## Docker

```bash
cp .env.example .env
docker compose up --build -d
docker compose exec app cat /app/data/api-token
```

Open http://127.0.0.1:8000. A named volume persists the SQLite database and keys. The container runs unprivileged; host publishing is loopback-only. Do not use multiple workers or multiple app replicas: the cancellation registry and single-scan lock are process-local. For Docker-local LLMs, loopback is inside the container; a non-loopback model URL uses metadata-only mode.

## Database and persistence

SQLite is the default. `DATABASE_URL=postgresql+psycopg://user:password@host:5432/bugbounty` selects PostgreSQL using the same SQLAlchemy models. Create the database and restricted user first. Tables are created at startup. This initial schema has no upgrade migrations; back up before schema changes. PostgreSQL compatibility is designed into the models but requires testing against your actual deployment.

Back up the database **and encryption key together**. Database access, local filesystem access and the API token grant sensitive privileges. Audit records are comprehensive application logs, not tamper-proof legal evidence. Retention and access controls are the operator's responsibility.

## Verification

```bash
.venv/bin/python -m pytest -q
npm --prefix frontend run build
curl --fail http://127.0.0.1:8000/health
```

Tests use a separate temporary database and an owned ephemeral HTTP fixture. They do not contact third-party targets or populate your production dashboard. Coverage includes authorization, scope confusion, DNS restrictions, real passive/active HTTP tests, encrypted account storage, credential redaction, stopping, budgets, callbacks, reviews, exports and reward validation.

## Layout

```text
bug-bounty-ai/
  backend/app/          FastAPI routes, models, AI, reports, integrations
  backend/app/scanner/  Scope enforcement, pinned transport, recon, detectors
  backend/tests/       Isolated test suite and owned HTTP fixture
  frontend/            React, Tailwind, Recharts and production build
  data/                Generated database, API token, encryption key (ignored)
  .env.example         Configuration reference
  Dockerfile           Multi-stage, unprivileged image
  compose.yaml         Persistent loopback-only deployment
```

Never scan a third-party website merely because it is reachable or has a public bug bounty page. Confirm the exact assets, automation policy, exclusions and allowed actions first. A clean scan is not evidence that the target has no vulnerabilities; an indicator is not a promise of a bounty.
