#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if curl --fail --silent --max-time 2 http://127.0.0.1:8000/health >/dev/null; then
  echo "Bug Bounty AI is already listening on http://127.0.0.1:8000"
  exit 0
fi

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi

.venv/bin/pip install -r backend/requirements.txt
if [[ ! -f .env ]]; then
  cp .env.example .env
fi

echo "Building frontend..."
npm --prefix frontend ci --no-audit --no-fund
npm --prefix frontend run build

echo "Starting Bug Bounty AI at http://127.0.0.1:8000"
exec .venv/bin/uvicorn app.main:app \
  --app-dir backend \
  --host 127.0.0.1 \
  --port 8000 \
  --workers 1 \
  --no-access-log
