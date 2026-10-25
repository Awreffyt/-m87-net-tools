#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PORT="${PORT:-8000}"
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --workers 1 --no-server-header
