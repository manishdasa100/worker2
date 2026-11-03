#!/usr/bin/env bash
# Launch worker2 in a delegated cgroup scope (required by the rootless sandbox).
# Works from any terminal incl. SSH.  Usage: ./run.sh [dev|prod]  (default: dev)
set -euo pipefail
cd "$(dirname "$0")"
ENV_NAME="${1:-dev}"
[[ -f ".env.${ENV_NAME}" ]] || { echo "error: .env.${ENV_NAME} not found (copy .env.example)" >&2; exit 1; }
PY=".venv/bin/python3"; [[ -x "$PY" ]] || PY="python3"
command -v systemd-run >/dev/null || { echo "error: systemd-run not found (needs a systemd host)" >&2; exit 1; }
# --scope keeps the worker attached to this terminal while delegating the
# memory+pids controllers to its own cgroup subtree.
exec systemd-run --user --scope -p Delegate=yes --quiet "$PY" main.py --env "${ENV_NAME}"
