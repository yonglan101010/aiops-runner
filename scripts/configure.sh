#!/usr/bin/env bash
# Bash 入口；交互与事务逻辑由 Python 向导统一实现。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="${PYTHON:-python3}"
fi
exec "$PY" "$ROOT/scripts/configure_wizard.py" "$@"
