#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://127.0.0.1:8002/healthz}"
python3 - "$URL" <<'PY'
import sys
import urllib.request

url = sys.argv[1]
with urllib.request.urlopen(url, timeout=5) as resp:
    print(resp.status)
PY
