#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$ROOT/.env" ]; then
  set -a
  . "$ROOT/.env"
  set +a
fi

export PATH="$ROOT/.venv/bin:$PATH"

# Claude Code is commonly installed with an unprivileged user's npm prefix
# (for example /home/claude/.npm-global/bin).  A service started through
# runuser/systemd does not necessarily source that user's shell profile, so
# include the conventional user-local npm bin directory explicitly.  A caller
# may still provide a custom directory through CLAUDE_CLI_DIR.
if [ -n "${CLAUDE_CLI_DIR:-}" ]; then
  export PATH="$CLAUDE_CLI_DIR:$PATH"
elif [ -d "${HOME:-}/.npm-global/bin" ]; then
  export PATH="$HOME/.npm-global/bin:$PATH"
fi

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  echo "缺少虚拟环境；请先运行 scripts/install.sh" >&2
  exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
  echo "警告：PATH 中找不到 claude CLI；真实诊断会以 claude_not_found 失败" >&2
fi

cd "$ROOT"
export RUNNER_CONFIG="${RUNNER_CONFIG:-config/runner.yaml}"
export PYTHONPATH="runner"
exec "$ROOT/.venv/bin/python" -m runner.server
