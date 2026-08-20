#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"

cd "$ROOT"
"$PY" -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -e "$ROOT/runner"

SECURE_DIRS=(
  "$ROOT/config/keys"
  "$ROOT/state/deadletter"
  "$ROOT/state/kubernetes"
)
mkdir -p "${SECURE_DIRS[@]}"
chmod 700 "${SECURE_DIRS[@]}"
if [ -n "${RUNNER_SERVICE_USER:-}" ]; then
  if ! id "$RUNNER_SERVICE_USER" >/dev/null 2>&1; then
    echo "Runner 服务用户不存在: $RUNNER_SERVICE_USER" >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ] && [ "$(id -un)" != "$RUNNER_SERVICE_USER" ]; then
    echo "需要由 root 或 $RUNNER_SERVICE_USER 设置 Runner 安全目录所有者。" >&2
    exit 1
  fi
  if [ "$(id -u)" -eq 0 ]; then
    RUNNER_SERVICE_GROUP="$(id -gn "$RUNNER_SERVICE_USER")"
    chown "$RUNNER_SERVICE_USER:$RUNNER_SERVICE_GROUP" "${SECURE_DIRS[@]}"
  fi
fi

# Persistent trusted-session identity is an explicit installation artifact.
# Startup only validates it and will never silently generate a replacement.
IDENTITY_ARGS=(--file "$ROOT/state/runner-instance-id")
if [ -n "${RUNNER_SERVICE_USER:-}" ]; then
  IDENTITY_ARGS+=(--service-user "$RUNNER_SERVICE_USER")
fi
RUNNER_IDENTITY="$(PYTHONPATH="$ROOT/runner" "$ROOT/.venv/bin/python" -m runner.instance_identity init "${IDENTITY_ARGS[@]}")"

SKILL_PATH="agent-project-trusted/.claude/skills/trusted-repair-session/SKILL.md"
claude -p "只读取并确认 Trusted 修复 Skill 已可用。Skill 相对项目根目录的路径是 ${SKILL_PATH}。不得修改任何文件，不得执行系统命令，不得访问网络；仅输出 skill_ready。" --output-format json

echo "已安装虚拟环境: $ROOT/.venv"
echo "Runner 实例 ID: $RUNNER_IDENTITY（请登记到 AIOps Provider）"
echo "Claude CLI 与 Trusted 会话 Skill 已确认可用。"
if command -v kubectl >/dev/null 2>&1; then
  echo "kubectl：已找到（仅作为可选排障工具，Runner 运行不依赖它）。"
else
  echo "kubectl：未安装（不影响 Runner；需要人工排障时可按 Kubernetes 官方说明安装）。"
fi
if [ -n "${RUNNER_SERVICE_USER:-}" ] && [ "$(id -un)" != "$RUNNER_SERVICE_USER" ]; then
  echo "下一步请以服务用户运行配置向导：runuser -u $RUNNER_SERVICE_USER -- $ROOT/scripts/configure.sh"
else
  echo "下一步运行配置向导：$ROOT/scripts/configure.sh"
fi
