import importlib.util
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "agent-project-trusted"
HOOK_PATH = PROJECT / "bin" / "trusted_tool_hook.py"
SETTINGS_PATH = PROJECT / ".claude" / "settings.json"
SKILL_PATH = (
    PROJECT
    / ".claude"
    / "skills"
    / "trusted-repair-session"
    / "SKILL.md"
)
INSPECTION_SKILL_PATH = (
    PROJECT
    / ".claude"
    / "skills"
    / "trusted-inspection-session"
    / "SKILL.md"
)


def _load_hook():
    spec = importlib.util.spec_from_file_location("trusted_tool_hook", HOOK_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


HOOK = _load_hook()


def _payload(tool_name, tool_input):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def _decision(result):
    return result["hookSpecificOutput"]["permissionDecision"]


@pytest.mark.parametrize(
    "command",
    [
        "./bin/target-exec 'systemctl status nginx.service --no-pager'",
        './bin/target-exec "du -x --max-depth=1 -- /srv/data"',
        "./bin/target-exec 'systemctl restart nginx.service'",
        "./bin/target-exec 'rm -- /srv/app/stale.lock'",
        (
            "./bin/target-exec 'systemctl restart nginx.service; "
            "systemctl is-active nginx.service'"
        ),
    ],
)
def test_hook_allows_only_single_target_exec_outer_shape(command):
    result = HOOK.evaluate_hook(_payload("Bash", {"command": command}))
    assert _decision(result) == "allow"


@pytest.mark.parametrize(
    "remote",
    [
        "awk '{print $1}' /var/log/x | sed -n '1,20p'",
        "find /srv -name '*.log' -printf '%s %p\\n' | sort -nr",
        """psql -c "UPDATE jobs SET state='ready' WHERE id=42" """.strip(),
        (
            "systemctl restart nginx.service; "
            "systemctl is-active nginx.service"
        ),
    ],
)
def test_hook_preserves_complex_remote_command_as_one_opaque_argument(remote):
    command = f"./bin/target-exec {shlex.quote(remote)}"
    assert shlex.split(command) == ["./bin/target-exec", remote]
    result = HOOK.evaluate_hook(_payload("Bash", {"command": command}))
    assert _decision(result) == "allow"


@pytest.mark.parametrize(
    "command",
    [
        "ssh host uptime",
        "ls -la",
        "cat .env",
        "find / -maxdepth 3",
        "grep -R secret .",
        "env",
        "python3 -c 'print(1)'",
        "./bin/target-exec 'df -h' && ls",
        "./bin/target-exec 'df -h'|cat",
        "./bin/target-exec 'df -h' > local-output",
        "./bin/target-exec \"$(id)\"",
        "./bin/target-exec *",
        "./bin/target-exec ~",
        "./bin/target-exec 'df -h' &",
        "./bin/target-exec 'df -h' extra",
        "./bin/target-exec df",
        "./bin/target-exec 'df'junk",
        "./bin/target-exec 'df' 'uptime'",
        "target-exec 'df -h'",
        "/opt/runner/bin/target-exec 'df -h'",
        "./bin/target-exec",
        "./bin/target-exec ''",
    ],
)
def test_hook_denies_local_commands_bypass_and_shell_injection(command):
    result = HOOK.evaluate_hook(_payload("Bash", {"command": command}))
    assert _decision(result) == "deny"


@pytest.mark.parametrize(
    "tool_name",
    [
        "Read",
        "Grep",
        "Glob",
        "Edit",
        "Write",
        "WebFetch",
        "WebSearch",
        "Agent",
        "Task",
        "mcp__filesystem__read_file",
    ],
)
def test_hook_denies_every_non_skill_non_bash_tool(tool_name):
    result = HOOK.evaluate_hook(_payload(tool_name, {}))
    assert _decision(result) == "deny"


def test_hook_allows_only_the_trusted_skill_and_rejects_background_bash():
    assert _decision(
        HOOK.evaluate_hook(
            _payload("Skill", {"skill": "trusted-repair-session"})
        )
    ) == "allow"
    assert _decision(
        HOOK.evaluate_hook(_payload("Skill", {"skill": "other-skill"}))
    ) == "deny"
    assert _decision(
        HOOK.evaluate_hook(
            _payload(
                "Bash",
                {
                    "command": "./bin/target-exec 'df -h'",
                    "run_in_background": True,
                },
            )
        )
    ) == "deny"
    for field, value in (
        ("run_in_background", 1),
        ("run_in_background", "false"),
        ("dangerouslyDisableSandbox", 1),
        ("dangerouslyDisableSandbox", "false"),
    ):
        assert _decision(
            HOOK.evaluate_hook(
                _payload(
                    "Bash",
                    {
                        "command": "./bin/target-exec 'df -h'",
                        field: value,
                    },
                )
            )
        ) == "deny"


def test_hook_allows_claude_builtin_structured_output_only_as_output_channel():
    """A JSON-schema diagnosis cannot complete when this internal tool is denied."""
    assert _decision(
        HOOK.evaluate_hook(_payload("StructuredOutput", {"schema": "diagnosis"}))
    ) == "allow"


def test_hook_process_malformed_input_fails_closed_without_echoing_input():
    secret = "never-print-this-secret"
    completed = subprocess.run(
        [sys.executable, str(HOOK_PATH)],
        input=f'{{"broken":"{secret}"',
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert secret not in completed.stdout
    assert secret not in completed.stderr
    assert _decision(json.loads(completed.stdout)) == "deny"


def test_settings_use_dontask_and_fail_closed_pretooluse_hook():
    settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    permissions = settings["permissions"]
    assert permissions["defaultMode"] == "dontAsk"
    assert permissions["allow"] == [
        "Skill(trusted-repair-session)",
        "Skill(trusted-inspection-session)",
        "Skill(host-context-initialization)",
    ]
    assert "Bash" not in permissions["allow"]
    assert {
        "Read",
        "Grep",
        "Glob",
        "Cd",
        "Edit",
        "Write",
        "PowerShell",
        "Agent",
        "TaskCreate",
        "TaskOutput",
        "ToolSearch",
        "mcp__*",
    }.issubset(permissions["deny"])
    hook_group = settings["hooks"]["PreToolUse"][0]
    assert "matcher" not in hook_group
    command = hook_group["hooks"][0]["command"]
    assert "trusted_tool_hook.py" in command
    assert "exit 2" in command


def test_target_exec_remains_a_transparent_ssh_wrapper_without_remote_gateway():
    wrapper = (PROJECT / "bin" / "target-exec").read_text(encoding="utf-8")
    assert wrapper.startswith("#!/bin/bash\n")
    assert 'if [ "$#" -ne 1 ]' in wrapper
    assert "TIMEOUT_BIN=/usr/bin/timeout" in wrapper
    assert "SSH_BIN=/usr/bin/ssh" in wrapper
    assert 'REMOTE_COMMAND="cd / && $1"' in wrapper
    assert 'exec "$TIMEOUT_BIN"' in wrapper
    assert '"$SSH_BIN" -F /dev/null -T' in wrapper
    assert "-o ClearAllForwardings=yes" in wrapper
    assert "-o PermitLocalCommand=no" in wrapper
    assert "-o GlobalKnownHostsFile=/dev/null" in wrapper
    assert "-o UpdateHostKeys=no" in wrapper
    assert '"$REMOTE_COMMAND"' in wrapper
    assert "#!/usr/bin/env bash" not in wrapper
    assert "exec timeout" not in wrapper
    assert "approved" not in wrapper.lower()
    assert "policy" not in wrapper.lower()


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/bin/bash").is_file(),
    reason="requires the Linux trusted-runner shell",
)
def test_target_exec_passes_hardened_ssh_argv_and_opaque_command(tmp_path):
    wrapper = (PROJECT / "bin" / "target-exec").read_text(encoding="utf-8")
    fake_timeout = tmp_path / "timeout"
    fake_ssh = tmp_path / "ssh"
    timeout_capture = tmp_path / "timeout.argv"
    ssh_capture = tmp_path / "ssh.argv"
    copied_wrapper = tmp_path / "target-exec"

    fake_timeout.write_text(
        "#!/bin/bash\n"
        "printf '%s\\n' \"$1\" > \"$CAPTURE_TIMEOUT\"\n"
        "shift\n"
        "exec \"$@\"\n",
        encoding="utf-8",
    )
    fake_ssh.write_text(
        "#!/bin/bash\n"
        "printf '%s\\n' \"$@\" > \"$CAPTURE_SSH\"\n",
        encoding="utf-8",
    )
    copied_wrapper.write_text(
        wrapper.replace(
            "readonly TIMEOUT_BIN=/usr/bin/timeout",
            f"readonly TIMEOUT_BIN={shlex.quote(str(fake_timeout))}",
        ).replace(
            "readonly SSH_BIN=/usr/bin/ssh",
            f"readonly SSH_BIN={shlex.quote(str(fake_ssh))}",
        ),
        encoding="utf-8",
    )
    for path in (fake_timeout, fake_ssh, copied_wrapper):
        path.chmod(0o700)

    remote = (
        "awk '{print $1}' /var/log/x | sed -n '1,20p'; "
        """psql -c "UPDATE jobs SET state='ready' WHERE id=42" """
    ).strip()
    env = {
        **os.environ,
        "CAPTURE_TIMEOUT": str(timeout_capture),
        "CAPTURE_SSH": str(ssh_capture),
        "AIOPS_TARGET_COMMAND_TIMEOUT_SEC": "17",
        "AIOPS_TARGET_KNOWN_HOSTS": "/secure/known_hosts",
        "AIOPS_TARGET_SSH_KEY": "/secure/id_ed25519",
        "AIOPS_TARGET_PORT": "2222",
        "AIOPS_TARGET_SSH_USER": "runner",
        "AIOPS_TARGET_ADDRESS": "192.0.2.10",
    }
    completed = subprocess.run(
        [str(copied_wrapper), remote],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert timeout_capture.read_text(encoding="utf-8").splitlines() == ["17"]
    ssh_argv = ssh_capture.read_text(encoding="utf-8").splitlines()
    assert ssh_argv[:4] == ["-F", "/dev/null", "-T", "-o"]
    assert "BatchMode=yes" in ssh_argv
    assert "ClearAllForwardings=yes" in ssh_argv
    assert "PermitLocalCommand=no" in ssh_argv
    assert "UserKnownHostsFile=/secure/known_hosts" in ssh_argv
    assert "GlobalKnownHostsFile=/dev/null" in ssh_argv
    assert "UpdateHostKeys=no" in ssh_argv
    assert "StrictHostKeyChecking=yes" in ssh_argv
    assert "IdentitiesOnly=yes" in ssh_argv
    assert ssh_argv[-3:] == [
        "runner@192.0.2.10",
        "--",
        f"cd / && {remote}",
    ]


def test_skill_freezes_native_diagnostics_and_four_field_output_contract():
    skill = SKILL_PATH.read_text(encoding="utf-8")
    assert "最多调用 20 次 `./bin/target-exec`" in skill
    assert "沿最大贡献路径逐层下钻，深度不限" in skill
    for evidence_source in (
        "systemctl",
        "`ps`",
        "`ss`",
        "/proc/<pid>/exe",
        "/proc/<pid>/cgroup",
        "podman",
        "docker",
        "deleted-open",
        "inode",
        "overlay",
        "volume",
    ):
        assert evidence_source in skill
    assert "不在目标机安装、升级或下载任何工具" in skill
    assert "`repair_commands` 和 `verification_steps` 都必须非空" in skill
    assert "'awk '\"'\"'{print $1}'\"'\"' /var/log/x'" in skill

    sample = skill.split("```json", 1)[1].split("```", 1)[0]
    proposal = json.loads(sample)
    assert set(proposal) == {
        "diagnosis_conclusion",
        "repair_commands",
        "impact_scope",
        "rollback_and_verification",
    }
    assert set(proposal["repair_commands"][0]) == {
        "command",
        "reason",
        "expected_result",
    }
    assert set(
        proposal["rollback_and_verification"]["verification_steps"][0]
    ) == {"command", "success_criteria"}


def test_skill_requires_assistant_only_terminal_verification_marker():
    skill = SKILL_PATH.read_text(encoding="utf-8")
    assert (
        '{"kind":"verification","status":"succeeded","result":"简体中文验证结果"}'
        in skill
    )
    assert (
        '{"kind":"verification","status":"failed","result":"简体中文失败证据"}'
        in skill
    )
    assert "assistant content.text" in skill
    assert "执行完成条件不可省略" in skill
    assert "验证无法完成、" in skill
    assert "任一命令失败时也不得直接结束" in skill
    assert "不得在它前后输出自由文本、Markdown、代码块、" in skill
    assert "第二个 JSON 或额外字段" in skill
    assert "不得把它放进 tool stdout 或 `plan_delta` marker" in skill


def test_inspection_skill_uses_host_context_for_bounded_service_diagnostics():
    skill = INSPECTION_SKILL_PATH.read_text(encoding="utf-8")
    assert "<untrusted-host-context>" in skill
    assert "最多选择 3 个诊断锚点" in skill
    assert "每个诊断锚点最多追加 2 次调用" in skill
    assert "合计最多使用 18 次调用" in skill
    assert "至少保留 2 次预算" in skill
    assert "仅因历史服务消失不得判定异常" in skill
    assert "/proc/<pid>/environ" in skill
