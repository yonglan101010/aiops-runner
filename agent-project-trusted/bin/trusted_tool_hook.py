#!/usr/bin/python3
"""Fail-closed PreToolUse boundary for trusted Claude sessions.

This guard deliberately validates only the *runner-local* tool shape.  The
remote command remains opaque to preserve the trusted-session blueprint's
approved free-terminal semantics.
"""

from __future__ import annotations

import json
import shlex
import sys
from typing import Any, Mapping


_MAX_LOCAL_COMMAND_LENGTH = 65536
_ALLOWED_BASH_INPUT_KEYS = {
    "command",
    "description",
    "timeout",
    "run_in_background",
    "dangerouslyDisableSandbox",
}


def _decision(value: str, reason: str | None = None) -> dict[str, Any]:
    output: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": value,
    }
    if reason:
        output["permissionDecisionReason"] = reason
    return {"hookSpecificOutput": output}


def _deny(reason: str) -> dict[str, Any]:
    return _decision("deny", reason)


def _has_local_shell_control(command: str) -> bool:
    """Return true for operators or expansions evaluated by the local shell.

    Operators inside a single-quoted ``target-exec`` argument are intentionally
    ignored: they belong to the opaque remote command and are governed by the
    trusted-session workflow, not by this local boundary.
    """

    quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        if char == "\x00" or char in "\r\n":
            return True
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            # Avoid accepting alternate spellings that shlex and the invoking
            # shell could interpret differently.
            return True
        if char == "'":
            if quote is None:
                quote = "'"
            index += 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char in "$`":
            return True
        if quote is None and char in ";&|<>(){}#*?[]~":
            return True
        index += 1
    return quote is not None


def _is_fully_quoted_argument(value: str) -> bool:
    """Accept one shell word made entirely from adjacent quoted segments."""

    index = 0
    content_length = 0
    while index < len(value):
        quote = value[index]
        if quote not in {"'", '"'}:
            return False
        index += 1
        closed = False
        while index < len(value):
            char = value[index]
            if char == quote:
                index += 1
                closed = True
                break
            if char == "\x00" or char in "\r\n":
                return False
            # Expansions and escapes in double quotes would be evaluated by
            # the runner-local shell. Use adjacent single-quoted segments to
            # represent such bytes without changing the remote command.
            if quote == '"' and char in "$`\\":
                return False
            content_length += 1
            index += 1
        if not closed:
            return False
    return content_length > 0


def _valid_target_exec(command: Any) -> bool:
    if (
        not isinstance(command, str)
        or not command.strip()
        or len(command) > _MAX_LOCAL_COMMAND_LENGTH
        or _has_local_shell_control(command)
    ):
        return False
    stripped = command.strip()
    outer = stripped.split(maxsplit=1)
    if len(outer) != 2 or outer[0] != "./bin/target-exec":
        return False
    wrapped = outer[1].strip()
    if not _is_fully_quoted_argument(wrapped):
        return False
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return False
    return (
        len(words) == 2
        and words[0] == "./bin/target-exec"
        and bool(words[1].strip())
    )


def evaluate_hook(payload: Mapping[str, Any]) -> dict[str, Any]:
    if payload.get("hook_event_name") != "PreToolUse":
        return _deny("trusted session only accepts PreToolUse validation")

    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return _deny("trusted session rejected malformed tool input")

    # Claude Code uses this built-in, non-shell tool to materialize the value
    # requested by ``--json-schema``.  It cannot execute commands or access
    # the runner filesystem; denying it leaves a completed diagnosis without
    # a terminal ``result.structured_output`` and therefore forces manual
    # intervention.  All stateful/local tools remain denied below.
    if tool_name == "StructuredOutput":
        return _decision("allow")

    if tool_name == "Skill":
        if tool_input.get("skill") in {
            "trusted-repair-session", "trusted-inspection-session", "host-context-initialization"
        }:
            return _decision("allow")
        return _deny("only a trusted AIOps session skill may be invoked")

    if tool_name != "Bash":
        return _deny("trusted session only permits its Skill and target-exec")

    if set(tool_input) - _ALLOWED_BASH_INPUT_KEYS:
        return _deny("trusted session rejected unsupported Bash input")
    if (
        "run_in_background" in tool_input
        and tool_input["run_in_background"] is not False
    ):
        return _deny("background Bash is not permitted in trusted sessions")
    if (
        "dangerouslyDisableSandbox" in tool_input
        and tool_input["dangerouslyDisableSandbox"] is not False
    ):
        return _deny("sandbox bypass is not permitted in trusted sessions")
    if not _valid_target_exec(tool_input.get("command")):
        return _deny(
            "Bash must be exactly: ./bin/target-exec '<one remote command>'"
        )
    return _decision("allow")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, Mapping):
            result = _deny("trusted session rejected malformed hook input")
        else:
            result = evaluate_hook(payload)
    except Exception:
        # Never expose input or exception details: tool input can contain
        # credentials, and every hook failure must resolve to a denial.
        result = _deny("trusted session tool policy failed closed")
    json.dump(result, sys.stdout, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
