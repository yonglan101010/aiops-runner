"""Private four-section diagnosis draft and deterministic v1 expansion.

The Claude-facing schema is intentionally not the public AIOps callback
contract.  Claude owns only the four business sections below; Runner owns every
identity, sequencing, timeout, risk and digest field in ``RepairProposal v1``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Mapping

from jsonschema import Draft7Validator, FormatChecker

from .trusted_repair_contract import (
    PROPOSAL_HASH_ALGORITHM_ID,
    PROPOSAL_HASH_FIELDS,
    SCHEMA_VERSION,
    _canonical_json,
)


DEFAULT_COMMAND_TIMEOUT_SECONDS = 30
DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS = frozenset(
    {
        "diagnosis_conclusion",
        "repair_commands",
        "impact_scope",
        "rollback_and_verification",
    }
)

_NONEMPTY = {"type": "string", "minLength": 1, "maxLength": 16384}
_COMMAND = {"type": "string", "minLength": 1, "maxLength": 32768}

DIAGNOSIS_DRAFT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "additionalProperties": False,
    "required": sorted(DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS),
    "properties": {
        "diagnosis_conclusion": {
            "type": "object",
            "additionalProperties": False,
            "required": ["summary", "root_cause", "evidence", "confidence_percent"],
            "properties": {
                "summary": _NONEMPTY,
                "root_cause": _NONEMPTY,
                "evidence": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["summary", "source", "reference"],
                        "properties": {
                            "summary": _NONEMPTY,
                            "source": {
                                "type": "string",
                                "enum": ["command", "file", "metric", "log", "other"],
                            },
                            "reference": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 2048,
                            },
                        },
                    },
                },
                "confidence_percent": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                },
            },
        },
        "repair_commands": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["command", "reason", "expected_result"],
                "properties": {
                    "command": _COMMAND,
                    "reason": _NONEMPTY,
                    "expected_result": _NONEMPTY,
                },
            },
        },
        "impact_scope": {
            "type": "object",
            "additionalProperties": False,
            "required": ["expected_impact", "affected_scope", "risk_summary"],
            "properties": {
                "expected_impact": _NONEMPTY,
                "affected_scope": _NONEMPTY,
                "risk_summary": _NONEMPTY,
            },
        },
        "rollback_and_verification": {
            "type": "object",
            "additionalProperties": False,
            "required": ["rollback_instructions", "verification_steps"],
            "properties": {
                "rollback_instructions": _NONEMPTY,
                "verification_steps": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["command", "success_criteria"],
                        "properties": {
                            "command": _COMMAND,
                            "success_criteria": _NONEMPTY,
                        },
                    },
                },
            },
        },
    },
}

Draft7Validator.check_schema(DIAGNOSIS_DRAFT_SCHEMA)
_DRAFT_VALIDATOR = Draft7Validator(
    DIAGNOSIS_DRAFT_SCHEMA, format_checker=FormatChecker()
)

_SHELL_CONTROL = re.compile(r"[;&|><`\r\n]|\$\(|\$\{")
_READ_ONLY_PROGRAMS = frozenset(
    {
        "[",
        "df",
        "du",
        "findmnt",
        "free",
        "id",
        "ls",
        "ps",
        "pwd",
        "ss",
        "stat",
        "test",
        "true",
        "uname",
        "uptime",
        "whoami",
    }
)
_READ_ONLY_SYSTEMCTL_ACTIONS = frozenset(
    {
        "is-active",
        "is-enabled",
        "is-failed",
        "list-dependencies",
        "list-unit-files",
        "list-units",
        "show",
        "status",
    }
)


class TrustedProposalDraftError(ValueError):
    """Stable validation failure for model-owned diagnosis output."""

    code = "TRUSTED_PROPOSAL_DRAFT_INVALID"


def diagnosis_draft_schema_json() -> str:
    """Return the exact inline schema accepted by Claude CLI ``--json-schema``."""
    return json.dumps(
        DIAGNOSIS_DRAFT_SCHEMA,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def validate_diagnosis_draft(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and deep-copy one private four-section diagnosis draft."""
    if not isinstance(value, Mapping):
        raise TrustedProposalDraftError("diagnosis structured_output must be an object")
    errors = sorted(
        _DRAFT_VALIDATOR.iter_errors(value),
        key=lambda item: [str(part) for part in item.absolute_path],
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise TrustedProposalDraftError(
            f"diagnosis draft validation failed at {path}: {errors[0].message}"
        )
    # JSON round-trip strips Mapping subclasses and prevents callers from
    # mutating the validated object after it enters the session pipeline.
    return json.loads(json.dumps(dict(value), ensure_ascii=False))


def _confidence_string(percent: int) -> str:
    if percent == 0:
        return "0"
    if percent == 100:
        return "1"
    return f"{percent / 100:.2f}".rstrip("0").rstrip(".")


def _observed_at(value: datetime | str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise TrustedProposalDraftError("observed_at must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if not isinstance(value, str) or not value:
        raise TrustedProposalDraftError("observed_at must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustedProposalDraftError("observed_at must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise TrustedProposalDraftError("observed_at must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _runner_timeout(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrustedProposalDraftError("command timeout must be an integer")
    return max(1, min(value, 1800))


def command_is_high_risk(command: str) -> bool:
    """Classify only a narrow read-only command set as low risk.

    Anything compound, shell-expanded, privileged, modifying, or unknown is
    high risk.  This conservative default is a Runner decision, never a model
    assertion.
    """
    if not isinstance(command, str) or not command.strip() or _SHELL_CONTROL.search(command):
        return True
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return True
    if not argv:
        return True
    program = os.path.basename(argv[0])
    if program in _READ_ONLY_PROGRAMS:
        return False
    if program == "systemctl" and len(argv) >= 2:
        action = next((item for item in argv[1:] if not item.startswith("-")), "")
        return action not in _READ_ONLY_SYSTEMCTL_ACTIONS
    return True


def expand_diagnosis_draft_to_v1(
    draft: Mapping[str, Any],
    *,
    runner_provider_id: str,
    logical_target_id: str,
    observed_at: datetime | str,
    command_timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Build a public ``RepairProposal v1`` from a validated private draft.

    The result is created from an empty dictionary.  Model data therefore
    cannot override target identity, protocol version, sequence, timeout,
    risk, failure policy or hash fields.
    """
    validated = validate_diagnosis_draft(draft)
    timestamp = _observed_at(observed_at)
    timeout = _runner_timeout(command_timeout_seconds)
    diagnosis = validated["diagnosis_conclusion"]
    impact = validated["impact_scope"]
    rollback = validated["rollback_and_verification"]

    proposal: dict[str, Any] = {
        "kind": "repair_proposal",
        "schema_version": SCHEMA_VERSION,
        "proposal_revision": 1,
        "proposal_hash_algorithm_id": PROPOSAL_HASH_ALGORITHM_ID,
        "proposal_hash": "",
        "diagnosis_summary": diagnosis["summary"],
        "root_cause": diagnosis["root_cause"],
        "evidence": [
            {
                "summary": item["summary"],
                "source": item["source"],
                "observed_at": timestamp,
                "reference": item["reference"],
            }
            for item in diagnosis["evidence"]
        ],
        "confidence": _confidence_string(diagnosis["confidence_percent"]),
        "target": {
            "runner_provider_id": str(runner_provider_id),
            "logical_target_id": str(logical_target_id),
            "platform": "linux",
        },
        "initial_commands": [
            {
                "sequence": sequence,
                "command": item["command"],
                "cwd": "/",
                "reason": item["reason"],
                "expected_result": item["expected_result"],
                "expected_impact": impact["expected_impact"],
                "timeout_seconds": timeout,
                "high_risk": command_is_high_risk(item["command"]),
                "on_failure": "stop_and_reassess",
            }
            for sequence, item in enumerate(validated["repair_commands"], start=1)
        ],
        "expected_impact": impact["expected_impact"],
        "affected_scope": impact["affected_scope"],
        "rollback_instructions": rollback["rollback_instructions"],
        "verification_steps": [
            {
                "sequence": sequence,
                "command": item["command"],
                "success_criteria": item["success_criteria"],
                "timeout_seconds": timeout,
            }
            for sequence, item in enumerate(rollback["verification_steps"], start=1)
        ],
        "risk_summary": impact["risk_summary"],
    }
    hash_payload = {field: proposal[field] for field in PROPOSAL_HASH_FIELDS}
    proposal["proposal_hash"] = "sha256:" + hashlib.sha256(
        _canonical_json(hash_payload).encode("utf-8")
    ).hexdigest()
    return proposal


__all__ = [
    "DEFAULT_COMMAND_TIMEOUT_SECONDS",
    "DIAGNOSIS_DRAFT_SCHEMA",
    "DIAGNOSIS_DRAFT_TOP_LEVEL_KEYS",
    "TrustedProposalDraftError",
    "command_is_high_risk",
    "diagnosis_draft_schema_json",
    "expand_diagnosis_draft_to_v1",
    "validate_diagnosis_draft",
]
