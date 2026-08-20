"""Persistent manual multi-target inspection orchestration."""

from __future__ import annotations

import hashlib
import json
import os
import getpass
import re
import copy
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from .callback import Sender
from .config import TrustedInspectionConfig
from .trusted_inventory import ManagedInventory
from .trusted_proposal_draft import diagnosis_draft_schema_json
from .trusted_session import (
    TrustedSessionError,
    TrustedSessionOrchestrator,
    _minimal_child_env,
    config_fingerprint,
    redact_sensitive,
)


INSPECTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "overall_status",
        "summary",
        "resource_snapshot",
        "service_inventory",
        "baseline_checks",
        "findings",
    ],
    "properties": {
        "schema_version": {"const": 2},
        "overall_status": {
            "enum": ["HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"]
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 600},
        "resource_snapshot": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "cpu_usage_percent",
                "load_per_core",
                "memory_available_percent",
                "max_disk_usage_percent",
                "max_inode_usage_percent",
            ],
            "properties": {
                "cpu_usage_percent": {
                    "type": ["number", "null"], "minimum": 0, "maximum": 100
                },
                "load_per_core": {"type": ["number", "null"], "minimum": 0},
                "memory_available_percent": {
                    "type": ["number", "null"], "minimum": 0, "maximum": 100
                },
                "max_disk_usage_percent": {
                    "type": ["number", "null"], "minimum": 0, "maximum": 100
                },
                "max_inode_usage_percent": {
                    "type": ["number", "null"], "minimum": 0, "maximum": 100
                },
            },
        },
        "service_inventory": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "collection_status",
                "totals",
                "items",
                "other_running_services",
                "truncated",
            ],
            "properties": {
                "collection_status": {
                    "enum": ["COMPLETE", "PARTIAL", "UNAVAILABLE"]
                },
                "totals": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "systemd_running",
                        "containers_running",
                        "listening_ports",
                        "high_resource_processes",
                    ],
                    "properties": {
                        "systemd_running": {"type": "integer", "minimum": 0},
                        "containers_running": {"type": "integer", "minimum": 0},
                        "listening_ports": {"type": "integer", "minimum": 0},
                        "high_resource_processes": {"type": "integer", "minimum": 0},
                    },
                },
                "items": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "kind",
                            "name",
                            "display_name",
                            "status",
                            "importance",
                            "key_reasons",
                            "ports",
                            "health_summary",
                        ],
                        "properties": {
                            "kind": {
                                "enum": ["systemd", "container", "process"]
                            },
                            "name": {
                                "type": "string", "minLength": 1, "maxLength": 255
                            },
                            "display_name": {
                                "type": "string", "minLength": 1, "maxLength": 500
                            },
                            "status": {
                                "enum": ["RUNNING", "DEGRADED", "UNKNOWN"]
                            },
                            "importance": {"enum": ["KEY", "OTHER"]},
                            "key_reasons": {
                                "type": "array",
                                "uniqueItems": True,
                                "items": {
                                    "enum": [
                                        "LISTENING", "CONTAINER", "HIGH_RESOURCE"
                                    ]
                                },
                            },
                            "ports": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["protocol", "port"],
                                    "properties": {
                                        "protocol": {"enum": ["tcp", "udp"]},
                                        "port": {
                                            "type": "integer",
                                            "minimum": 1,
                                            "maximum": 65535,
                                        },
                                    },
                                },
                            },
                            "health_summary": {
                                "type": "string", "minLength": 1, "maxLength": 500
                            },
                        },
                    },
                },
                "other_running_services": {
                    "type": "array",
                    "maxItems": 300,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["name", "display_name"],
                        "properties": {
                            "name": {
                                "type": "string", "minLength": 1, "maxLength": 255
                            },
                            "display_name": {
                                "type": "string", "minLength": 1, "maxLength": 500
                            },
                        },
                    },
                },
                "truncated": {"type": "boolean"},
            },
        },
        "baseline_checks": {
            "type": "array",
            "minItems": 8,
            "maxItems": 8,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["category", "status", "summary", "evidence"],
                "properties": {
                    "category": {
                        "enum": [
                            "cpu", "memory", "disk", "inode", "service",
                            "network", "process", "container",
                        ]
                    },
                    "status": {"enum": ["PASS", "WARN", "FAIL", "UNKNOWN"]},
                    "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
                    "evidence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["reference", "observation"],
                            "properties": {
                                "reference": {
                                    "type": "string", "minLength": 1, "maxLength": 2000
                                },
                                "observation": {
                                    "type": "string", "minLength": 1, "maxLength": 1200
                                },
                            },
                        },
                    },
                },
            },
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "severity", "category", "title", "description",
                    "evidence", "recommendation",
                ],
                "properties": {
                    "severity": {"enum": ["WARNING", "CRITICAL"]},
                    "category": {"type": "string", "minLength": 1, "maxLength": 64},
                    "title": {"type": "string", "minLength": 1, "maxLength": 500},
                    "description": {"type": "string", "minLength": 1, "maxLength": 4000},
                    "recommendation": {"type": "string", "minLength": 1, "maxLength": 4000},
                    "evidence": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["reference", "observation"],
                            "properties": {
                                "reference": {
                                    "type": "string", "minLength": 1, "maxLength": 2000
                                },
                                "observation": {
                                    "type": "string", "minLength": 1, "maxLength": 1200
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}
Draft202012Validator.check_schema(INSPECTION_SCHEMA)
_REPORT_VALIDATOR = Draft202012Validator(INSPECTION_SCHEMA)
CLAUDE_INSPECTION_SCHEMA = copy.deepcopy(INSPECTION_SCHEMA)
CLAUDE_INSPECTION_SCHEMA["required"].remove("service_inventory")
del CLAUDE_INSPECTION_SCHEMA["properties"]["service_inventory"]
CLAUDE_INSPECTION_SCHEMA["required"].remove("schema_version")
del CLAUDE_INSPECTION_SCHEMA["properties"]["schema_version"]
CLAUDE_INSPECTION_SCHEMA["properties"]["resource_snapshot"]["required"] = []
for _metric_schema in CLAUDE_INSPECTION_SCHEMA["properties"][
    "resource_snapshot"
]["properties"].values():
    _metric_schema["type"] = "number"
Draft202012Validator.check_schema(CLAUDE_INSPECTION_SCHEMA)
_CLAUDE_REPORT_VALIDATOR = Draft202012Validator(CLAUDE_INSPECTION_SCHEMA)
_TERMINAL = {
    "HEALTHY", "WARNING", "CRITICAL", "UNKNOWN", "FAILED", "CANCELLED"
}
# UNKNOWN is a schema-valid, evidence-limited report. In particular, command
# budget recovery must not turn a safely finalised UNKNOWN report into a batch
# failure merely because a conclusion could not be supported by the evidence.
_VALID_REPORT = {"HEALTHY", "WARNING", "CRITICAL", "UNKNOWN"}
_BASELINE_CATEGORY_ORDER = (
    "cpu", "memory", "disk", "inode", "service", "network", "process", "container"
)
_BASELINE_CATEGORIES = set(_BASELINE_CATEGORY_ORDER)
_INSPECTION_FORMAT_RETRY_TIMEOUT_SEC = 30
_COMMAND_BUDGET_SUMMARY_PREFIX = "本次巡检达到命令预算上限，以下结论仅基于已收集证据。"
_INSPECTION_CALLBACK_MAX_ATTEMPTS = 3
_INSPECTION_CALLBACK_RETRY_DELAY_SEC = 0.25
# Terminal snapshots are durable in the local journal.  When the control plane
# is restarting, retry the latest terminal snapshot with a bounded backoff
# rather than leaving the batch permanently RUNNING upstream.
_INSPECTION_CALLBACK_RETRY_INITIAL_DELAY_SEC = 5
_INSPECTION_CALLBACK_RETRY_MAX_DELAY_SEC = 300
_INSPECTION_CALLBACK_REPLAY_POLL_SEC = 1
_TERMINAL_BATCH_STATUSES = {"SUCCEEDED", "PARTIAL_SUCCESS", "FAILED", "CANCELLED"}
_REPAIR_COMMAND_PATTERN = re.compile(
    r"```|(?:^|\n)\s*[$#]\s+\S|"
    r"\b(?:sudo\s+)?systemctl\s+\S+|"
    r"\b(?:docker|podman|kubectl)\s+\S+|"
    r"\b(?:apt(?:-get)?|yum|dnf|apk)\s+\S+|"
    r"(?:^|\s)(?:rm\s+-|sed\s+-i|chmod\s+|chown\s+)",
    re.IGNORECASE,
)
_KUBERNETES_FACT_NUMBER_PATTERN = re.compile(
    r"(?<![\w.-])\d+(?:\.\d+)?%?(?![\w.-])"
)
_KUBERNETES_OBJECT_REFERENCE_PATTERN = re.compile(
    r"\b(Node|Namespace|Deployment|StatefulSet|DaemonSet|ReplicaSet|Pod|Job|CronJob|"
    r"Service|EndpointSlice|Ingress|PersistentVolumeClaim|PersistentVolume|"
    r"StorageClass|HorizontalPodAutoscaler)/([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)\b",
    re.IGNORECASE,
)
_KUBERNETES_SEVERITY_CLAIM_PATTERN = re.compile(
    r"\b(?:HEALTHY|WARNING|CRITICAL|UNKNOWN)\b|健康|警告|严重|未知",
    re.IGNORECASE,
)
_SERVICE_SECTIONS = {
    "__AIOPS_SYSTEMD__": "systemd",
    "__AIOPS_LISTENERS__": "listeners",
    "__AIOPS_CONTAINERS__": "containers",
    "__AIOPS_PROCESSES__": "processes",
}
_SERVICE_INVENTORY_COMMAND = (
    "printf '__AIOPS_SYSTEMD__\\n'; "
    "LC_ALL=C systemctl list-units --type=service --state=running "
    "--no-legend --plain --no-pager 2>/dev/null || true; "
    "printf '__AIOPS_LISTENERS__\\n'; "
    "LC_ALL=C ss -H -lntup 2>/dev/null || LC_ALL=C netstat -lntup 2>/dev/null || true; "
    "printf '__AIOPS_CONTAINERS__\\n'; "
    "if command -v docker >/dev/null; then "
    "docker ps --format '{{.Names}}\\t{{.Status}}\\t{{.Ports}}'; "
    "elif command -v podman >/dev/null; then "
    "podman ps --format '{{.Names}}\\t{{.Status}}\\t{{.Ports}}'; fi; "
    "printf '__AIOPS_PROCESSES__\\n'; "
    "LC_ALL=C ps -eo comm=,%cpu=,%mem= --sort=-%cpu 2>/dev/null | head -n 30"
)
_SAFE_INSPECTION_RECOMMENDATION = (
    "建议人工确认问题影响并生成修复提案，具体操作经审批后执行。"
)
_PUBLIC_FAILURE_CODES = {
    "MODEL_AUTHENTICATION_FAILED",
    "MODEL_RATE_LIMITED",
    "MODEL_QUOTA_EXHAUSTED",
    "MODEL_PROVIDER_UNAVAILABLE",
    "MODEL_CONNECTION_FAILED",
    "INSPECTION_CONFIGURATION_INVALID",
    "TARGET_CONNECTION_FAILED",
    "INSPECTION_TIMEOUT",
    "INSPECTION_COMMAND_BUDGET_EXHAUSTED",
    "INSPECTION_OUTPUT_INVALID",
    "RUNNER_RESTARTED_DURING_INSPECTION",
    "INSPECTION_FAILED",
}

KUBERNETES_INTERPRETATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["executive_summary", "priorities", "limitations"],
    "properties": {
        "executive_summary": {"type": "string", "minLength": 1, "maxLength": 1200},
        "priorities": {
            "type": "array",
            "maxItems": 3,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["finding_id", "explanation", "impact", "recommendation"],
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1, "maxLength": 64},
                    "explanation": {"type": "string", "minLength": 1, "maxLength": 1200},
                    "impact": {"type": "string", "minLength": 1, "maxLength": 800},
                    "recommendation": {"type": "string", "minLength": 1, "maxLength": 1200},
                },
            },
        },
        "limitations": {
            "type": "array",
            "maxItems": 10,
            "items": {"type": "string", "minLength": 1, "maxLength": 500},
        },
    },
}
Draft202012Validator.check_schema(KUBERNETES_INTERPRETATION_SCHEMA)
_KUBERNETES_INTERPRETATION_VALIDATOR = Draft202012Validator(
    KUBERNETES_INTERPRETATION_SCHEMA
)


def _public_inspection_failure(exc: Exception) -> dict[str, Any]:
    classified = getattr(exc, "failure_code", None)
    if classified not in _PUBLIC_FAILURE_CODES:
        error_code = str(getattr(exc, "code", type(exc).__name__))
        if "TARGET_CONNECTION" in error_code:
            classified = "TARGET_CONNECTION_FAILED"
        elif "PROCESS_TIMEOUT" in error_code:
            classified = "INSPECTION_TIMEOUT"
        elif "COMMAND_BUDGET" in error_code:
            classified = "INSPECTION_COMMAND_BUDGET_EXHAUSTED"
        elif error_code in {
            "TRUSTED_INSPECTION_REPORT_MISSING",
            "TRUSTED_INSPECTION_REPORT_INVALID",
            "TRUSTED_INSPECTION_BASELINE_INCOMPLETE",
            "TRUSTED_INSPECTION_FINDING_ORDER_INVALID",
            "TRUSTED_INSPECTION_STATUS_INCONSISTENT",
            "TRUSTED_INSPECTION_REPAIR_COMMAND_FORBIDDEN",
            "TRUSTED_INSPECTION_SERVICE_STATUS_INVALID",
            "TRUSTED_INSPECTION_SERVICE_DUPLICATE",
            "TRUSTED_INSPECTION_SERVICE_IMPORTANCE_INVALID",
            "TRUSTED_INSPECTION_SERVICE_LIMIT_EXCEEDED",
            "TRUSTED_INSPECTION_SERVICE_TOTAL_INCONSISTENT",
            "TRUSTED_STREAM_INVALID_JSON",
            "TRUSTED_STREAM_UNCLOSED_TOOL",
            "TRUSTED_STREAM_NO_TERMINAL",
        }:
            classified = "INSPECTION_OUTPUT_INVALID"
        elif error_code in {
            "TRUSTED_INSPECTION_VALIDATION_FAILED",
            "TRUSTED_INVENTORY_UNAVAILABLE",
            "TRUSTED_PROJECT_DIR_MISSING",
            "TRUSTED_CLAUDE_BINARY_MISSING",
        }:
            classified = "INSPECTION_CONFIGURATION_INVALID"
        elif error_code == "RUNNER_RESTARTED_DURING_INSPECTION":
            classified = error_code
        else:
            classified = "INSPECTION_FAILED"
    failure: dict[str, Any] = {"code": classified}
    http_status = getattr(exc, "http_status", None)
    if (
        isinstance(http_status, int)
        and not isinstance(http_status, bool)
        and 100 <= http_status <= 599
    ):
        failure["http_status"] = http_status
    return failure


def _validated_kubernetes_interpretation(
    value: Any, evidence: Mapping[str, Any]
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    candidate = copy.deepcopy(dict(value))
    if list(_KUBERNETES_INTERPRETATION_VALIDATOR.iter_errors(candidate)):
        return None
    allowed = {
        str(item.get("finding_id"))
        for item in evidence.get("findings", [])
        if isinstance(item, Mapping) and item.get("finding_id")
    }
    referenced = [
        str(item.get("finding_id"))
        for item in candidate.get("priorities", [])
        if isinstance(item, Mapping)
    ]
    if len(referenced) != len(set(referenced)) or any(
        finding_id not in allowed for finding_id in referenced
    ):
        return None
    rendered = json.dumps(candidate, ensure_ascii=False)
    if _REPAIR_COMMAND_PATTERN.search(rendered):
        return None
    if _KUBERNETES_SEVERITY_CLAIM_PATTERN.search(rendered):
        return None

    def fact_numbers(value: Any) -> set[str]:
        return set(_KUBERNETES_FACT_NUMBER_PATTERN.findall(
            json.dumps(value, ensure_ascii=False)
        ))

    def object_references(value: Any) -> set[str]:
        return {
            f"{kind}/{name}".casefold()
            for kind, name in _KUBERNETES_OBJECT_REFERENCE_PATTERN.findall(
                json.dumps(value, ensure_ascii=False)
            )
        }

    if not fact_numbers(candidate.get("executive_summary")) <= fact_numbers(evidence):
        return None
    if not object_references(candidate.get("executive_summary")) <= object_references(evidence):
        return None
    findings_by_id = {
        str(item.get("finding_id")): item
        for item in evidence.get("findings", [])
        if isinstance(item, Mapping) and item.get("finding_id")
    }
    for priority in candidate.get("priorities", []):
        source = findings_by_id.get(str(priority.get("finding_id")))
        if source is None:
            return None
        narrative = {
            key: priority.get(key)
            for key in ("explanation", "impact", "recommendation")
        }
        if not fact_numbers(narrative) <= fact_numbers(source):
            return None
        if not object_references(narrative) <= object_references(source):
            return None
    return candidate


def _failure_target_status(failure: Mapping[str, Any]) -> str:
    return (
        "UNKNOWN"
        if failure.get("code")
        in {
            "TARGET_CONNECTION_FAILED",
            "INSPECTION_TIMEOUT",
            "INSPECTION_COMMAND_BUDGET_EXHAUSTED",
            "RUNNER_RESTARTED_DURING_INSPECTION",
        }
        else "FAILED"
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _uuid(value: Any, label: str) -> str:
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_VALIDATION_FAILED", f"{label} must be a UUID"
        ) from exc
    if parsed != str(value):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_VALIDATION_FAILED", f"{label} must be canonical"
        )
    return parsed


def _expected_report_status(report: Mapping[str, Any]) -> str:
    checks = report.get("baseline_checks") or []
    findings = report.get("findings") or []
    severities = {
        item.get("severity") for item in findings if isinstance(item, Mapping)
    }
    check_statuses = {
        item.get("status") for item in checks if isinstance(item, Mapping)
    }
    if "CRITICAL" in severities:
        return "CRITICAL"
    if severities or check_statuses & {"WARN", "FAIL"}:
        return "WARNING"
    if "UNKNOWN" in check_statuses:
        return "UNKNOWN"
    return "HEALTHY"


def _normalize_report_status(report: dict[str, Any]) -> None:
    """Derive the terminal status from validated evidence instead of model prose."""
    report["overall_status"] = _expected_report_status(report)


def _unknown_fallback_report() -> dict[str, Any]:
    return {
        "overall_status": "UNKNOWN",
        "summary": "巡检已完成，但未获得可验证的结构化报告；所有基线状态按未知处理。",
        "resource_snapshot": {},
        "baseline_checks": [
            {
                "category": category,
                "status": "UNKNOWN",
                "summary": "未获得可验证的结构化结果",
                "evidence": [],
            }
            for category in _BASELINE_CATEGORY_ORDER
        ],
        "findings": [],
    }


def _is_command_budget_exhausted(exc: Exception) -> bool:
    return getattr(exc, "code", None) == "TRUSTED_DIAGNOSIS_COMMAND_BUDGET_EXHAUSTED"


def _mark_command_budget_limited(report: dict[str, Any]) -> None:
    summary = str(report.get("summary") or "")
    if summary.startswith(_COMMAND_BUDGET_SUMMARY_PREFIX):
        return
    report["summary"] = (
        _COMMAND_BUDGET_SUMMARY_PREFIX
        + summary[: 600 - len(_COMMAND_BUDGET_SUMMARY_PREFIX)]
    )


def _validate_report_semantics(report: Mapping[str, Any]) -> None:
    checks = report.get("baseline_checks") or []
    categories = [item.get("category") for item in checks if isinstance(item, Mapping)]
    if len(categories) != len(set(categories)) or set(categories) != _BASELINE_CATEGORIES:
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_BASELINE_INCOMPLETE",
            "inspection must report every baseline category exactly once",
        )
    findings = report.get("findings") or []
    if [item.get("severity") for item in findings] != sorted(
        (item.get("severity") for item in findings),
        key=lambda value: 0 if value == "CRITICAL" else 1,
    ):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_FINDING_ORDER_INVALID",
            "critical findings must precede warnings",
        )
    expected = _expected_report_status(report)
    if report.get("overall_status") != expected:
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_STATUS_INCONSISTENT",
            "inspection overall status conflicts with its evidence",
        )
    for finding in findings:
        recommendation = str(finding.get("recommendation") or "")
        if _REPAIR_COMMAND_PATTERN.search(recommendation):
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_REPAIR_COMMAND_FORBIDDEN",
                "inspection reports must not contain repair commands",
            )

    inventory = report.get("service_inventory") or {}
    items = inventory.get("items") or []
    other_services = inventory.get("other_running_services") or []
    collection_status = inventory.get("collection_status")
    if collection_status == "PARTIAL" and not inventory.get("truncated"):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_STATUS_INVALID",
            "partial service inventory must be marked truncated",
        )
    if collection_status == "UNAVAILABLE" and (
        items
        or other_services
        or any((inventory.get("totals") or {}).values())
        or inventory.get("truncated")
    ):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_STATUS_INVALID",
            "unavailable service inventory must not claim collected data",
        )
    identities = [
        (item.get("kind"), item.get("name"))
        for item in items
        if isinstance(item, Mapping)
    ]
    if len(identities) != len(set(identities)):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_DUPLICATE",
            "inspection service inventory contains duplicate identities",
        )
    for item in items:
        importance = item.get("importance")
        reasons = set(item.get("key_reasons") or [])
        if importance != "KEY" or not reasons:
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_SERVICE_IMPORTANCE_INVALID",
                "detailed service items must be key services",
            )
        if item.get("kind") == "container" and (
            importance != "KEY" or "CONTAINER" not in reasons
        ):
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_SERVICE_IMPORTANCE_INVALID",
                "running containers must be key services",
            )
        if item.get("ports") and (
            importance != "KEY" or "LISTENING" not in reasons
        ):
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_SERVICE_IMPORTANCE_INVALID",
                "listening services must be key services",
            )
    other_names = [item.get("name") for item in other_services]
    if len(other_names) != len(set(other_names)):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_DUPLICATE",
            "inspection compact service inventory contains duplicate identities",
        )
    detailed_systemd = {
        item.get("name") for item in items if item.get("kind") == "systemd"
    }
    if detailed_systemd & set(other_names):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_DUPLICATE",
            "service cannot appear in detailed and compact inventory",
        )
    if len(items) + len(other_services) > 300:
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_LIMIT_EXCEEDED",
            "inspection service inventory exceeds 300 collected services",
        )
    systemd_collected = len(detailed_systemd) + len(other_services)
    systemd_total = int((inventory.get("totals") or {}).get("systemd_running") or 0)
    if (
        systemd_collected > systemd_total
        or (not inventory.get("truncated") and systemd_collected != systemd_total)
    ):
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_SERVICE_TOTAL_INCONSISTENT",
            "systemd running total conflicts with collected services",
        )


def _sanitize_inspection_report(report: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = copy.deepcopy(dict(report))
    for finding in sanitized.get("findings") or []:
        recommendation = str(finding.get("recommendation") or "")
        if _REPAIR_COMMAND_PATTERN.search(recommendation):
            finding["recommendation"] = _SAFE_INSPECTION_RECOMMENDATION
    return sanitized


def _validated_model_report(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    report = _sanitize_inspection_report(value)
    if list(_CLAUDE_REPORT_VALIDATOR.iter_errors(report)) or "repair_commands" in report:
        return None
    _normalize_report_status(report)
    try:
        _validate_report_semantics(report)
    except TrustedSessionError:
        return None
    return report


def _unavailable_service_inventory() -> dict[str, Any]:
    return {
        "collection_status": "UNAVAILABLE",
        "totals": {
            "systemd_running": 0,
            "containers_running": 0,
            "listening_ports": 0,
            "high_resource_processes": 0,
        },
        "items": [],
        "other_running_services": [],
        "truncated": False,
    }


def _safe_inventory_text(value: Any, limit: int) -> str:
    return redact_sensitive(str(value or "").strip(), limit=limit) or "未提供说明"


def _service_sections(output: str) -> dict[str, list[str]]:
    sections = {value: [] for value in _SERVICE_SECTIONS.values()}
    current: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line in _SERVICE_SECTIONS:
            current = _SERVICE_SECTIONS[line]
        elif current is not None and line:
            sections[current].append(line)
    return sections


def _parse_service_inventory(output: str) -> dict[str, Any]:
    sections = _service_sections(output)
    systemd: dict[str, str] = {}
    for line in sections["systemd"]:
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            systemd[parts[0]] = _safe_inventory_text(
                parts[4] if len(parts) == 5 else parts[0], 500
            )

    key_items: dict[tuple[str, str], dict[str, Any]] = {}

    def match_systemd(process_name: str) -> str | None:
        candidate = process_name.lower()
        if not candidate:
            return None
        for unit_name, description in systemd.items():
            stem = unit_name.removesuffix(".service").split("@", 1)[0].lower()
            if (
                stem == candidate
                or (len(candidate) >= 4 and candidate in stem)
                or (len(stem) >= 4 and stem in candidate)
                or (len(candidate) >= 4 and candidate in description.lower())
            ):
                return unit_name
        return None

    def promote_systemd(
        unit_name: str,
        reason: str,
        port: tuple[str, int] | None = None,
    ) -> None:
        key = ("systemd", unit_name)
        item = key_items.setdefault(key, {
            "kind": "systemd",
            "name": unit_name,
            "display_name": systemd.get(unit_name, unit_name),
            "status": "RUNNING",
            "importance": "KEY",
            "key_reasons": [],
            "ports": [],
            "health_summary": "systemd 显示为运行中",
        })
        if reason not in item["key_reasons"]:
            item["key_reasons"].append(reason)
        if port is not None:
            value = {"protocol": port[0], "port": port[1]}
            if value not in item["ports"]:
                item["ports"].append(value)

    listening_ports: set[tuple[str, int]] = set()
    unmatched_listeners: dict[str, set[tuple[str, int]]] = {}
    for line in sections["listeners"]:
        columns = line.split()
        if not columns:
            continue
        protocol = "tcp" if columns[0].lower().startswith("tcp") else (
            "udp" if columns[0].lower().startswith("udp") else ""
        )
        if not protocol or len(columns) < 5:
            continue
        local_address = columns[4]
        port_text = local_address.rsplit(":", 1)[-1]
        if not port_text.isdigit():
            continue
        port = (protocol, int(port_text))
        listening_ports.add(port)
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        process_name = process_match.group(1) if process_match else ""
        unit_name = match_systemd(process_name)
        if unit_name:
            promote_systemd(unit_name, "LISTENING", port)
        elif process_name:
            unmatched_listeners.setdefault(process_name, set()).add(port)

    for process_name, ports in unmatched_listeners.items():
        key_items[("process", process_name)] = {
            "kind": "process",
            "name": _safe_inventory_text(process_name, 255),
            "display_name": _safe_inventory_text(process_name, 500),
            "status": "UNKNOWN",
            "importance": "KEY",
            "key_reasons": ["LISTENING"],
            "ports": [
                {"protocol": protocol, "port": port}
                for protocol, port in sorted(ports)
            ],
            "health_summary": "检测到监听端口，但无法可靠关联 systemd 服务",
        }

    container_count = 0
    for line in sections["containers"]:
        parts = line.split("\t", 2)
        if not parts or not parts[0].strip():
            continue
        container_count += 1
        name = _safe_inventory_text(parts[0], 255)
        status_text = _safe_inventory_text(parts[1] if len(parts) > 1 else "", 500)
        port_text = parts[2] if len(parts) > 2 else ""
        ports = []
        for port_match in re.finditer(
            r"(?:^|,\s*)(?:[^,\s]+:)?(\d+)->\d+/(tcp|udp)", port_text
        ):
            value = {
                "protocol": port_match.group(2),
                "port": int(port_match.group(1)),
            }
            if value not in ports:
                ports.append(value)
                listening_ports.add((value["protocol"], value["port"]))
        degraded = "unhealthy" in status_text.lower() or "restarting" in status_text.lower()
        key_items[("container", name)] = {
            "kind": "container",
            "name": name,
            "display_name": name,
            "status": "DEGRADED" if degraded else "RUNNING",
            "importance": "KEY",
            "key_reasons": ["CONTAINER", *(["LISTENING"] if ports else [])],
            "ports": sorted(ports, key=lambda value: (value["protocol"], value["port"])),
            "health_summary": status_text,
        }

    high_resource_processes: set[str] = set()
    for line in sections["processes"]:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            cpu_percent = float(parts[-2])
            memory_percent = float(parts[-1])
        except ValueError:
            continue
        if cpu_percent < 10 and memory_percent < 10:
            continue
        process_name = _safe_inventory_text(" ".join(parts[:-2]), 255)
        high_resource_processes.add(process_name)
        unit_name = match_systemd(process_name)
        if unit_name:
            promote_systemd(unit_name, "HIGH_RESOURCE")
            continue
        key = ("process", process_name)
        item = key_items.setdefault(key, {
            "kind": "process",
            "name": process_name,
            "display_name": process_name,
            "status": "UNKNOWN",
            "importance": "KEY",
            "key_reasons": [],
            "ports": [],
            "health_summary": "无法可靠关联 systemd 服务",
        })
        if "HIGH_RESOURCE" not in item["key_reasons"]:
            item["key_reasons"].append("HIGH_RESOURCE")
        item["health_summary"] = (
            f"采样 CPU {cpu_percent:g}%，内存 {memory_percent:g}%"
        )

    status_order = {"DEGRADED": 0, "UNKNOWN": 1, "RUNNING": 2}
    kind_order = {"container": 0, "systemd": 1, "process": 2}
    items = sorted(
        key_items.values(),
        key=lambda item: (
            status_order[item["status"]],
            kind_order[item["kind"]],
            item["display_name"],
        ),
    )
    all_key_count = len(items)
    items = items[:100]
    detailed_systemd = {
        item["name"] for item in items if item["kind"] == "systemd"
    }
    other_services = [
        {"name": name, "display_name": description}
        for name, description in sorted(systemd.items())
        if name not in detailed_systemd
    ]
    remaining = max(0, 300 - len(items))
    all_other_count = len(other_services)
    other_services = other_services[:remaining]
    truncated = all_key_count > len(items) or all_other_count > len(other_services)
    return {
        "collection_status": "PARTIAL" if truncated else "COMPLETE",
        "totals": {
            "systemd_running": len(systemd),
            "containers_running": container_count,
            "listening_ports": len(listening_ports),
            "high_resource_processes": len(high_resource_processes),
        },
        "items": items,
        "other_running_services": other_services,
        "truncated": truncated,
    }


class InspectionStore:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def path(self, batch_id: str) -> Path:
        return self.directory / f"{_uuid(batch_id, 'batch_id')}.json"

    def load(self, batch_id: str) -> dict[str, Any]:
        try:
            value = json.loads(self.path(batch_id).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_NOT_FOUND", "inspection batch not found"
            ) from exc
        if not isinstance(value, dict) or value.get("batch_id") != batch_id:
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_CORRUPT", "inspection batch is invalid"
            )
        return value

    def save(self, value: Mapping[str, Any], *, increment_revision: bool = True) -> dict[str, Any]:
        batch_id = _uuid(value.get("batch_id"), "batch_id")
        with self._lock:
            target = self.path(batch_id)
            temporary = target.with_suffix(f".tmp.{os.getpid()}.{threading.get_ident()}")
            payload = dict(value)
            if increment_revision:
                payload["snapshot_revision"] = int(
                    payload.get("snapshot_revision") or 0
                ) + 1
            payload["updated_at"] = _utc_now()
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
            return payload

    def update(
        self,
        batch_id: str,
        mutate: Callable[[dict[str, Any]], None],
        *,
        increment_revision: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            value = self.load(batch_id)
            mutate(value)
            return self.save(value, increment_revision=increment_revision)

    def active(self) -> dict[str, Any] | None:
        for path in self.directory.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if value.get("status") in {"PREPARING", "RUNNING"}:
                return value
        return None

    def terminal_callback_failures(self) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for path in self.directory.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (
                value.get("status") in _TERMINAL_BATCH_STATUSES
                and isinstance(value.get("callback_delivery"), Mapping)
            ):
                values.append(value)
        return values

    def by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        for path in self.directory.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if value.get("idempotency_key") == key:
                return value
        return None

    def purge(self, retention_days: int, *, now: float | None = None) -> list[Path]:
        cutoff = (time.time() if now is None else now) - retention_days * 86400
        removed: list[Path] = []
        with self._lock:
            for path in self.directory.glob("*.json"):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    modified = path.stat().st_mtime
                except (OSError, ValueError):
                    continue
                if (
                    value.get("status")
                    in {"SUCCEEDED", "PARTIAL_SUCCESS", "FAILED", "CANCELLED"}
                    and modified < cutoff
                ):
                    try:
                        path.unlink()
                        removed.append(path)
                    except OSError:
                        continue
        return removed


class InspectionManager:
    def __init__(
        self,
        config: TrustedInspectionConfig,
        *,
        inventory: ManagedInventory,
        orchestrator: TrustedSessionOrchestrator,
        sender: Sender,
        token_env: str,
        proposal_ready: Callable[[str], None] | None = None,
        context_provider: Callable[[str], str] | None = None,
        kubernetes=None,
        callback_failure: Callable[[], None] | None = None,
    ):
        self.config = config
        self.inventory = inventory
        self.orchestrator = orchestrator
        self.sender = sender
        self.token_env = token_env
        self.proposal_ready = proposal_ready
        self.context_provider = context_provider
        self.kubernetes = kubernetes
        self.callback_failure = callback_failure
        self.store = InspectionStore(config.journal_dir)
        self._gate = threading.RLock()
        self._callback_replay_gate = threading.Lock()
        self._callback_replay_stop = threading.Event()
        self._callback_replay_thread: threading.Thread | None = None
        self._cancelled: set[str] = set()
        self.store.purge(config.retention_days)
        self.orchestrator.cleanup_transcripts()
        self._recover()

    def start_callback_retries(self) -> None:
        if self._callback_replay_thread is not None:
            return
        self._callback_replay_stop.clear()
        self._callback_replay_thread = threading.Thread(
            target=self._callback_replay_loop,
            name="trusted-inspection-callback-retry",
            daemon=True,
        )
        self._callback_replay_thread.start()

    def stop_callback_retries(self) -> None:
        self._callback_replay_stop.set()
        thread = self._callback_replay_thread
        if thread is not None:
            thread.join(timeout=_INSPECTION_CALLBACK_REPLAY_POLL_SEC + 1)
        self._callback_replay_thread = None

    def _callback_replay_loop(self) -> None:
        while not self._callback_replay_stop.is_set():
            self.replay_due_callbacks()
            self._callback_replay_stop.wait(_INSPECTION_CALLBACK_REPLAY_POLL_SEC)

    def targets(self) -> tuple[int, dict[str, Any]]:
        if not self.config.enabled:
            return 503, {"error_code": "TRUSTED_INSPECTION_DISABLED"}
        return 200, {"targets": self._public_targets()}

    def _public_targets(self) -> list[dict[str, Any]]:
        targets = [{**item, "target_type": "LINUX_HOST"} for item in self.inventory.public_targets()]
        if self.kubernetes is not None:
            for cluster in self.kubernetes._clusters().values():
                identity = self.kubernetes._identity(cluster)
                targets.append({
                    "logical_target_id": cluster.id,
                    "display_name": cluster.display_name,
                    "environment": cluster.environment,
                    "target_type": "KUBERNETES_CLUSTER",
                    "cluster_uid": identity["cluster_uid"],
                })
        return targets

    def create(self, body: bytes) -> tuple[int, dict[str, Any]]:
        try:
            request = json.loads(body or b"{}")
            required = {
                "batch_id", "tenant_id", "runner_provider_id", "target_scope",
                "logical_target_ids", "concurrency", "idempotency_key",
            }
            optional = {"target_options"}
            if not isinstance(request, dict) or not required.issubset(request) or set(request) - required - optional:
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_VALIDATION_FAILED",
                    "inspection request fields are incomplete or unknown",
                )
            batch_id = _uuid(request["batch_id"], "batch_id")
            _uuid(request["runner_provider_id"], "runner_provider_id")
            if request["target_scope"] not in {"all", "selected"}:
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_VALIDATION_FAILED", "invalid target_scope"
                )
            if (
                isinstance(request["concurrency"], bool)
                or not isinstance(request["concurrency"], int)
                or request["concurrency"] < 1
            ):
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_VALIDATION_FAILED",
                    "concurrency must be a positive integer",
                )
            public = self._public_targets()
            public_by_id = {row["logical_target_id"]: row for row in public}
            requested = request["logical_target_ids"]
            if not isinstance(requested, list) or any(
                not isinstance(item, str) for item in requested
            ):
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_VALIDATION_FAILED",
                    "logical_target_ids must be a string list",
                )
            target_ids = (
                list(public_by_id)
                if request["target_scope"] == "all"
                else list(dict.fromkeys(requested))
            )
            if not target_ids or any(item not in public_by_id for item in target_ids):
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_TARGET_INVALID",
                    "inspection contains an unmanaged target",
                )
            target_options = request.get("target_options") or {}
            if not isinstance(target_options, dict) or set(target_options) - set(target_ids):
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_VALIDATION_FAILED", "target_options contains an unmanaged target"
                )
            for target_id, options in target_options.items():
                if not isinstance(options, dict) or set(options) != {"namespaces"} or not isinstance(options["namespaces"], list) or any(not isinstance(item, str) or not item for item in options["namespaces"]):
                    raise TrustedSessionError(
                        "TRUSTED_INSPECTION_VALIDATION_FAILED", "Kubernetes target namespaces are invalid"
                    )
            fingerprint = hashlib.sha256(
                json.dumps(
                    {
                        key: request[key]
                        for key in (
                            "tenant_id", "runner_provider_id", "target_scope",
                            "logical_target_ids", "concurrency", "target_options",
                        )
                        if key in request
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            with self._gate:
                by_key = self.store.by_idempotency_key(
                    str(request["idempotency_key"])
                )
                if by_key is not None:
                    if by_key.get("request_fingerprint") != fingerprint:
                        return 409, {
                            "error_code": "TRUSTED_INSPECTION_IDEMPOTENCY_CONFLICT",
                            "active_batch_id": by_key["batch_id"],
                        }
                    return 202, self._public(by_key)
                try:
                    existing = self.store.load(batch_id)
                except TrustedSessionError:
                    existing = None
                if existing is not None:
                    if existing.get("request_fingerprint") != fingerprint:
                        return 409, {
                            "error_code": "TRUSTED_INSPECTION_IDEMPOTENCY_CONFLICT",
                            "active_batch_id": batch_id,
                        }
                    return 202, self._public(existing)
                active = self.store.active()
                if active is not None:
                    return 409, {
                        "error_code": "TRUSTED_INSPECTION_BATCH_ACTIVE",
                        "active_batch_id": active["batch_id"],
                    }
                now = _utc_now()
                fingerprint_value = config_fingerprint(self.orchestrator.config)
                batch = {
                    "batch_id": batch_id,
                    "tenant_id": str(request["tenant_id"]),
                    "runner_provider_id": request["runner_provider_id"],
                    "runner_instance_id": self.orchestrator.config.runner_instance_id,
                    "idempotency_key": str(request["idempotency_key"]),
                    "request_fingerprint": fingerprint,
                    "status": "PREPARING",
                    "failure": None,
                    "requested_concurrency": request["concurrency"],
                    "effective_concurrency": min(request["concurrency"], len(target_ids)),
                    "created_at": now,
                    "started_at": None,
                    "finished_at": None,
                    "targets": [
                        {
                            **public_by_id[target_id],
                            "inspection_scope": target_options.get(target_id, {"namespaces": []}),
                            "session_id": str(uuid.uuid4()),
                            "claude_session_id": None,
                            "config_fingerprint": fingerprint_value,
                            "runner_config_version": (
                                self.orchestrator.config.runner_config_version or None
                            ),
                            "status": "QUEUED",
                            "report": None,
                            "failure": None,
                            "terminal_reason": None,
                            "started_at": None,
                            "finished_at": None,
                        }
                        for target_id in target_ids
                    ],
                }
                batch = self.store.save(batch)
                threading.Thread(
                    target=self._run_batch,
                    args=(batch_id,),
                    name=f"inspection-batch-{batch_id}",
                    daemon=True,
                ).start()
                return 202, self._public(batch)
        except TrustedSessionError as exc:
            return 422, {"error_code": exc.code, "message": str(exc)}
        except (TypeError, ValueError, json.JSONDecodeError):
            return 400, {"error_code": "TRUSTED_INSPECTION_BAD_JSON"}

    def get(self, batch_id: str) -> tuple[int, dict[str, Any]]:
        try:
            return 200, self._public(self.store.load(batch_id))
        except TrustedSessionError as exc:
            return 404, {"error_code": exc.code, "message": str(exc)}

    def cancel(self, batch_id: str) -> tuple[int, dict[str, Any]]:
        try:
            with self._gate:
                batch = self.store.load(batch_id)
                if batch["status"] in {"SUCCEEDED", "PARTIAL_SUCCESS", "FAILED", "CANCELLED"}:
                    return 200, self._public(batch)
                self._cancelled.add(batch_id)
                for target in batch["targets"]:
                    if target["status"] == "DIAGNOSING":
                        self.orchestrator.cancel(target["session_id"])
                batch = self.store.update(batch_id, self._mark_cancelled)
            self._callback(batch)
            return 202, self._public(batch)
        except TrustedSessionError as exc:
            return 404, {"error_code": exc.code, "message": str(exc)}

    def generate_proposal(self, session_id: str) -> tuple[int, dict[str, Any]]:
        try:
            batch, target = self._find_target(session_id)
            if target.get("target_type") == "KUBERNETES_CLUSTER":
                return 409, {"error_code": "KUBERNETES_REPAIR_NOT_SUPPORTED"}
            if target["status"] not in {"WARNING", "CRITICAL"}:
                return 409, {"error_code": "INSPECTION_TARGET_NOT_ACTIONABLE"}
            metadata = self.orchestrator.journal.load(session_id)
            if metadata.get("status") == "PENDING_APPROVAL":
                if (
                    metadata.get("callback_proposal_attempted")
                    and metadata.get("callback_proposal_last_ok") is False
                    and self.proposal_ready is not None
                ):
                    self.orchestrator.journal.update(
                        session_id,
                        callback_proposal_attempted=False,
                    )
                    self.proposal_ready(session_id)
                return 202, {
                    "session_id": session_id,
                    "claude_session_id": metadata["claude_session_id"],
                    "status": "PENDING_APPROVAL",
                }
            if metadata.get("status") != "INSPECTION_COMPLETED":
                return 409, {"error_code": "INSPECTION_PROPOSAL_CONFLICT"}
            self.orchestrator.journal.update(session_id, status="PROPOSAL_GENERATING")
            threading.Thread(
                target=self._generate_proposal,
                args=(batch["batch_id"], session_id),
                name=f"inspection-proposal-{session_id}",
                daemon=True,
            ).start()
            return 202, {
                "session_id": session_id,
                "claude_session_id": metadata["claude_session_id"],
                "status": "PROPOSAL_GENERATING",
            }
        except TrustedSessionError as exc:
            return 404, {"error_code": exc.code, "message": str(exc)}

    def health(self) -> dict[str, Any]:
        active = self.store.active()
        if active is None:
            return {
                "inspection_active_batch_id": None,
                "inspection_active": 0,
                "inspection_queued": 0,
                "inspection_requested_concurrency": 0,
                "inspection_effective_concurrency": 0,
            }
        return {
            "inspection_active_batch_id": active["batch_id"],
            "inspection_active": sum(
                item["status"] == "DIAGNOSING" for item in active["targets"]
            ),
            "inspection_queued": sum(
                item["status"] == "QUEUED" for item in active["targets"]
            ),
            "inspection_requested_concurrency": active["requested_concurrency"],
            "inspection_effective_concurrency": active["effective_concurrency"],
        }

    def _collect_service_inventory(
        self,
        profile: Mapping[str, Any],
        *,
        remaining_command_budget: int,
    ) -> dict[str, Any]:
        if remaining_command_budget < 1:
            return _unavailable_service_inventory()
        adapter = self.orchestrator.adapter
        env = _minimal_child_env(
            adapter.base_env,
            adapter.session_store_dir,
            profile,
        )
        try:
            completed = subprocess.run(
                ["./bin/target-exec", _SERVICE_INVENTORY_COMMAND],
                cwd=adapter.project_dir,
                env=env,
                capture_output=True,
                text=True,
                shell=False,
                timeout=int(profile["command_timeout_sec"]) + 5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return _unavailable_service_inventory()
        if completed.returncode != 0 or "__AIOPS_SYSTEMD__" not in completed.stdout:
            return _unavailable_service_inventory()
        return _parse_service_inventory(completed.stdout)

    def _persist_inspection_event(
        self,
        session_id: str,
        event: Mapping[str, Any],
    ) -> None:
        # The terminal report is sanitized and validated below before it enters
        # the journal metadata. Its raw model form belongs only in the encrypted
        # transcript.
        if event.get("event_type") == "inspection_report_created":
            return
        self.orchestrator._persist_live_event(session_id, dict(event))

    def _run_batch(self, batch_id: str) -> None:
        batch = self.store.update(
            batch_id,
            lambda value: value.update(status="RUNNING", started_at=value["started_at"] or _utc_now()),
        )
        self._callback(batch)
        targets = [item["session_id"] for item in batch["targets"] if item["status"] == "QUEUED"]
        with ThreadPoolExecutor(
            max_workers=batch["effective_concurrency"],
            thread_name_prefix="trusted-inspection",
        ) as pool:
            futures = {pool.submit(self._inspect_target, batch_id, session_id): session_id
                       for session_id in targets}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass
        batch = self.store.update(batch_id, self._finish_batch)
        self._callback(batch)

    def _inspect_target(self, batch_id: str, session_id: str) -> None:
        with self._gate:
            if batch_id in self._cancelled:
                return
            batch, target = self._find_target(session_id)
            target_id = target["logical_target_id"]
            if target.get("target_type") == "KUBERNETES_CLUSTER":
                self._inspect_kubernetes_target(batch_id, session_id, batch, target)
                return
            try:
                profile = self.inventory.ssh_profile(target_id)
            except Exception as exc:
                failure = _public_inspection_failure(exc)
                now = _utc_now()
                self._update_target(
                    batch_id,
                    session_id,
                    status=_failure_target_status(failure),
                    failure=failure,
                    terminal_reason=failure["code"],
                    started_at=now,
                    finished_at=now,
                )
                self._callback(self.store.load(batch_id))
                return
            claude_session_id = str(uuid.uuid4())
            started = _utc_now()
            self._update_target(
                batch_id,
                session_id,
                status="DIAGNOSING",
                claude_session_id=claude_session_id,
                started_at=started,
                failure=None,
                terminal_reason=None,
            )
            metadata = {
                "session_id": session_id,
                "claude_session_id": claude_session_id,
                "logical_target_id": target_id,
                "status": "DIAGNOSING",
                "session_kind": "inspection",
                "batch_id": batch_id,
                "tenant_id": batch["tenant_id"],
                # Existing repair callbacks require a UUID run binding. For an
                # inspection-sourced repair the session UUID is the synthetic
                # source binding; AIOps independently binds inspection_target_id.
                "run_id": session_id,
                "repair_id": None,
                "runner_provider_id": batch["runner_provider_id"],
                "runner_instance_id": self.orchestrator.config.runner_instance_id,
                "config_fingerprint": config_fingerprint(self.orchestrator.config),
                "runner_config_version": self.orchestrator.config.runner_config_version or None,
                "os_user": self.orchestrator.os_user or getpass.getuser(),
                "cwd": os.path.abspath(self.orchestrator.config.project_dir),
                "session_store_dir": os.path.abspath(
                    self.orchestrator.config.session_store_dir
                ),
                "config_path": os.path.abspath(
                    self.orchestrator.config.runner_config_path
                ) if self.orchestrator.config.runner_config_path else "",
                "pid": None,
                "remote_command_seen": False,
            }
            try:
                self.orchestrator.journal.create(metadata)
                self.orchestrator.journal.append_event(
                    session_id,
                    {
                        "event_type": "session_created",
                        "actor": {"type": "runner", "id": "runner"},
                    },
                )
            except Exception as exc:
                failure = _public_inspection_failure(exc)
                self._update_target(
                    batch_id,
                    session_id,
                    status=_failure_target_status(failure),
                    failure=failure,
                    terminal_reason=failure["code"],
                    finished_at=_utc_now(),
                )
                self._callback(self.store.load(batch_id))
                return
        self._callback(self.store.load(batch_id))

        try:
            command_budget_exhausted = False
            all_events: list[dict[str, Any]] = []
            try:
                result = self.orchestrator.adapter.run(
                    session_id=session_id,
                    claude_session_id=claude_session_id,
                    prompt=self._inspection_prompt(target_id) + (self.context_provider(target_id) if self.context_provider else ""),
                    resume=False,
                    event_sink=lambda event: self._persist_inspection_event(
                        session_id, event
                    ),
                    timeout_sec=self.config.diagnosis_timeout_sec,
                    command_budget=self.config.diagnosis_command_budget,
                    target_ssh=profile,
                    spawn_guard=lambda: self.orchestrator._lifecycle_gate,
                    pre_spawn=lambda: self.orchestrator._pre_spawn(session_id, "DIAGNOSING"),
                    phase="inspecting",
                    skill_name="trusted-inspection-session",
                    output_schema=json.dumps(
                        CLAUDE_INSPECTION_SCHEMA, separators=(",", ":")
                    ),
                )
                all_events = list(result.events)
            except TrustedSessionError as exc:
                if not _is_command_budget_exhausted(exc):
                    raise
                command_budget_exhausted = True
                self.orchestrator.journal.append_event(
                    session_id,
                    {
                        "event_type": "inspection_command_budget_reached",
                        "actor": {"type": "runner", "id": "runner"},
                        "metadata": {
                            "command_budget": self.config.diagnosis_command_budget,
                        },
                    },
                )
            reports = [
                event["inspection_report"]
                for event in all_events
                if event.get("event_type") == "inspection_report_created"
            ]
            report = (
                _validated_model_report(reports[0])
                if len(reports) == 1
                else None
            )
            if report is None:
                try:
                    retry_result = self.orchestrator.adapter.run(
                        session_id=session_id,
                        claude_session_id=claude_session_id,
                        prompt=self._inspection_format_retry_prompt(
                            command_budget_exhausted=command_budget_exhausted
                        ),
                        resume=True,
                        event_sink=lambda event: self._persist_inspection_event(
                            session_id, event
                        ),
                        timeout_sec=_INSPECTION_FORMAT_RETRY_TIMEOUT_SEC,
                        command_budget=0,
                        target_ssh=None,
                        spawn_guard=lambda: self.orchestrator._lifecycle_gate,
                        pre_spawn=lambda: self.orchestrator._pre_spawn(
                            session_id, "DIAGNOSING"
                        ),
                        phase="inspecting",
                        skill_name="trusted-inspection-session",
                        output_schema=json.dumps(
                            CLAUDE_INSPECTION_SCHEMA, separators=(",", ":")
                        ),
                        allow_tools=False,
                    )
                    all_events.extend(retry_result.events)
                    reports = [
                        event["inspection_report"]
                        for event in retry_result.events
                        if event.get("event_type") == "inspection_report_created"
                    ]
                    report = (
                        _validated_model_report(reports[0])
                        if len(reports) == 1
                        else None
                    )
                except Exception:
                    if batch_id in self._cancelled:
                        raise
                    report = None
            if report is None:
                report = _unknown_fallback_report()
                _normalize_report_status(report)
                _validate_report_semantics(report)
            if command_budget_exhausted:
                _mark_command_budget_limited(report)
            report["schema_version"] = 2
            snapshot = report.setdefault("resource_snapshot", {})
            for metric in (
                "cpu_usage_percent",
                "load_per_core",
                "memory_available_percent",
                "max_disk_usage_percent",
                "max_inode_usage_percent",
            ):
                snapshot.setdefault(metric, None)
            command_count = (
                self.config.diagnosis_command_budget
                if command_budget_exhausted
                else sum(
                    event.get("event_type") == "command_started"
                    for event in all_events
                )
            )
            report["service_inventory"] = self._collect_service_inventory(
                profile,
                remaining_command_budget=max(
                    0, self.config.diagnosis_command_budget - command_count
                ),
            )
            if list(_REPORT_VALIDATOR.iter_errors(report)):
                raise TrustedSessionError(
                    "TRUSTED_INSPECTION_REPORT_INVALID",
                    "runner-augmented inspection report is invalid",
                )
            _validate_report_semantics(report)
            status = str(report["overall_status"])
            self.orchestrator.journal.update(
                session_id, status="INSPECTION_COMPLETED", inspection_report=report
            )
            self._update_target(
                batch_id,
                session_id,
                status=status,
                report=report,
                finished_at=_utc_now(),
                failure=None,
                terminal_reason=None,
            )
        except Exception as exc:
            failure = _public_inspection_failure(exc)
            code = failure["code"]
            status = _failure_target_status(failure)
            try:
                self.orchestrator.journal.update(
                    session_id, status="DIAGNOSIS_ONLY", terminal_reason=str(code)
                )
            except Exception:
                pass
            self._update_target(
                batch_id,
                session_id,
                status=status,
                failure=failure,
                terminal_reason=str(code),
                finished_at=_utc_now(),
            )
        self._callback(self.store.load(batch_id))

    def _inspect_kubernetes_target(
        self, batch_id: str, session_id: str,
        batch: Mapping[str, Any], target: Mapping[str, Any],
    ) -> None:
        """Run deterministic v2 checks, then bounded no-tools interpretation."""
        target_id = str(target["logical_target_id"])
        namespaces = list((target.get("inspection_scope") or {}).get("namespaces") or [])
        claude_session_id = str(uuid.uuid4())
        self._update_target(
            batch_id, session_id, status="DIAGNOSING",
            claude_session_id=claude_session_id, started_at=_utc_now(),
            failure=None, terminal_reason=None,
        )
        self._callback(self.store.load(batch_id))
        try:
            evidence = self.kubernetes.deterministic_health(target_id, namespaces)
            report = {**evidence, "target_type": "KUBERNETES_CLUSTER"}
            if report.get("schema_version") == "kubernetes-inspection/v1":
                report.update({
                    "summary": (
                        f"检查 {evidence['checked_assets']} 个资源，"
                        f"发现 {len(evidence['findings'])} 项需关注结果。"
                    ),
                    "interpretation_status": "UNAVAILABLE",
                    "model_interpretation": None,
                })
            self.orchestrator.journal.create({
                "session_id": session_id, "claude_session_id": claude_session_id,
                "logical_target_id": target_id, "status": "DIAGNOSING",
                "session_kind": "inspection", "target_type": "KUBERNETES_CLUSTER",
                "batch_id": batch_id, "tenant_id": batch["tenant_id"],
                "run_id": session_id, "repair_id": None,
                "runner_provider_id": batch["runner_provider_id"],
                "runner_instance_id": self.orchestrator.config.runner_instance_id,
                "config_fingerprint": config_fingerprint(self.orchestrator.config),
                "runner_config_version": self.orchestrator.config.runner_config_version or None,
                "os_user": self.orchestrator.os_user or getpass.getuser(),
                "cwd": os.path.abspath(self.orchestrator.config.project_dir),
                "session_store_dir": os.path.abspath(self.orchestrator.config.session_store_dir),
                "config_path": os.path.abspath(self.orchestrator.config.runner_config_path) if self.orchestrator.config.runner_config_path else "",
                "pid": None, "remote_command_seen": False,
            })
            if report.get("schema_version") == "kubernetes-inspection/v2":
                model_evidence = {
                    "overall_status": report.get("overall_status"),
                    "deterministic_summary": report.get("summary"),
                    "snapshot": report.get("snapshot"),
                    "coverage": report.get("coverage"),
                    "findings": list(report.get("findings") or [])[:50],
                    "input_truncated": len(report.get("findings") or []) > 50,
                }
                try:
                    def run_interpretation(*, resume: bool, prompt: str):
                        return self.orchestrator.adapter.run(
                            session_id=session_id,
                            claude_session_id=claude_session_id,
                            prompt=prompt,
                            resume=resume,
                            event_sink=lambda event: self._persist_inspection_event(
                                session_id, event
                            ),
                            timeout_sec=self.config.diagnosis_timeout_sec,
                            command_budget=0,
                            target_ssh=None,
                            spawn_guard=lambda: self.orchestrator._lifecycle_gate,
                            pre_spawn=lambda: self.orchestrator._pre_spawn(
                                session_id, "DIAGNOSING"
                            ),
                            phase="inspecting",
                            skill_name="kubernetes-inspection-session",
                            output_schema=json.dumps(
                                KUBERNETES_INTERPRETATION_SCHEMA,
                                separators=(",", ":"),
                            ),
                            allow_tools=False,
                            append_skill_prompt=True,
                        )

                    result = run_interpretation(
                        resume=False,
                        prompt=(
                            "解读以下 Runner 生成的确定性、脱敏 Kubernetes v2 证据。"
                            "仅返回 JSON Schema 要求的结构化结果。\n"
                            + json.dumps(
                                model_evidence,
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                        ),
                    )

                    def interpretation_from(events: Any) -> dict[str, Any] | None:
                        candidates = [
                            event.get("inspection_report")
                            for event in events
                            if event.get("event_type") == "inspection_report_created"
                        ]
                        return (
                            _validated_kubernetes_interpretation(
                                candidates[0], model_evidence
                            )
                            if len(candidates) == 1
                            else None
                        )

                    interpretation = interpretation_from(result.events)
                    if interpretation is None:
                        retry = run_interpretation(
                            resume=True,
                            prompt=(
                                "仅修正上一轮输出格式。不得调用工具、不得添加新事实，"
                                "所有 finding_id 必须来自上一轮证据，最多保留三个优先项，"
                                "只返回 JSON Schema 要求的结构化结果。"
                            ),
                        )
                        interpretation = interpretation_from(retry.events)
                    if interpretation is None:
                        raise TrustedSessionError(
                            "TRUSTED_INSPECTION_REPORT_INVALID",
                            "Kubernetes interpretation is invalid",
                        )
                    report["interpretation"] = {
                        "status": "AVAILABLE",
                        **interpretation,
                    }
                except Exception as exc:
                    failure = _public_inspection_failure(exc)
                    report["completion_status"] = "PARTIAL"
                    report["interpretation"] = {
                        "status": "UNAVAILABLE",
                        "failure_code": failure["code"],
                        "priorities": [],
                        "limitations": ["AI 解读未生成，当前报告仅包含确定性规则结论。"],
                    }
                    if failure.get("http_status") is not None:
                        report["interpretation"]["failure_http_status"] = failure[
                            "http_status"
                        ]
            else:
                legacy_schema = {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["overall_status", "summary", "findings"],
                    "properties": {
                        "overall_status": {"enum": ["HEALTHY", "WARNING", "CRITICAL"]},
                        "summary": {"type": "string", "maxLength": 1200},
                        "findings": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["rule_id", "explanation", "recommendation"],
                                "properties": {
                                    "rule_id": {"type": "string", "maxLength": 128},
                                    "explanation": {"type": "string", "maxLength": 1200},
                                    "recommendation": {"type": "string", "maxLength": 1200},
                                },
                            },
                        },
                    },
                }
                try:
                    result = self.orchestrator.adapter.run(
                        session_id=session_id,
                        claude_session_id=claude_session_id,
                        prompt=(
                            "只解读以下 Runner 确定性、脱敏 Kubernetes 证据；"
                            "不得生成命令或修复步骤。\n"
                            + json.dumps(
                                evidence, ensure_ascii=False, separators=(",", ":")
                            )
                        ),
                        resume=False,
                        event_sink=lambda event: self._persist_inspection_event(
                            session_id, event
                        ),
                        timeout_sec=self.config.diagnosis_timeout_sec,
                        command_budget=0,
                        target_ssh=None,
                        spawn_guard=lambda: self.orchestrator._lifecycle_gate,
                        pre_spawn=lambda: self.orchestrator._pre_spawn(
                            session_id, "DIAGNOSING"
                        ),
                        phase="inspecting",
                        skill_name="kubernetes-inspection-session",
                        output_schema=json.dumps(legacy_schema, separators=(",", ":")),
                        allow_tools=False,
                    )
                    candidates = [
                        event.get("inspection_report")
                        for event in result.events
                        if event.get("event_type") == "inspection_report_created"
                    ]
                    if (
                        len(candidates) == 1
                        and isinstance(candidates[0], dict)
                        and not _REPAIR_COMMAND_PATTERN.search(
                            json.dumps(candidates[0], ensure_ascii=False)
                        )
                    ):
                        report["interpretation_status"] = "AVAILABLE"
                        report["model_interpretation"] = candidates[0]
                        report["summary"] = str(
                            candidates[0].get("summary") or report["summary"]
                        )[:1200]
                except Exception:
                    # v1 remains backward compatible. v2 records safe reasons.
                    pass
            status = str(evidence["overall_status"])
            self.orchestrator.journal.update(session_id, status="INSPECTION_COMPLETED", inspection_report=report)
            self._update_target(batch_id, session_id, status=status, report=report, finished_at=_utc_now(), failure=None, terminal_reason=None)
        except Exception as exc:
            failure = _public_inspection_failure(exc)
            self._update_target(batch_id, session_id, status=_failure_target_status(failure), failure=failure, terminal_reason=failure["code"], finished_at=_utc_now())
        self._callback(self.store.load(batch_id))

    def _generate_proposal(self, batch_id: str, session_id: str) -> None:
        try:
            metadata = self.orchestrator.journal.load(session_id)
            target_id = str(metadata["logical_target_id"])
            profile = self.inventory.ssh_profile(target_id)
            result = self.orchestrator.adapter.run(
                session_id=session_id,
                claude_session_id=str(metadata["claude_session_id"]),
                prompt=self._proposal_prompt(session_id, metadata.get("inspection_report")),
                resume=True,
                event_sink=lambda event: self.orchestrator._persist_live_event(session_id, event),
                timeout_sec=self.orchestrator.config.diagnosis_timeout_sec,
                command_budget=self.orchestrator.config.diagnosis_command_budget,
                target_ssh=profile,
                spawn_guard=lambda: self.orchestrator._lifecycle_gate,
                pre_spawn=lambda: self.orchestrator._pre_spawn(session_id, "PROPOSAL_GENERATING"),
                phase="proposing",
                skill_name="trusted-inspection-session",
                output_schema=diagnosis_draft_schema_json(),
            )
            drafts = [
                event["proposal_draft"] for event in result.events
                if event.get("event_type") == "proposal_draft_created"
            ]
            if len(drafts) != 1:
                raise TrustedSessionError(
                    "TRUSTED_PROPOSAL_MISSING", "proposal generation returned no proposal"
                )
            proposal = self.orchestrator._bind_generated_proposal(
                drafts[0], metadata,
                command_timeout_seconds=int(profile["command_timeout_sec"]),
            )
            proposal_hash = self.orchestrator.proposal_validator(proposal)
            if not isinstance(proposal_hash, str):
                proposal_hash = proposal.get("proposal_hash")
            fingerprint = self.orchestrator.journal.save_proposal(session_id, proposal)
            expires = datetime.now(timezone.utc) + timedelta(
                seconds=min(self.orchestrator.config.approval_ttl_sec, 1800)
            )
            self.orchestrator.journal.update(
                session_id,
                status="PENDING_APPROVAL",
                proposal_revision=proposal["proposal_revision"],
                proposal_hash_algorithm_id=proposal["proposal_hash_algorithm_id"],
                proposal_hash=proposal_hash or proposal.get("proposal_hash"),
                proposal_content_fingerprint=fingerprint,
                approval_expires_at=expires.isoformat().replace("+00:00", "Z"),
            )
            self.orchestrator.journal.append_event(
                session_id, {"event_type": "proposal_created", "actor": {"type": "claude", "id": "claude"}}
            )
            if self.proposal_ready is not None:
                self.proposal_ready(session_id)
        except Exception as exc:
            self.orchestrator.journal.update(
                session_id, status="MANUAL_INTERVENTION",
                terminal_reason=str(getattr(exc, "code", type(exc).__name__)),
            )
            if self.proposal_ready is not None:
                self.proposal_ready(session_id)

    def _find_target(self, session_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        for path in self.store.directory.glob("*.json"):
            try:
                batch = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for target in batch.get("targets", []):
                if target.get("session_id") == session_id:
                    return batch, target
        raise TrustedSessionError(
            "TRUSTED_INSPECTION_TARGET_NOT_FOUND", "inspection target not found"
        )

    def _update_target(self, batch_id: str, session_id: str, **changes: Any) -> None:
        def mutate(value: dict[str, Any]) -> None:
            for target in value["targets"]:
                if target["session_id"] == session_id:
                    # Cancellation is terminal for the batch target. A Claude
                    # process that exits concurrently must not overwrite it.
                    if (
                        target["status"] == "CANCELLED"
                        and changes.get("status") != "CANCELLED"
                    ):
                        return
                    target.update(changes)
                    return
            raise TrustedSessionError(
                "TRUSTED_INSPECTION_TARGET_NOT_FOUND", "inspection target not found"
            )
        self.store.update(batch_id, mutate)

    def _finish_batch(self, value: dict[str, Any]) -> None:
        if value["status"] == "CANCELLED":
            return
        statuses = {item["status"] for item in value["targets"]}
        valid = sum(item["status"] in _VALID_REPORT for item in value["targets"])
        if statuses <= _VALID_REPORT:
            status = "SUCCEEDED"
        elif valid:
            status = "PARTIAL_SUCCESS"
        else:
            status = "FAILED"
        failures = [
            item.get("failure")
            for item in value["targets"]
            if isinstance(item.get("failure"), dict)
        ]
        common_failure = (
            failures[0]
            if status == "FAILED"
            and len(failures) == len(value["targets"])
            and all(item == failures[0] for item in failures)
            else None
        )
        value.update(
            status=status,
            failure=common_failure,
            finished_at=_utc_now(),
        )

    def _mark_cancelled(self, value: dict[str, Any]) -> None:
        for target in value["targets"]:
            if target["status"] not in _TERMINAL:
                target.update(
                    status="CANCELLED",
                    failure=None,
                    terminal_reason=None,
                    finished_at=_utc_now(),
                )
        value.update(status="CANCELLED", failure=None, finished_at=_utc_now())

    def _public(self, batch: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(batch)
        value.pop("request_fingerprint", None)
        # Local callback delivery diagnostics are deliberately never included
        # in the untrusted callback envelope.
        value.pop("callback_delivery", None)
        counts = {status.lower(): 0 for status in _TERMINAL | {"QUEUED", "DIAGNOSING"}}
        for target in value["targets"]:
            counts[target["status"].lower()] = counts.get(target["status"].lower(), 0) + 1
        value["counts"] = counts
        return value

    def _callback(self, batch: Mapping[str, Any]) -> bool:
        batch_id = str(batch["batch_id"])
        snapshot_revision = int(batch.get("snapshot_revision") or 0)
        if not self.config.aiops_url:
            self._record_callback_failure(
                batch_id, snapshot_revision, attempts=0, status_code=0,
                error="callback_url_unavailable", retryable=False,
            )
            return False
        token = os.environ.get(self.token_env, "")
        if not token:
            self._record_callback_failure(
                batch_id, snapshot_revision, attempts=0, status_code=0,
                error="callback_token_unavailable", retryable=False,
            )
            return False
        body = json.dumps(
            {
                "kind": "inspection_batch_snapshot",
                "schema_version": "1.1",
                **self._public(batch),
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()
        status_code = 0
        error = ""
        attempts = 0
        for attempt in range(1, _INSPECTION_CALLBACK_MAX_ATTEMPTS + 1):
            attempts = attempt
            status_code, error = self.sender.post(
                self.config.aiops_url,
                body,
                {"Content-Type": "application/json", "X-API-KEY": token},
                timeout=10,
            )
            if not error and 200 <= status_code < 300:
                self._clear_callback_failure(batch_id, snapshot_revision)
                return True
            if not self._callback_failure_retriable(status_code, error):
                break
            if attempt < _INSPECTION_CALLBACK_MAX_ATTEMPTS:
                time.sleep(_INSPECTION_CALLBACK_RETRY_DELAY_SEC * attempt)

        self._record_callback_failure(
            batch_id,
            snapshot_revision,
            attempts=attempts,
            status_code=status_code,
            error=error or "callback_rejected",
            retryable=self._callback_failure_retriable(status_code, error),
        )
        if self.callback_failure is not None:
            self.callback_failure()
        return False

    @staticmethod
    def _callback_failure_retriable(status_code: int, error: str) -> bool:
        if status_code:
            return status_code in {408, 429} or status_code >= 500
        return bool(error)

    @staticmethod
    def _callback_retry_delay(retry_count: int) -> int:
        exponent = max(retry_count - 1, 0)
        return min(
            _INSPECTION_CALLBACK_RETRY_INITIAL_DELAY_SEC * (2 ** exponent),
            _INSPECTION_CALLBACK_RETRY_MAX_DELAY_SEC,
        )

    def _record_callback_failure(
        self,
        batch_id: str,
        snapshot_revision: int,
        *,
        attempts: int,
        status_code: int,
        error: str,
        retryable: bool,
    ) -> None:
        """Persist only bounded delivery metadata; never persist callback bodies or tokens."""
        try:
            def mutate(value: dict[str, Any]) -> None:
                if int(value.get("snapshot_revision") or 0) != snapshot_revision:
                    return
                previous = value.get("callback_delivery")
                same_snapshot = (
                    isinstance(previous, Mapping)
                    and int(previous.get("snapshot_revision") or -1) == snapshot_revision
                )
                retry_count = int(previous.get("retry_count") or 0) + 1 if same_snapshot else 1
                total_attempts = int(previous.get("attempts") or 0) + attempts if same_snapshot else attempts
                delivery = {
                    "status": "RETRY_PENDING" if retryable else "FAILED",
                    "retryable": retryable,
                    "retry_count": retry_count,
                    "attempts": total_attempts,
                    "snapshot_revision": snapshot_revision,
                    "http_status": status_code or None,
                    "error": error[:128],
                }
                if retryable:
                    delivery["next_retry_at"] = time.time() + self._callback_retry_delay(retry_count)
                value["callback_delivery"] = delivery

            self.store.update(batch_id, mutate, increment_revision=False)
        except Exception:
            pass

    def _clear_callback_failure(self, batch_id: str, snapshot_revision: int) -> None:
        try:
            def mutate(value: dict[str, Any]) -> None:
                if int(value.get("snapshot_revision") or 0) == snapshot_revision:
                    value.pop("callback_delivery", None)

            self.store.update(batch_id, mutate, increment_revision=False)
        except Exception:
            pass

    def replay_due_callbacks(self, *, now: float | None = None) -> int:
        """Replay durable terminal snapshots without creating a new inspection."""
        if not self._callback_replay_gate.acquire(blocking=False):
            return 0
        try:
            current_time = time.time() if now is None else now
            delivered = 0
            for batch in self.store.terminal_callback_failures():
                delivery = batch.get("callback_delivery")
                if not isinstance(delivery, Mapping):
                    continue
                retryable = delivery.get("retryable")
                if retryable is None:
                    retryable = self._callback_failure_retriable(
                        int(delivery.get("http_status") or 0), str(delivery.get("error") or ""),
                    )
                if not retryable or float(delivery.get("next_retry_at") or 0) > current_time:
                    continue
                if self._callback(batch):
                    delivered += 1
            return delivered
        finally:
            self._callback_replay_gate.release()

    def _recover(self) -> None:
        active = self.store.active()
        if active is None:
            return
        for target in active["targets"]:
            if target["status"] == "DIAGNOSING":
                target.update(
                    status="UNKNOWN",
                    failure={"code": "RUNNER_RESTARTED_DURING_INSPECTION"},
                    terminal_reason="RUNNER_RESTARTED_DURING_INSPECTION",
                    finished_at=_utc_now(),
                )
        self.store.save(active)
        threading.Thread(
            target=self._run_batch, args=(active["batch_id"],), daemon=True
        ).start()

    @staticmethod
    def _inspection_prompt(target_id: str) -> str:
        return (
            "调用 trusted-inspection-session skill，对唯一目标 "
            f"{target_id} 执行完整手动巡检。必须先完成固定基线，再只针对异常追加只读诊断；"
            "最多调用 20 次 ./bin/target-exec。不得生成修复命令。"
            "服务运行清单由 runner 另行做一次确定性只读采集，"
            "不得为了清单逐服务或逐端口追加查询，也不得输出 service_inventory。"
            "最终只输出符合 runner 所给 JSON Schema 的巡检报告。"
        )

    @staticmethod
    def _inspection_format_retry_prompt(*, command_budget_exhausted: bool = False) -> str:
        prefix = (
            "巡检已达到命令预算上限。" if command_budget_exhausted else "仅修正上一轮巡检结果的输出格式。"
        )
        return (
            prefix
            + "不得调用任何工具，不得重新巡检，"
            "不得补充或猜测证据；只根据本会话已有证据，通过 StructuredOutput "
            "返回符合 runner 所给 JSON Schema 的巡检报告。证据不足的基线必须标记 UNKNOWN。"
        )

    @staticmethod
    def _proposal_prompt(session_id: str, report: Any) -> str:
        return json.dumps(
            {
                "action": "generate_repair_proposal_from_inspection",
                "session_id": session_id,
                "inspection_report": report,
                "requirements": [
                    "resume this exact Claude session",
                    "collect additional read-only evidence only when necessary",
                    "return the four-field repair proposal structured output",
                    "do not execute any repair command before approval",
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
