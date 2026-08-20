"""Map raw provider alerts into the runner alert contract before prompting Claude."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

CATEGORIES = ("cpu_high", "mem_high", "disk_full", "service_down", "http_5xx", "other")
REQUIRED_ALERT_KEYS = {
    "run_id",
    "alert_id",
    "tenant_id",
    "logical_target_id",
    "category",
    "severity",
    "service",
    "timestamp",
    "summary",
    "labels",
    "annotations",
    "incident",
}

_CATEGORY_HINTS = (
    ("cpu_high", ("cpu", "cpuutilization", "load average", "loadavg")),
    ("mem_high", ("mem", "memory", "memoryutilization", "oom", "swap")),
    ("disk_full", (
        "disk", "diskusageutilization", "diskfull", "filesystem", "inode",
        "no space", "磁盘", "存储/磁盘使用率",
    )),
    ("service_down", ("down", "not running", "unreachable", "crashloop", "failed to start")),
    ("http_5xx", ("5xx", "http_5", "500", "502", "503", "504", "internal server error")),
)


def normalize_alert(alert: object) -> object:
    """Return a canonical alert dict when possible; non-dicts pass through for validation errors.

    The runner accepts both the frozen AIOps->Runner contract and raw provider alerts enriched
    with control fields from AIOps. Provider payload fields remain untrusted data.
    """
    if not isinstance(alert, Mapping):
        return alert
    if REQUIRED_ALERT_KEYS.issubset(alert.keys()):
        return dict(alert)

    labels = _dict_or_empty(alert.get("labels"))
    annotations = _build_annotations(alert)
    labels.pop("tenant_id", None)
    annotations.pop("tenant_id", None)

    return {
        "run_id": str(_first_non_empty(alert, "run_id")),
        "alert_id": str(_first_non_empty(alert, "alert_id", "id", "fingerprint", "alert_hash")),
        "tenant_id": str(_first_non_empty(alert, "tenant_id")),
        "logical_target_id": str(
            _first_non_empty(alert, "logical_target_id")
            or labels.get("logical_target_id")
            or labels.get("instance_name")
            or labels.get("instance")
            or ""
        ),
        "category": _category(alert, labels, annotations),
        "severity": str(_first_non_empty(alert, "severity")),
        "service": str(_first_non_empty(alert, "service") or labels.get("service") or labels.get("namespace") or ""),
        "timestamp": _normalize_timestamp(
            _first_non_empty(alert, "timestamp", "fired_at", "lastReceived", "firingStartTime", "startedAt")
        ),
        "summary": str(_first_non_empty(alert, "summary", "message", "name", "title", "description")),
        "labels": labels,
        "annotations": annotations,
        "incident": dict(alert["incident"]) if isinstance(alert.get("incident"), Mapping) else None,
    }


def _dict_or_empty(value: Any) -> dict:
    return dict(value) if isinstance(value, Mapping) else {}


def _first_non_empty(alert: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = alert.get(key)
        if value is not None and value != "":
            return value
    return ""


def _normalize_timestamp(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if "T" in text:
        return text
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text
    return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def _build_annotations(alert: Mapping[str, Any]) -> dict:
    annotations = _dict_or_empty(alert.get("annotations"))
    for key in ("description", "message", "url", "note", "status", "environment"):
        value = alert.get(key)
        if value is not None and value != "":
            annotations.setdefault(key, value)
    return annotations


def _category(alert: Mapping[str, Any], labels: Mapping[str, Any], annotations: Mapping[str, Any]) -> str:
    explicit = alert.get("category")
    if isinstance(explicit, str) and explicit in CATEGORIES:
        return explicit

    haystack = " ".join(
        str(x).lower()
        for x in (
            alert.get("id", ""),
            alert.get("fingerprint", ""),
            alert.get("name", ""),
            alert.get("summary", ""),
            alert.get("title", ""),
            alert.get("message", ""),
            alert.get("description", ""),
            alert.get("service", ""),
            " ".join(f"{k}={v}" for k, v in labels.items()),
            " ".join(f"{k}={v}" for k, v in annotations.items()),
        )
    )
    for category, hints in _CATEGORY_HINTS:
        if any(hint in haystack for hint in hints):
            return category
    return "other"
