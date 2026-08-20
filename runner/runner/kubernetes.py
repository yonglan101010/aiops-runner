"""Read-only Kubernetes/VKE inventory and observability boundary.

The module deliberately exposes structured operations only.  It never accepts
kubectl commands, PromQL, or TLS DSL from callers and never persists raw logs.
"""

from __future__ import annotations

import base64
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import stat
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import yaml

PROTOCOL_VERSION = "kubernetes-observability/v1"
ASSET_SUMMARY_SCHEMA_VERSION = 3
OBJECT_QUERY_MAX_ITEMS = 100
INSPECTION_SCHEMA_VERSION = "kubernetes-inspection/v2"
INSPECTION_RULESET_VERSION = "kubernetes-health-rules/2.0.0"
INSPECTION_EVENT_WINDOW_SECONDS = 60 * 60
INSPECTION_TRANSIENT_GRACE_SECONDS = 5 * 60
INSPECTION_MAX_FINDINGS = 200
INSPECTION_MAX_AFFECTED_OBJECTS = 10
_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
_HIGH_SIGNAL_EVENT_REASONS = {
    "BackOff", "Failed", "FailedAttachVolume", "FailedCreate",
    "FailedMount", "FailedScheduling", "FailedSync", "FailedValidation",
    "ImagePullBackOff", "InspectFailed", "NodeNotReady", "Unhealthy",
}
_CONTAINER_WAITING_REASONS = {
    "CrashLoopBackOff", "CreateContainerConfigError", "CreateContainerError",
    "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "RunContainerError",
}
CAPABILITY_STATUSES = {
    "AVAILABLE", "MISSING", "UNAUTHORIZED", "MISCONFIGURED", "UNREACHABLE"
}
HISTORY_RANGES = {"1h", "6h", "24h", "7d", "30d"}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9._/-]{0,253}$")
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~+/=-]{12,}|(?:password|token|secret|access[_-]?key)\s*[:=]\s*\S+)"
)
_SENSITIVE_ANNOTATION = re.compile(r"(?i)(token|secret|password|credential|auth|key)")


class KubernetesBoundaryError(ValueError):
    def __init__(self, code: str, message: str, *, status: int = 400, retriable: bool = False):
        super().__init__(message)
        self.code = code
        self.status = status
        self.retriable = retriable


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _decode(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise KubernetesBoundaryError("INVALID_JSON", "request body must be JSON") from exc
    if not isinstance(value, dict):
        raise KubernetesBoundaryError("INVALID_REQUEST", "request body must be an object")
    return value


def _bounded_string(value: Any, field_name: str, *, maximum: int = 253, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise KubernetesBoundaryError("INVALID_FILTER", f"{field_name} is required")
    if len(text) > maximum or (text and not _SAFE_LABEL.fullmatch(text)):
        raise KubernetesBoundaryError("INVALID_FILTER", f"{field_name} is invalid")
    return text


def _bounded_context(value: Any, *, maximum: int = 1024) -> str:
    """Validate a kubeconfig context name without treating it as a query label.

    Context names are selected from a trusted node-local kubeconfig and passed
    directly to the Kubernetes Python Client, never to a shell or query DSL.
    VKE names commonly contain ``@``, so the stricter request-filter alphabet
    used by ``_bounded_string`` is not appropriate here.
    """

    raw = str(value or "")
    text = raw.strip()
    if not text:
        raise KubernetesBoundaryError(
            "INVENTORY_INVALID", "context is required", status=503
        )
    if raw != text or len(text) > maximum or any(
        unicodedata.category(character) in {"Cc", "Cs"}
        for character in text
    ):
        raise KubernetesBoundaryError(
            "INVENTORY_INVALID", "context is invalid", status=503
        )
    return text


def _only_fields(data: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise KubernetesBoundaryError(
            "UNSUPPORTED_FILTER", f"unsupported field(s): {', '.join(sorted(unknown))}"
        )


def _redact(text: str) -> str:
    cleaned = "".join(
        character if character in "\n\t" or unicodedata.category(character) != "Cc" else "�"
        for character in text
    )
    return _CREDENTIAL_PATTERN.sub("[REDACTED]", cleaned)


def _first(mapping: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def _integer(value: Any, default: int | None = None) -> int | None:
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _managed_fields_updated_at(metadata: Any) -> str | None:
    """Return the latest Kubernetes-managed field timestamp without exposing managers or fields."""
    timestamps = [
        parsed for entry in (_first(metadata, "managedFields", "managed_fields", default=[]) or [])
        if isinstance(entry, dict)
        for parsed in [_timestamp(_first(entry, "time"))]
        if parsed is not None
    ]
    if not timestamps:
        return None
    return max(timestamps).isoformat().replace("+00:00", "Z")


def _raw_list_payload(response: Any) -> tuple[list[dict[str, Any]], str]:
    """Decode a generated-client raw list response without model validation.

    EndpointSlice has a required ``endpoints`` model field in the Python
    client.  Some VKE responses legitimately omit it for an empty slice.  The
    Kubernetes API response remains valid JSON, so decode only the bounded
    fields needed by the existing safe asset projection.
    """
    try:
        raw = getattr(response, "data", b"")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        payload = json.loads(raw or "{}")
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, dict):
        raise KubernetesBoundaryError("RESOURCE_WATCH_FAILED", "raw Kubernetes list is invalid", status=503)
    items = payload.get("items")
    metadata = payload.get("metadata")
    return (
        [item for item in items if isinstance(item, dict)] if isinstance(items, list) else [],
        str(_first(metadata, "resourceVersion", "resource_version", default="") or ""),
    )


def _age_seconds(value: Any, *, now: datetime | None = None) -> int | None:
    observed = _timestamp(value)
    if observed is None:
        return None
    current = now or datetime.now(timezone.utc)
    return max(0, int((current - observed).total_seconds()))


def _condition_rows(raw: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        condition_type = str(_first(item, "type", default=""))[:64]
        condition_status = str(_first(item, "status", default="Unknown"))[:16]
        if not condition_type:
            continue
        row = {"type": condition_type, "status": condition_status}
        reason = str(_first(item, "reason", default=""))[:128]
        changed_at = str(
            _first(
                item,
                "lastTransitionTime", "last_transition_time",
                "lastUpdateTime", "last_update_time",
                default="",
            )
        )[:64]
        if reason:
            row["reason"] = reason
        if changed_at:
            row["last_transition_time"] = changed_at
        rows.append(row)
    return rows[:16]


def _condition_map(summary: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("type")): row
        for row in summary.get("conditions", [])
        if isinstance(row, dict) and row.get("type")
    }


def _object_ref(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": str(asset.get("kind") or "")[:64],
        "namespace": asset.get("namespace"),
        "name": str(asset.get("name") or "")[:253],
        "uid": str(asset.get("uid") or "")[:128],
    }


def _safe_containers(raw: Any) -> list[dict[str, Any]]:
    """Project container definitions without env, commands, or volume secrets."""
    result: list[dict[str, Any]] = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name = str(_first(item, "name", default=""))[:253]
        if not name:
            continue
        row: dict[str, Any] = {"name": name}
        image = str(_first(item, "image", default=""))[:1024]
        if image:
            row["image"] = image
        resources = _first(item, "resources", default={})
        if isinstance(resources, dict):
            safe_resources: dict[str, dict[str, str]] = {}
            for category in ("requests", "limits"):
                values = _first(resources, category, default={})
                if isinstance(values, dict):
                    safe_resources[category] = {
                        str(key)[:64]: str(value)[:64]
                        for key, value in list(values.items())[:16]
                    }
            if safe_resources:
                row["resources"] = safe_resources
        ports = _first(item, "ports", default=[])
        if isinstance(ports, list):
            safe_ports = []
            for port in ports[:16]:
                if not isinstance(port, dict):
                    continue
                value = _integer(_first(port, "containerPort", "container_port"))
                if value is None:
                    continue
                safe_ports.append({
                    "port": value,
                    "name": str(_first(port, "name", default=""))[:64],
                    "protocol": str(_first(port, "protocol", default="TCP"))[:16],
                })
            if safe_ports:
                row["ports"] = safe_ports
        result.append(row)
    return result[:32]


def _safe_labels(raw: Any, *, maximum: int = 20) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(key)[:128]: _redact(str(value))[:256]
        for key, value in list(raw.items())[:maximum]
        if not _SENSITIVE_ANNOTATION.search(str(key))
    }


def _health_status(kind: str, summary: dict[str, Any]) -> str:
    if kind == "Node":
        ready = _condition_map(summary).get("Ready")
        return "CRITICAL" if ready and ready.get("status") != "True" else "HEALTHY"
    if kind == "Pod":
        phase = str(summary.get("phase") or "Unknown")
        if phase in {"Failed", "Unknown"}:
            return "CRITICAL"
        if phase in {"Pending", "Succeeded"} or summary.get("ready") is False:
            return "WARNING"
        return "HEALTHY" if phase == "Running" else "UNKNOWN"
    if kind in {"Deployment", "StatefulSet"}:
        desired = _integer(summary.get("desired_replicas"))
        ready = _integer(summary.get("available_replicas"))
        if ready is None:
            ready = _integer(summary.get("ready_replicas"))
        if desired is not None and ready is not None:
            return "WARNING" if ready < desired else "HEALTHY"
    if kind == "DaemonSet":
        desired = _integer(summary.get("desired_number_scheduled"))
        ready = _integer(summary.get("number_ready"))
        if desired is not None and ready is not None:
            return "WARNING" if ready < desired else "HEALTHY"
    if kind == "Job":
        return "CRITICAL" if (_integer(summary.get("failed"), 0) or 0) > 0 else "HEALTHY"
    return "UNKNOWN"


def _scaled_to_zero_excluded_uids(assets: list[dict[str, Any]]) -> set[str]:
    """Identify explicitly stopped workloads and everything they own.

    ReplicaSets and ControllerRevisions frequently have zero replicas while
    still being valid revision history for an active workload, so only a
    top-level Deployment or StatefulSet can start an exclusion tree.
    """
    excluded = {
        str(asset.get("uid") or "")
        for asset in assets
        if asset.get("kind") in {"Deployment", "StatefulSet"}
        and _integer((asset.get("status_summary") or {}).get("desired_replicas")) == 0
        and asset.get("uid")
    }
    changed = True
    while changed:
        changed = False
        for asset in assets:
            uid = str(asset.get("uid") or "")
            if not uid or uid in excluded:
                continue
            owners = asset.get("owners") if isinstance(asset.get("owners"), list) else []
            if any(
                str(owner.get("uid") or "") in excluded
                for owner in owners
                if isinstance(owner, dict)
            ):
                excluded.add(uid)
                changed = True
    return excluded


def _exclude_scaled_to_zero_assets(
    assets: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    excluded = _scaled_to_zero_excluded_uids(assets)
    return (
        [asset for asset in assets if str(asset.get("uid") or "") not in excluded],
        excluded,
    )


def _filtered_resource_coverage(
    resources: list[dict[str, Any]], assets: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for asset in assets:
        kind = str(asset.get("kind") or "Unknown")
        counts[kind] = counts.get(kind, 0) + 1
    return [
        {
            **resource,
            "checked_count": counts.get(str(resource.get("kind") or ""), 0),
        }
        if resource.get("status") == "COMPLETE"
        else dict(resource)
        for resource in resources
    ]


@dataclass(frozen=True)
class ClusterConfig:
    id: str
    display_name: str
    environment: str
    kubeconfig_path: str
    context: str
    namespace_allowlist: tuple[str, ...] = ()
    vmp: dict[str, str] = field(default_factory=dict)
    tls: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AssetCollectionSnapshot:
    items: list[dict[str, Any]]
    resources: list[dict[str, Any]]

    @property
    def complete(self) -> bool:
        return all(item.get("status") == "COMPLETE" for item in self.resources)


class KubernetesInventory:
    """Loads a node-local cluster inventory without ever reading credential values."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._base = os.path.dirname(os.path.dirname(self.path))

    def load(self) -> dict[str, ClusterConfig]:
        if not os.path.isfile(self.path):
            raise KubernetesBoundaryError("INVENTORY_MISSING", "kubernetes inventory file is missing", status=503)
        with open(self.path, "r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream) or {}
        if not isinstance(data, dict) or set(data) != {"clusters"} or not isinstance(data["clusters"], list):
            raise KubernetesBoundaryError("INVENTORY_INVALID", "inventory must contain only a clusters list", status=503)
        result: dict[str, ClusterConfig] = {}
        allowed = {"id", "display_name", "environment", "kubeconfig_path", "context", "namespace_allowlist", "vmp", "tls"}
        for raw in data["clusters"]:
            if not isinstance(raw, dict) or set(raw) - allowed:
                raise KubernetesBoundaryError("INVENTORY_INVALID", "cluster entry contains unsupported fields", status=503)
            cluster_id = _bounded_string(raw.get("id"), "cluster.id")
            if cluster_id in result:
                raise KubernetesBoundaryError("INVENTORY_INVALID", "cluster ids must be unique", status=503)
            namespaces = raw.get("namespace_allowlist") or []
            if not isinstance(namespaces, list):
                raise KubernetesBoundaryError("INVENTORY_INVALID", "namespace_allowlist must be a list", status=503)
            namespaces = tuple(_bounded_string(item, "namespace") for item in namespaces)
            kubeconfig = str(raw.get("kubeconfig_path") or "").strip()
            if not kubeconfig:
                raise KubernetesBoundaryError("INVENTORY_INVALID", "kubeconfig_path is required", status=503)
            if not os.path.isabs(kubeconfig):
                kubeconfig = os.path.abspath(os.path.join(self._base, kubeconfig))
            for block in (raw.get("vmp") or {}, raw.get("tls") or {}):
                if not isinstance(block, dict) or any(not isinstance(v, str) for v in block.values()):
                    raise KubernetesBoundaryError("INVENTORY_INVALID", "vmp/tls configuration must contain strings", status=503)
            result[cluster_id] = ClusterConfig(
                id=cluster_id,
                display_name=str(raw.get("display_name") or cluster_id)[:255],
                environment=_bounded_string(raw.get("environment") or "unknown", "environment"),
                kubeconfig_path=kubeconfig,
                context=_bounded_context(raw.get("context")),
                namespace_allowlist=namespaces,
                vmp=dict(raw.get("vmp") or {}),
                tls=dict(raw.get("tls") or {}),
            )
        return result

    @staticmethod
    def validate_local_file(cluster: ClusterConfig) -> dict[str, Any]:
        path = Path(cluster.kubeconfig_path)
        if not path.is_file():
            raise KubernetesBoundaryError("KUBECONFIG_MISSING", "kubeconfig file is missing", status=503)
        info = path.stat()
        mode = stat.S_IMODE(info.st_mode)
        if os.name != "nt":
            if mode != 0o600:
                raise KubernetesBoundaryError("KUBECONFIG_PERMISSIONS", "kubeconfig must have mode 0600", status=503)
            if info.st_uid != os.geteuid():
                raise KubernetesBoundaryError("KUBECONFIG_OWNER", "kubeconfig must be owned by the runner service user", status=503)
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise KubernetesBoundaryError("KUBECONFIG_INVALID", "kubeconfig cannot be parsed", status=503) from exc
        contexts = {item.get("name") for item in document.get("contexts", []) if isinstance(item, dict)}
        if cluster.context not in contexts:
            raise KubernetesBoundaryError("KUBECONFIG_CONTEXT", "configured kubeconfig context is missing", status=503)
        certificate_expiry = None
        for user in document.get("users", []):
            values = (user or {}).get("user") or {}
            if values.get("exec") is not None:
                raise KubernetesBoundaryError(
                    "KUBECONFIG_EXEC_UNSUPPORTED",
                    "kubeconfig exec authentication plugins are not allowed",
                    status=503,
                )
            encoded = values.get("client-certificate-data")
            certificate_file = values.get("client-certificate")
            if not encoded and not certificate_file:
                continue
            try:
                from cryptography import x509
                raw = base64.b64decode(encoded) if encoded else Path(certificate_file if os.path.isabs(certificate_file) else path.parent / certificate_file).read_bytes()
                certificate = x509.load_pem_x509_certificate(raw)
                expires = certificate.not_valid_after_utc
                certificate_expiry = expires.isoformat().replace("+00:00", "Z")
                if expires <= datetime.now(timezone.utc):
                    raise KubernetesBoundaryError("KUBECONFIG_CERTIFICATE_EXPIRED", "kubeconfig client certificate has expired", status=503)
            except KubernetesBoundaryError:
                raise
            except Exception as exc:
                raise KubernetesBoundaryError("KUBECONFIG_CERTIFICATE_INVALID", "kubeconfig client certificate is invalid", status=503) from exc
        return {"path": str(path), "mode": oct(mode), "owner_uid": getattr(info, "st_uid", None), "context": cluster.context, "certificate_expiry": certificate_expiry}


class ClusterClient(Protocol):
    def identity(self, cluster: ClusterConfig) -> dict[str, Any]: ...
    def capabilities(self, cluster: ClusterConfig) -> list[dict[str, Any]]: ...
    def assets(self, cluster: ClusterConfig) -> list[dict[str, Any]]: ...
    def current_metrics(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...
    def current_logs(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...
    def current_events(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...


class HistoryClient(Protocol):
    def metrics(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...
    def logs(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...
    def events(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]: ...


class UnconfiguredHistoryClient:
    """Safe default: never invents a provider endpoint or accepts a raw query."""

    def _missing(self, kind: str) -> dict[str, Any]:
        raise KubernetesBoundaryError(
            f"{kind.upper()}_MISCONFIGURED",
            f"{kind} official SDK adapter is not configured",
            status=503,
        )

    def metrics(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        return self._missing("vmp")

    def logs(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        return self._missing("tls")

    def events(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        return self._missing("tls")


class VolcengineHistoryClient:
    """Official SDK discovery plus bounded VMP Prometheus/TLS queries."""

    _RANGE_SECONDS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
    _STEP_SECONDS = {"1h": 30, "6h": 60, "24h": 300, "7d": 1800, "30d": 7200}

    @staticmethod
    def _credentials() -> tuple[str, str]:
        ak = os.environ.get("VOLCENGINE_ACCESS_KEY_ID") or os.environ.get("VOLC_ACCESSKEY") or ""
        sk = os.environ.get("VOLCENGINE_ACCESS_KEY_SECRET") or os.environ.get("VOLC_SECRETKEY") or ""
        if not ak or not sk:
            raise KubernetesBoundaryError("VOLCENGINE_CREDENTIALS_MISSING", "Volcengine credentials are not configured", status=503)
        return ak, sk

    @staticmethod
    def _selector(query: dict[str, Any]) -> str:
        labels = []
        if query.get("namespace"):
            labels.append(f'namespace="{query["namespace"]}"')
        if query.get("resource_name"):
            label = "node" if query["resource_type"] == "node" else "pod"
            labels.append(f'{label}="{query["resource_name"]}"')
        return "{" + ",".join(labels) + "}" if labels else ""

    def _promql(self, query: dict[str, Any]) -> str:
        selector = self._selector(query)
        resource_type, metric = query["resource_type"], query["metric"]
        expressions = {
            ("node", "cpu_usage"): f'sum(rate(node_cpu_seconds_total{selector[:-1] + ("," if selector else "{") + "mode!=\"idle\"}"}[5m])) by (instance)',
            ("node", "cpu_utilization"): f'100 * (1 - avg(rate(node_cpu_seconds_total{selector[:-1] + ("," if selector else "{") + "mode=\"idle\"}"}[5m])) by (instance))',
            ("node", "memory_usage"): f'node_memory_MemTotal_bytes{selector} - node_memory_MemAvailable_bytes{selector}',
            ("node", "memory_utilization"): f'100 * (1 - node_memory_MemAvailable_bytes{selector} / node_memory_MemTotal_bytes{selector})',
            ("node", "network_receive"): f'sum(rate(node_network_receive_bytes_total{selector}[5m])) by (instance)',
            ("node", "network_transmit"): f'sum(rate(node_network_transmit_bytes_total{selector}[5m])) by (instance)',
            ("pod", "cpu_usage"): f'sum(rate(container_cpu_usage_seconds_total{selector[:-1] + ("," if selector else "{") + "container!=\"\",pod!=\"\"}"}[5m])) by (namespace,pod)',
            ("pod", "cpu_utilization"): f'100 * sum(rate(container_cpu_usage_seconds_total{selector[:-1] + ("," if selector else "{") + "container!=\"\",pod!=\"\"}"}[5m])) by (namespace,pod)',
            ("pod", "memory_usage"): f'sum(container_memory_working_set_bytes{selector[:-1] + ("," if selector else "{") + "container!=\"\",pod!=\"\"}"}) by (namespace,pod)',
            ("pod", "memory_utilization"): f'100 * sum(container_memory_working_set_bytes{selector[:-1] + ("," if selector else "{") + "container!=\"\",pod!=\"\"}"}) by (namespace,pod) / sum(kube_pod_container_resource_limits{selector[:-1] + ("," if selector else "{") + "resource=\"memory\"}"}) by (namespace,pod)',
            ("pod", "network_receive"): f'sum(rate(container_network_receive_bytes_total{selector}[5m])) by (namespace,pod)',
            ("pod", "network_transmit"): f'sum(rate(container_network_transmit_bytes_total{selector}[5m])) by (namespace,pod)',
        }
        return expressions[(resource_type, metric)]

    def _workspace(self, cluster: ClusterConfig):
        if not cluster.vmp.get("region") or not cluster.vmp.get("workspace_id"):
            raise KubernetesBoundaryError("VMP_MISCONFIGURED", "VMP workspace configuration is incomplete", status=503)
        ak, sk = self._credentials()
        try:
            import volcenginesdkcore
            import volcenginesdkvmp
            configuration = volcenginesdkcore.Configuration()
            configuration.ak, configuration.sk = ak, sk
            configuration.region = cluster.vmp["region"]
            configuration.host = f'vmp.{cluster.vmp["region"]}.volcengineapi.com'
            api = volcenginesdkvmp.VMPApi(volcenginesdkcore.ApiClient(configuration))
            workspace = api.get_workspace(volcenginesdkvmp.GetWorkspaceRequest(id=cluster.vmp["workspace_id"]))
            auth = api.get_workspace_auth_info(volcenginesdkvmp.GetWorkspaceAuthInfoRequest(id=cluster.vmp["workspace_id"]))
            endpoint = workspace.prometheus_query_intranet_endpoint or workspace.prometheus_query_endpoint
            if not endpoint or not auth.bearer_token:
                raise KubernetesBoundaryError("VMP_MISCONFIGURED", "VMP query endpoint or bearer token is unavailable", status=503)
            return endpoint.rstrip("/"), auth.bearer_token
        except KubernetesBoundaryError:
            raise
        except Exception as exc:
            status = getattr(exc, "status", None)
            code = "VMP_UNAUTHORIZED" if status in {401, 403} else "VMP_UNREACHABLE"
            raise KubernetesBoundaryError(code, "VMP workspace discovery failed", status=503, retriable=status not in {401, 403}) from exc

    def metrics(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        endpoint, bearer = self._workspace(cluster)
        seconds = self._RANGE_SECONDS[query["range"]]
        end = datetime.now(timezone.utc)
        params = urlencode({"query": self._promql(query), "start": int((end - timedelta(seconds=seconds)).timestamp()), "end": int(end.timestamp()), "step": self._STEP_SECONDS[query["range"]]})
        request = Request(f"{endpoint}/api/v1/query_range?{params}", headers={"Accept": "application/json", "Authorization": f"Bearer {bearer}"})
        try:
            with urlopen(request, timeout=30) as response:  # noqa: S310 - endpoint comes only from official SDK workspace metadata
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise KubernetesBoundaryError("VMP_RESPONSE_TOO_LARGE", "VMP response exceeded 4 MiB", status=503)
            payload = json.loads(raw)
            if payload.get("status") != "success" or not isinstance(payload.get("data"), dict):
                raise KubernetesBoundaryError("VMP_RESPONSE_INVALID", "VMP returned an invalid response", status=503)
            return {"metric": query["metric"], "range": query["range"], "step_seconds": self._STEP_SECONDS[query["range"]], "series": payload["data"].get("result", [])[:1000]}
        except KubernetesBoundaryError:
            raise
        except Exception as exc:
            raise KubernetesBoundaryError("VMP_QUERY_FAILED", "VMP history query failed", status=503, retriable=True) from exc

    @staticmethod
    def _tls_query(query: dict[str, Any], *, event: bool) -> str:
        terms = ["*"]
        mapping = {"namespace": "namespace", "pod": "pod", "container": "container", "level": "level", "type": "type", "reason": "reason"}
        for key, field_name in mapping.items():
            if query.get(key):
                escaped = str(query[key]).replace('"', '\\"')
                terms.append(f'{field_name}:"{escaped}"')
        return " AND ".join(terms)

    def _tls(self, cluster: ClusterConfig, query: dict[str, Any], *, event: bool) -> dict[str, Any]:
        topic_key = "event_topic_id" if event else "log_topic_id"
        region, topic_id = cluster.tls.get("region"), cluster.tls.get(topic_key)
        if not region or not topic_id:
            raise KubernetesBoundaryError("TLS_MISCONFIGURED", "TLS topic configuration is incomplete", status=503)
        ak, sk = self._credentials()
        seconds = self._RANGE_SECONDS[query["range"]]
        end_ms = int(time.time() * 1000)
        try:
            from volcengine.tls.TLSService import TLSService
            from volcengine.tls.tls_requests import SearchLogsRequest
            endpoint = f"tls-{region}.ivolces.com"
            client = TLSService(endpoint, ak, sk, region)
            context = query.get("cursor")
            logs: list[Any] = []
            for _ in range(2):
                kwargs = {"topic_id": topic_id, "query": self._tls_query(query, event=event), "limit": 100, "start_time": end_ms - seconds * 1000, "end_time": end_ms}
                if context:
                    kwargs["context"] = context
                response = client.search_logs_v2(SearchLogsRequest(**kwargs)).response
                page = response.get("Logs") or response.get("AnalysisResult", {}).get("Data") or []
                logs.extend(page[:100])
                context = response.get("Context")
                if not context or not page:
                    break
            safe = json.loads(_redact(json.dumps(logs[:200], ensure_ascii=False)))
            return {"items": safe, "next_cursor": context, "range": query["range"], "truncated": bool(context)}
        except Exception as exc:
            status = getattr(exc, "status", None)
            code = "TLS_UNAUTHORIZED" if status in {401, 403} else "TLS_QUERY_FAILED"
            raise KubernetesBoundaryError(code, "TLS history query failed", status=503, retriable=status not in {401, 403}) from exc

    def logs(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        return self._tls(cluster, query, event=False)

    def events(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        return self._tls(cluster, query, event=True)

    def capabilities(self, cluster: ClusterConfig) -> list[dict[str, Any]]:
        rows = []
        checks = [
            ("vmp_workspace", lambda: self._workspace(cluster)),
            ("tls_logs", lambda: self._tls(cluster, {"range": "1h"}, event=False)),
            ("tls_events", lambda: self._tls(cluster, {"range": "1h"}, event=True)),
        ]
        for name, check in checks:
            try:
                check()
                rows.append({"name": name, "status": "AVAILABLE", "detail": "official provider query succeeded"})
            except KubernetesBoundaryError as exc:
                if "UNAUTHORIZED" in exc.code:
                    status = "UNAUTHORIZED"
                elif "MISCONFIGURED" in exc.code or "MISSING" in exc.code:
                    status = "MISCONFIGURED"
                else:
                    status = "UNREACHABLE"
                rows.append({"name": name, "status": status, "detail": exc.code})
        return rows


class OfficialKubernetesClient:
    """Kubernetes Python client adapter. Imports are lazy for config/test tooling."""

    RESOURCES = (
        ("v1", "Node"), ("v1", "Namespace"), ("v1", "Pod"),
        ("v1", "Service"), ("v1", "PersistentVolumeClaim"), ("v1", "PersistentVolume"),
        ("apps/v1", "Deployment"), ("apps/v1", "StatefulSet"),
        ("apps/v1", "DaemonSet"), ("apps/v1", "ReplicaSet"),
        ("apps/v1", "ControllerRevision"),
        ("batch/v1", "Job"), ("batch/v1", "CronJob"),
        ("discovery.k8s.io/v1", "EndpointSlice"),
        ("networking.k8s.io/v1", "Ingress"),
        ("storage.k8s.io/v1", "StorageClass"),
        ("autoscaling/v2", "HorizontalPodAutoscaler"),
        ("policy/v1", "PodDisruptionBudget"),
        ("v1", "ResourceQuota"), ("v1", "LimitRange"),
    )

    # ``watch.Watch`` needs generated client list methods.  DynamicClient
    # serialises a streamed response with kubernetes-client 33.x before Watch
    # can consume it, so it must remain limited to one-off inventory reads.
    _WATCH_METHODS = {
        ("v1", "Node"): ("CoreV1Api", "list_node", None),
        ("v1", "Namespace"): ("CoreV1Api", "list_namespace", None),
        ("v1", "Pod"): ("CoreV1Api", "list_pod_for_all_namespaces", "list_namespaced_pod"),
        ("v1", "Service"): ("CoreV1Api", "list_service_for_all_namespaces", "list_namespaced_service"),
        ("v1", "PersistentVolumeClaim"): ("CoreV1Api", "list_persistent_volume_claim_for_all_namespaces", "list_namespaced_persistent_volume_claim"),
        ("v1", "PersistentVolume"): ("CoreV1Api", "list_persistent_volume", None),
        ("apps/v1", "Deployment"): ("AppsV1Api", "list_deployment_for_all_namespaces", "list_namespaced_deployment"),
        ("apps/v1", "StatefulSet"): ("AppsV1Api", "list_stateful_set_for_all_namespaces", "list_namespaced_stateful_set"),
        ("apps/v1", "DaemonSet"): ("AppsV1Api", "list_daemon_set_for_all_namespaces", "list_namespaced_daemon_set"),
        ("apps/v1", "ReplicaSet"): ("AppsV1Api", "list_replica_set_for_all_namespaces", "list_namespaced_replica_set"),
        ("apps/v1", "ControllerRevision"): ("AppsV1Api", "list_controller_revision_for_all_namespaces", "list_namespaced_controller_revision"),
        ("batch/v1", "Job"): ("BatchV1Api", "list_job_for_all_namespaces", "list_namespaced_job"),
        ("batch/v1", "CronJob"): ("BatchV1Api", "list_cron_job_for_all_namespaces", "list_namespaced_cron_job"),
        ("discovery.k8s.io/v1", "EndpointSlice"): ("DiscoveryV1Api", "list_endpoint_slice_for_all_namespaces", "list_namespaced_endpoint_slice"),
        ("networking.k8s.io/v1", "Ingress"): ("NetworkingV1Api", "list_ingress_for_all_namespaces", "list_namespaced_ingress"),
        ("storage.k8s.io/v1", "StorageClass"): ("StorageV1Api", "list_storage_class", None),
        ("autoscaling/v2", "HorizontalPodAutoscaler"): ("AutoscalingV2Api", "list_horizontal_pod_autoscaler_for_all_namespaces", "list_namespaced_horizontal_pod_autoscaler"),
        ("policy/v1", "PodDisruptionBudget"): ("PolicyV1Api", "list_pod_disruption_budget_for_all_namespaces", "list_namespaced_pod_disruption_budget"),
        ("v1", "ResourceQuota"): ("CoreV1Api", "list_resource_quota_for_all_namespaces", "list_namespaced_resource_quota"),
        ("v1", "LimitRange"): ("CoreV1Api", "list_limit_range_for_all_namespaces", "list_namespaced_limit_range"),
    }

    def __init__(self) -> None:
        self._log_restart_counts: dict[tuple[str, str, str], int] = {}
        self._log_restart_lock = threading.Lock()

    def _apis(self, cluster: ClusterConfig):
        try:
            from kubernetes import client, config, dynamic
        except ImportError as exc:
            raise KubernetesBoundaryError("KUBERNETES_CLIENT_MISSING", "kubernetes client is not installed", status=503) from exc
        KubernetesInventory.validate_local_file(cluster)
        try:
            api_client = config.new_client_from_config(cluster.kubeconfig_path, context=cluster.context)
            return client, api_client, dynamic.DynamicClient(api_client)
        except Exception as exc:
            raise KubernetesBoundaryError("KUBERNETES_UNREACHABLE", "cluster client initialization failed", status=503, retriable=True) from exc

    def identity(self, cluster: ClusterConfig) -> dict[str, Any]:
        client, api_client, _ = self._apis(cluster)
        try:
            version = client.VersionApi(api_client).get_code(_request_timeout=10)
            namespace = client.CoreV1Api(api_client).read_namespace(
                "kube-system", _request_timeout=10
            )
            return {"cluster_uid": str(namespace.metadata.uid), "version": str(version.git_version)}
        except Exception as exc:
            raise KubernetesBoundaryError("KUBERNETES_UNREACHABLE", "cluster identity probe failed", status=503, retriable=True) from exc

    def _safe_asset(self, item: Any) -> dict[str, Any]:
        value = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        meta = value.get("metadata") or {}
        status = value.get("status") or {}
        spec = value.get("spec") or {}
        labels = _safe_labels(meta.get("labels"), maximum=32)
        owners = []
        for owner in _first(meta, "ownerReferences", "owner_references", default=[]) or []:
            if not isinstance(owner, dict):
                continue
            owners.append({
                "kind": str(owner.get("kind") or "")[:64],
                "name": str(owner.get("name") or "")[:253],
                "uid": str(owner.get("uid") or "")[:128],
                "controller": bool(owner.get("controller", False)),
            })
        kind = str(value.get("kind") or "")[:64]
        summary: dict[str, Any] = {}
        common_status_fields = {
            "phase": ("phase",),
            "replicas": ("replicas",),
            "ready_replicas": ("readyReplicas", "ready_replicas"),
            "available_replicas": ("availableReplicas", "available_replicas"),
            "updated_replicas": ("updatedReplicas", "updated_replicas"),
            "current_replicas": ("currentReplicas", "current_replicas"),
            "desired_number_scheduled": ("desiredNumberScheduled", "desired_number_scheduled"),
            "current_number_scheduled": ("currentNumberScheduled", "current_number_scheduled"),
            "updated_number_scheduled": ("updatedNumberScheduled", "updated_number_scheduled"),
            "number_ready": ("numberReady", "number_ready"),
            "number_available": ("numberAvailable", "number_available"),
            "number_unavailable": ("numberUnavailable", "number_unavailable"),
            "number_misscheduled": ("numberMisscheduled", "number_misscheduled"),
            "observed_generation": ("observedGeneration", "observed_generation"),
            "succeeded": ("succeeded",),
            "failed": ("failed",),
            "active": ("active",),
            "current_cpu_utilization_percentage": (
                "currentCPUUtilizationPercentage", "current_cpu_utilization_percentage"
            ),
            "desired_replicas_hpa": ("desiredReplicas", "desired_replicas"),
        }
        for canonical, aliases in common_status_fields.items():
            raw = _first(status, *aliases)
            if raw is not None:
                summary[canonical] = raw if canonical == "phase" else _integer(raw, raw)
        conditions = _condition_rows(_first(status, "conditions", default=[]))
        if conditions:
            summary["conditions"] = conditions
        creation_timestamp = str(
            _first(meta, "creationTimestamp", "creation_timestamp", default="")
        )[:64]
        updated_timestamp = _managed_fields_updated_at(meta)
        deletion_timestamp = str(
            _first(meta, "deletionTimestamp", "deletion_timestamp", default="")
        )[:64]
        if creation_timestamp:
            summary["creation_timestamp"] = creation_timestamp
            age = _age_seconds(creation_timestamp)
            if age is not None:
                summary["age_seconds"] = age
        if deletion_timestamp:
            summary["deletion_timestamp"] = deletion_timestamp
        generation = _integer(_first(meta, "generation"))
        if generation is not None:
            summary["generation"] = generation

        desired = _integer(_first(spec, "replicas"))
        if desired is not None:
            summary["desired_replicas"] = desired
        if kind in {"Deployment", "StatefulSet"}:
            observed = _integer(_first(status, "observedGeneration", "observed_generation"))
            ready_field = (
                _first(status, "availableReplicas", "available_replicas")
                if kind == "Deployment"
                else _first(status, "readyReplicas", "ready_replicas")
            )
            summary["replica_status_observed"] = (
                observed is not None
                and ready_field is not None
                and (generation is None or observed >= generation)
            )
        elif kind == "DaemonSet":
            observed = _integer(_first(status, "observedGeneration", "observed_generation"))
            summary["replica_status_observed"] = (
                observed is not None
                and _first(status, "desiredNumberScheduled", "desired_number_scheduled") is not None
                and _first(status, "numberReady", "number_ready") is not None
                and (generation is None or observed >= generation)
            )
        elif kind == "Node":
            summary["unschedulable"] = bool(_first(spec, "unschedulable", default=False))
            addresses = _first(status, "addresses", default=[])
            for address in addresses if isinstance(addresses, list) else []:
                if not isinstance(address, dict):
                    continue
                if _first(address, "type") == "InternalIP" and _first(address, "address"):
                    summary["internal_ip"] = str(_first(address, "address"))[:64]
                    break
        elif kind == "Pod":
            ready_condition = next(
                (row for row in conditions if row.get("type") == "Ready"), None
            )
            if ready_condition is not None:
                summary["ready"] = ready_condition.get("status") == "True"
            waiting_reasons: set[str] = set()
            terminated_reasons: set[str] = set()
            exit_codes: set[int] = set()
            restart_count = 0
            regular_container_statuses = (
                _first(status, "containerStatuses", "container_statuses", default=[]) or []
            )
            summary["total_containers"] = len(regular_container_statuses)
            summary["ready_containers"] = sum(
                1 for container in regular_container_statuses
                if isinstance(container, dict) and bool(_first(container, "ready", default=False))
            )
            container_statuses = regular_container_statuses + (
                _first(status, "initContainerStatuses", "init_container_statuses", default=[]) or []
            )
            for container in container_statuses:
                if not isinstance(container, dict):
                    continue
                restart_count += _integer(
                    _first(container, "restartCount", "restart_count"), 0
                ) or 0
                state = container.get("state") or {}
                waiting = state.get("waiting") or {}
                terminated = state.get("terminated") or {}
                if waiting.get("reason"):
                    waiting_reasons.add(str(waiting["reason"])[:128])
                if terminated.get("reason"):
                    terminated_reasons.add(str(terminated["reason"])[:128])
                exit_code = _integer(_first(terminated, "exitCode", "exit_code"))
                if exit_code is not None:
                    exit_codes.add(exit_code)
            summary["restart_count"] = restart_count
            if waiting_reasons:
                summary["waiting_reasons"] = sorted(waiting_reasons)[:10]
            if terminated_reasons:
                summary["terminated_reasons"] = sorted(terminated_reasons)[:10]
            if exit_codes:
                summary["exit_codes"] = sorted(exit_codes)[:10]
            node_name = _first(spec, "nodeName", "node_name")
            pod_ip = _first(status, "podIP", "pod_ip")
            if node_name:
                summary["node_name"] = str(node_name)[:253]
            if pod_ip:
                summary["pod_ip"] = str(pod_ip)[:64]
        elif kind == "Job":
            backoff_limit = _integer(_first(spec, "backoffLimit", "backoff_limit"))
            if backoff_limit is not None:
                summary["backoff_limit"] = backoff_limit
            for key in ("startTime", "completionTime"):
                raw = _first(status, key, "_".join(re.findall(r"[A-Z]?[a-z]+", key)).lower())
                if raw:
                    summary["start_time" if key == "startTime" else "completion_time"] = str(raw)[:64]
        elif kind == "HorizontalPodAutoscaler":
            for source, target in (
                (("minReplicas", "min_replicas"), "min_replicas"),
                (("maxReplicas", "max_replicas"), "max_replicas"),
            ):
                raw = _integer(_first(spec, *source))
                if raw is not None:
                    summary[target] = raw
            current = _integer(_first(status, "currentReplicas", "current_replicas"))
            desired_hpa = _integer(_first(status, "desiredReplicas", "desired_replicas"))
            if current is not None:
                summary["current_replicas"] = current
            if desired_hpa is not None:
                summary["desired_replicas"] = desired_hpa
        elif kind == "PersistentVolumeClaim":
            storage_class = _first(spec, "storageClassName", "storage_class_name")
            if storage_class:
                summary["storage_class"] = str(storage_class)[:253]
        elif kind == "Service":
            selector = _first(spec, "selector", default={}) or {}
            summary["selector_count"] = len(selector) if isinstance(selector, dict) else 0
            summary["service_type"] = str(_first(spec, "type", default="ClusterIP"))[:64]
            cluster_ip = _first(spec, "clusterIP", "cluster_ip")
            if cluster_ip:
                summary["cluster_ip"] = str(cluster_ip)[:64]
        elif kind == "EndpointSlice":
            endpoints = value.get("endpoints") or []
            ready = 0
            for endpoint in endpoints if isinstance(endpoints, list) else []:
                condition = endpoint.get("conditions") if isinstance(endpoint, dict) else {}
                if _first(condition or {}, "ready", default=True) is not False:
                    ready += 1
            summary["endpoint_count"] = len(endpoints) if isinstance(endpoints, list) else 0
            summary["ready_endpoint_count"] = ready
        spec_summary: dict[str, Any] = {}
        template = _first(spec, "template", default={})
        if kind == "CronJob":
            job_template = _first(spec, "jobTemplate", "job_template", default={})
            job_spec = _first(job_template, "spec", default={}) if isinstance(job_template, dict) else {}
            template = _first(job_spec, "template", default={})
        template_spec = _first(template, "spec", default={}) if isinstance(template, dict) else {}
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
            containers = _safe_containers(_first(template_spec, "containers", default=[]))
            if containers:
                spec_summary["containers"] = containers
            if kind == "CronJob":
                schedule = _first(spec, "schedule")
                if schedule:
                    spec_summary["schedule"] = str(schedule)[:128]
                spec_summary["suspend"] = bool(_first(spec, "suspend", default=False))
        elif kind == "Pod":
            containers = _safe_containers(_first(spec, "containers", default=[]))
            if containers:
                spec_summary["containers"] = containers
        elif kind == "Service":
            ports = _first(spec, "ports", default=[])
            if isinstance(ports, list):
                spec_summary["ports"] = [
                    {
                        "port": _integer(_first(port, "port")),
                        "target_port": str(_first(port, "targetPort", "target_port", default=""))[:64],
                        "protocol": str(_first(port, "protocol", default="TCP"))[:16],
                    }
                    for port in ports[:16]
                    if isinstance(port, dict) and _integer(_first(port, "port")) is not None
                ]
            selector = _safe_labels(_first(spec, "selector", default={}), maximum=20)
            if selector:
                spec_summary["selector"] = selector
        elif kind == "PersistentVolumeClaim":
            requests = _first(_first(spec, "resources", default={}), "requests", default={})
            if isinstance(requests, dict) and requests.get("storage"):
                spec_summary["requested_storage"] = str(requests["storage"])[:64]
        elif kind == "HorizontalPodAutoscaler":
            target = _first(spec, "scaleTargetRef", "scale_target_ref", default={})
            if isinstance(target, dict):
                spec_summary["target"] = {
                    "kind": str(_first(target, "kind", default=""))[:64],
                    "name": str(_first(target, "name", default=""))[:253],
                }
        elif kind == "ControllerRevision":
            revision_data = _first(value, "data", default={})
            raw = _first(revision_data, "raw", default="") if isinstance(revision_data, dict) else ""
            if isinstance(raw, str) and len(raw.encode("utf-8")) <= 256 * 1024:
                try:
                    decoded = json.loads(raw)
                    decoded_spec = _first(decoded, "spec", default={}) if isinstance(decoded, dict) else {}
                    decoded_template = _first(decoded_spec, "template", default={}) if isinstance(decoded_spec, dict) else {}
                    decoded_template_spec = _first(decoded_template, "spec", default={}) if isinstance(decoded_template, dict) else {}
                    revision_containers = _safe_containers(_first(decoded_template_spec, "containers", default=[]))
                    if revision_containers:
                        spec_summary["containers"] = revision_containers
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
        annotations = _first(meta, "annotations", default={})
        deployment_revision = None
        if isinstance(annotations, dict):
            deployment_revision = _integer(annotations.get("deployment.kubernetes.io/revision"))
        revision = deployment_revision if deployment_revision is not None else _integer(_first(value, "revision"))
        if revision is not None:
            summary["revision"] = revision
        if kind == "ControllerRevision":
            summary["revision"] = _integer(_first(value, "revision"), 0)
        return {
            "summary_schema_version": ASSET_SUMMARY_SCHEMA_VERSION,
            "api_version": value.get("api_version") or value.get("apiVersion") or "",
            "kind": kind,
            "namespace": meta.get("namespace"),
            "name": meta.get("name") or "",
            "uid": str(meta.get("uid") or ""),
            "resource_version": str(
                _first(meta, "resourceVersion", "resource_version", default="")
            ),
            "owners": owners,
            "labels": labels,
            "status_summary": summary,
            "spec_summary": spec_summary,
            "object_created_at": creation_timestamp or None,
            "object_updated_at": updated_timestamp,
            "generation": generation,
            "health_status": _health_status(kind, summary),
        }

    def collect_assets(self, cluster: ClusterConfig) -> AssetCollectionSnapshot:
        _, _, dynamic_client = self._apis(cluster)
        assets: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        for api_version, kind in self.RESOURCES:
            before = len(assets)
            try:
                resource = dynamic_client.resources.get(api_version=api_version, kind=kind)
                if cluster.namespace_allowlist and getattr(resource, "namespaced", False):
                    for namespace in cluster.namespace_allowlist:
                        response = resource.get(namespace=namespace)
                        assets.extend(self._safe_asset(item) for item in response.items)
                else:
                    response = resource.get()
                    assets.extend(self._safe_asset(item) for item in response.items)
            except Exception as exc:
                status = getattr(exc, "status", None)
                resources.append({
                    "api_version": api_version,
                    "kind": kind,
                    "status": "UNAUTHORIZED" if status == 403 else "UNAVAILABLE",
                    "checked_count": 0,
                    "failure_code": (
                        "KUBERNETES_RBAC_UNAUTHORIZED"
                        if status == 403
                        else "KUBERNETES_RESOURCE_API_MISSING"
                        if status == 404
                        else "ASSET_COLLECTION_FAILED"
                    ),
                })
                continue
            resources.append({
                "api_version": api_version,
                "kind": kind,
                "status": "COMPLETE",
                "checked_count": len(assets) - before,
            })
        return AssetCollectionSnapshot(assets, resources)

    def assets(self, cluster: ClusterConfig) -> list[dict[str, Any]]:
        snapshot = self.collect_assets(cluster)
        if not snapshot.complete:
            raise KubernetesBoundaryError(
                "ASSET_COLLECTION_PARTIAL",
                "asset collection is incomplete",
                status=503,
                retriable=True,
            )
        return snapshot.items

    def watch_assets(self, cluster: ClusterConfig, stop_event: threading.Event, callback, health_callback=None) -> None:
        """Watch generated Kubernetes API methods, one Kind/scope per worker."""
        client, api_client, _ = self._apis(cluster)
        from kubernetes import watch

        def report(key: str, state: str, *, changed: bool = False,
                   error_code: str | None = None, active: bool = False,
                   restart: bool = False) -> None:
            if health_callback is not None:
                health_callback(key, state, {
                    "heartbeat_at": _utcnow(), "changed": changed,
                    "error_code": error_code, "active": active, "restart": restart,
                })

        def safe_error_code(exc: Exception) -> str:
            if getattr(exc, "status", None) == 403:
                return "KUBERNETES_RBAC_UNAUTHORIZED"
            if getattr(exc, "status", None) == 404:
                return "KUBERNETES_RESOURCE_API_MISSING"
            return "RESOURCE_WATCH_FAILED"

        def watch_resource(api_version: str, kind: str, namespace: str | None) -> None:
            key = f"{api_version}/{kind}:{namespace or '*'}"
            resource_version = ""
            backoff = 1
            raw_mode = (api_version, kind) == ("discovery.k8s.io/v1", "EndpointSlice")
            api_name, all_method_name, namespaced_method_name = self._WATCH_METHODS[(api_version, kind)]
            api = getattr(client, api_name)(api_client)
            method = getattr(api, namespaced_method_name if namespace else all_method_name)
            while not stop_event.is_set():
                watcher = watch.Watch(return_type=None) if raw_mode else watch.Watch()
                try:
                    if not resource_version:
                        list_kwargs: dict[str, Any] = {"_request_timeout": 20}
                        if namespace:
                            list_kwargs["namespace"] = namespace
                        if raw_mode:
                            raw_items, resource_version = _raw_list_payload(
                                method(_preload_content=False, **list_kwargs)
                            )
                            items = [self._safe_asset(item) for item in raw_items]
                        else:
                            response = method(**list_kwargs)
                            resource_version = str(
                                getattr(getattr(response, "metadata", None), "resource_version", "") or ""
                            )
                            items = [self._safe_asset(item) for item in list(getattr(response, "items", []) or [])]
                        callback("RELIST", {
                            "api_version": api_version, "kind": kind, "items": items,
                            "scope_namespace": namespace,
                        })
                    report(key, "RUNNING", active=True)
                    watch_kwargs: dict[str, Any] = {
                        "timeout_seconds": 30, "resource_version": resource_version,
                        "_request_timeout": 40,
                    }
                    if namespace:
                        watch_kwargs["namespace"] = namespace
                    for event in watcher.stream(method, **watch_kwargs):
                        if stop_event.is_set():
                            watcher.stop()
                            break
                        raw = event.get("object")
                        event_type = str(event.get("type") or "")
                        if raw is None:
                            report(key, "RUNNING", active=True)
                            continue
                        asset = self._safe_asset(raw)
                        resource_version = str(asset.get("resource_version") or resource_version)
                        if event_type in {"ADDED", "MODIFIED", "DELETED"}:
                            callback(event_type, asset)
                            report(key, "RUNNING", changed=True, active=True)
                        else:
                            report(key, "RUNNING", active=True)
                    # A normal server timeout is a valid heartbeat, not a failure.
                    report(key, "RUNNING", active=True)
                    backoff = 1
                except Exception as exc:
                    report(key, "DEGRADED", error_code=safe_error_code(exc), active=False, restart=True)
                    resource_version = "" if getattr(exc, "status", None) == 410 else resource_version
                    stop_event.wait(backoff)
                    backoff = min(30, backoff * 2)
                finally:
                    watcher.stop()
            report(key, "STOPPED", active=False)

        scopes: list[tuple[str, str, str | None]] = []
        for api_version, kind in self.RESOURCES:
            _, _, namespaced_method_name = self._WATCH_METHODS[(api_version, kind)]
            if namespaced_method_name and cluster.namespace_allowlist:
                scopes.extend((api_version, kind, namespace) for namespace in cluster.namespace_allowlist)
            else:
                scopes.append((api_version, kind, None))
        threads = [
            threading.Thread(target=watch_resource, args=item, daemon=True,
                             name=f"k8s-watch-{item[1].lower()}-{item[2] or 'all'}")
            for item in scopes
        ]
        for thread in threads:
            thread.start()
        while not stop_event.wait(1):
            pass
        for thread in threads:
            thread.join(timeout=2)

    def capabilities(self, cluster: ClusterConfig) -> list[dict[str, Any]]:
        result = [{"name": "kubernetes_api", "status": "AVAILABLE", "detail": "read-only API reachable"}]
        try:
            self.current_metrics(cluster, {"resource_type": "node"})
            result.append({"name": "metrics_api", "status": "AVAILABLE", "detail": "metrics.k8s.io reachable"})
        except KubernetesBoundaryError as exc:
            status = "UNAUTHORIZED" if "UNAUTHORIZED" in exc.code else "MISSING"
            result.append({"name": "metrics_api", "status": status, "detail": exc.code})
        configured = {
            "vmp_workspace": bool(cluster.vmp.get("region") and cluster.vmp.get("workspace_id")),
            "tls_logs": bool(cluster.tls.get("region") and cluster.tls.get("log_topic_id")),
            "tls_events": bool(cluster.tls.get("region") and cluster.tls.get("event_topic_id")),
        }
        result.extend({"name": name, "status": "AVAILABLE" if ok else "MISCONFIGURED", "detail": "configured" if ok else "local configuration incomplete"} for name, ok in configured.items())
        addon_names = ("prometheus-agent", "log-collector", "event-collector", "node-problem-detector")
        try:
            _, api_client, _ = self._apis(cluster)
            from kubernetes import client
            pods = client.CoreV1Api(api_client).list_pod_for_all_namespaces().items
            names = {str(p.metadata.name) for p in pods}
            result.extend({"name": addon, "status": "AVAILABLE" if any(addon in name for name in names) else "MISSING", "detail": "detected" if any(addon in name for name in names) else "installation required for this capability"} for addon in addon_names)
        except Exception:
            result.extend({"name": addon, "status": "UNREACHABLE", "detail": "add-on probe failed"} for addon in addon_names)
        return result

    def current_metrics(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        client, api_client, _ = self._apis(cluster)
        plural = "nodes" if query["resource_type"] == "node" else "pods"
        try:
            response = client.CustomObjectsApi(api_client).list_cluster_custom_object("metrics.k8s.io", "v1beta1", plural)
        except Exception as exc:
            code = "METRICS_UNAUTHORIZED" if getattr(exc, "status", None) == 403 else "METRICS_MISSING"
            raise KubernetesBoundaryError(code, "Metrics API query failed", status=503) from exc
        items = response.get("items", [])
        namespace = query.get("namespace")
        if namespace:
            items = [item for item in items if item.get("metadata", {}).get("namespace") == namespace]
        return {"resource_type": query["resource_type"], "items": items[:1000]}

    def current_logs(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        client, api_client, _ = self._apis(cluster)
        try:
            text = client.CoreV1Api(api_client).read_namespaced_pod_log(
                query["pod"], query["namespace"], container=query["container"],
                previous=query.get("previous", False), tail_lines=query.get("tail_lines", 500),
                timestamps=True, _preload_content=True,
            )
        except Exception as exc:
            raise KubernetesBoundaryError("LOG_QUERY_FAILED", "pod log query failed", status=503, retriable=True) from exc
        raw = str(text).encode("utf-8")[: 2 * 1024 * 1024]
        rendered = _redact(raw.decode("utf-8", errors="replace"))
        return {"lines": rendered.splitlines()[:2000], "bytes": len(raw), "previous": query.get("previous", False)}

    def collect_logs(
        self, cluster: ClusterConfig, *, since_seconds: int, timeout: int, concurrency: int,
        all_namespaces: bool,
    ) -> list[dict[str, Any]]:
        client, api_client, _ = self._apis(cluster)
        api = client.CoreV1Api(api_client)
        try:
            pods = api.list_pod_for_all_namespaces(_request_timeout=timeout).items
        except Exception as exc:
            raise KubernetesBoundaryError(
                "LOG_DISCOVERY_FAILED", "pod discovery for log collection failed",
                status=503, retriable=True,
            ) from exc
        requests: list[tuple[Any, str, bool]] = []
        for pod in pods:
            if not all_namespaces and cluster.namespace_allowlist and pod.metadata.namespace not in cluster.namespace_allowlist:
                continue
            if str(getattr(pod.status, "phase", "")) != "Running":
                continue
            statuses = list(getattr(pod.status, "container_statuses", None) or [])
            statuses += list(getattr(pod.status, "init_container_statuses", None) or [])
            ephemeral = list(getattr(pod.status, "ephemeral_container_statuses", None) or [])
            for status in statuses + ephemeral:
                name = str(getattr(status, "name", "") or "")
                if name:
                    requests.append((pod, name, False))
                restart_count = int(getattr(status, "restart_count", 0) or 0)
                restart_key = (cluster.id, str(pod.metadata.uid), name)
                with self._log_restart_lock:
                    known_restart_count = restart_key in self._log_restart_counts
                    previous_count = self._log_restart_counts.get(restart_key, 0)
                    self._log_restart_counts[restart_key] = restart_count
                if name and known_restart_count and restart_count > previous_count:
                    requests.append((pod, name, True))

        def read(item: tuple[Any, str, bool]) -> dict[str, Any] | None:
            pod, container, previous = item
            try:
                value = api.read_namespaced_pod_log(
                    pod.metadata.name, pod.metadata.namespace, container=container,
                    previous=previous, since_seconds=max(1, since_seconds), timestamps=True,
                    _request_timeout=timeout, _preload_content=True,
                )
            except Exception:
                return None
            text = _redact(str(value))
            if not text:
                return None
            encoded = text.encode("utf-8")[:64 * 1024]
            rendered = encoded.decode("utf-8", errors="replace")
            now = _utcnow()
            return {
                "pod_uid": str(pod.metadata.uid), "pod": str(pod.metadata.name),
                "namespace": str(pod.metadata.namespace), "container": container,
                "previous": previous, "content": rendered,
                "bytes": len(encoded), "started_at": now, "ended_at": now,
                "observed_at": now,
            }

        rows: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            futures = [pool.submit(read, request) for request in requests]
            for future in as_completed(futures):
                row = future.result()
                if row:
                    rows.append(row)
        return rows

    def current_events(self, cluster: ClusterConfig, query: dict[str, Any]) -> dict[str, Any]:
        client, api_client, _ = self._apis(cluster)
        api = client.CoreV1Api(api_client)
        namespace = query.get("namespace")
        try:
            response = api.list_namespaced_event(namespace) if namespace else api.list_event_for_all_namespaces()
        except Exception as exc:
            raise KubernetesBoundaryError("EVENT_QUERY_FAILED", "event query failed", status=503, retriable=True) from exc
        source_items = list(response.items)
        items = []
        for event in source_items[:500]:
            items.append({
                "namespace": event.metadata.namespace,
                "event_uid": str(event.metadata.uid or ""),
                "type": event.type,
                "reason": event.reason,
                "message": _redact(str(event.message or ""))[:2000],
                "count": event.count,
                "object": {"kind": event.involved_object.kind, "name": event.involved_object.name, "uid": event.involved_object.uid},
                "last_timestamp": str(
                    event.last_timestamp
                    or event.event_time
                    or getattr(event, "deprecated_last_timestamp", None)
                    or ""
                ),
                "first_timestamp": str(getattr(event, "first_timestamp", None) or ""),
            })
        return {"items": items, "truncated": len(source_items) > len(items)}

    def watch_events(self, cluster: ClusterConfig, stop_event: threading.Event, callback) -> None:
        """Watch Kubernetes Events and resume from the latest resourceVersion."""
        client, api_client, _ = self._apis(cluster)
        from kubernetes import watch

        api = client.CoreV1Api(api_client)
        resource_version = ""
        def safe_event(event) -> dict[str, Any]:
            return {
                "namespace": event.metadata.namespace,
                "event_uid": str(event.metadata.uid or ""),
                "type": event.type,
                "reason": event.reason,
                "message": _redact(str(event.message or ""))[:2000],
                "count": event.count,
                "object": {
                    "kind": event.involved_object.kind,
                    "name": event.involved_object.name,
                    "uid": event.involved_object.uid,
                },
                "last_timestamp": str(
                    event.last_timestamp
                    or event.event_time
                    or getattr(event, "deprecated_last_timestamp", None)
                    or ""
                ),
                "first_timestamp": str(getattr(event, "first_timestamp", None) or ""),
            }
        while not stop_event.is_set():
            watcher = watch.Watch()
            try:
                kwargs: dict[str, Any] = {"timeout_seconds": 30}
                if resource_version:
                    kwargs["resource_version"] = resource_version
                for change in watcher.stream(api.list_event_for_all_namespaces, **kwargs):
                    if stop_event.is_set():
                        watcher.stop()
                        break
                    event = change.get("object")
                    if event is None or str(change.get("type") or "") == "DELETED":
                        continue
                    resource_version = str(getattr(event.metadata, "resource_version", "") or resource_version)
                    callback(safe_event(event))
            except Exception as exc:
                if getattr(exc, "status", None) == 410:
                    resource_version = ""
                    try:
                        response = api.list_event_for_all_namespaces()
                        resource_version = str(getattr(response.metadata, "resource_version", "") or "")
                        for event in response.items:
                            callback(safe_event(event))
                    except Exception:
                        pass
                stop_event.wait(1)
            finally:
                watcher.stop()


@dataclass
class SyncJob:
    id: str
    cluster_id: str
    cluster_uid: str
    status: str = "PENDING"
    assets: list[dict[str, Any]] = field(default_factory=list)
    error_code: str | None = None
    created_at: str = field(default_factory=_utcnow)
    finished_at: str | None = None


@dataclass
class CollectionItem:
    sequence: int
    value: dict[str, Any]
    size: int


class CollectionStream:
    """Bounded, process-local stream. Overflow is explicit and never hidden."""

    def __init__(self, maximum_bytes: int):
        self.maximum_bytes = maximum_bytes
        self.items: deque[CollectionItem] = deque()
        self.next_sequence = 1
        self.bytes = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def append(self, value: dict[str, Any]) -> int:
        size = len(_canonical(value))
        with self._lock:
            sequence = self.next_sequence
            self.next_sequence += 1
            item = CollectionItem(sequence, value, size)
            self.items.append(item)
            self.bytes += size
            while self.items and self.bytes > self.maximum_bytes:
                removed = self.items.popleft()
                self.bytes -= removed.size
                self.dropped += 1
            return sequence

    def read(self, after: int, *, limit: int, maximum_bytes: int) -> dict[str, Any]:
        with self._lock:
            available = list(self.items)
            oldest = available[0].sequence if available else self.next_sequence
            selected: list[dict[str, Any]] = []
            used = 0
            for item in available:
                if item.sequence <= after:
                    continue
                if len(selected) >= limit or used + item.size > maximum_bytes:
                    break
                selected.append({"sequence": item.sequence, **item.value})
                used += item.size
            last = selected[-1]["sequence"] if selected else after
            return {
                "items": selected,
                "next_sequence": last,
                "oldest_sequence": oldest,
                "gap": after < oldest - 1,
                "dropped": self.dropped,
                "queue_bytes": self.bytes,
            }

    def skip_to_latest(self, after: int) -> dict[str, Any]:
        """Advance a consumer without returning payloads (used after log quota exhaustion)."""
        with self._lock:
            oldest = self.items[0].sequence if self.items else self.next_sequence
            latest = self.next_sequence - 1
            return {
                "items": [], "next_sequence": max(after, latest),
                "oldest_sequence": oldest,
                "gap": False,
                "dropped": self.dropped, "queue_bytes": self.bytes,
                "quota_skipped": max(0, latest - after),
            }


class ClusterCollector:
    """Continuously projects current resources and bounded event/log deltas."""

    def __init__(self, service: "KubernetesService", cluster: ClusterConfig):
        self.service = service
        self.cluster = cluster
        self.epoch = str(uuid.uuid4())
        maximum = max(16, int(service.cfg.collection_memory_limit_mb)) * 1024 * 1024
        self.streams = {
            "resources": CollectionStream(maximum // 2),
            "events": CollectionStream(maximum // 8),
            "logs": CollectionStream(maximum - (maximum // 2 + maximum // 8)),
        }
        self.current: dict[str, dict[str, Any]] = {}
        self.raw_current: dict[str, dict[str, Any]] = {}
        self.current_lock = threading.Lock()
        self.last_success: dict[str, str | None] = {name: None for name in self.streams}
        self.last_error: dict[str, str | None] = {name: None for name in self.streams}
        self.watch_lock = threading.Lock()
        self.watchers: dict[str, dict[str, Any]] = {}
        self.expected_watchers = 0
        self.last_auto_reconcile = 0.0
        self.last_reconcile_at: str | None = None
        self.started_at = _utcnow()
        self.stop_event = threading.Event()
        self.reconcile_requested = threading.Event()
        self._event_keys: set[str] = set()
        self._log_keys: set[str] = set()
        self.thread = threading.Thread(target=self._run, daemon=True, name=f"k8s-collector-{cluster.id}")
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _collect_resources(self, *, baseline: bool = False) -> None:
        baseline_id = str(uuid.uuid4()) if baseline else None
        baseline_at = _utcnow()
        raw = self.service.client.assets(self.cluster)
        assets, _ = _exclude_scaled_to_zero_assets(raw)
        incoming = {str(item.get("uid") or ""): item for item in assets if item.get("uid")}
        with self.current_lock:
            self.raw_current = {str(item.get("uid") or ""): item for item in raw if item.get("uid")}
            self._replace_projection(
                incoming, baseline=baseline, baseline_id=baseline_id,
                observed_at=baseline_at,
            )
            if baseline:
                self.streams["resources"].append({
                    "change_type": "BASELINE_COMPLETE",
                    "baseline_id": baseline_id,
                    "expected_count": len(incoming),
                    "observed_at": baseline_at,
                })
        self.last_success["resources"] = _utcnow()
        self.last_error["resources"] = None
        if baseline:
            self.last_reconcile_at = self.last_success["resources"]

    def _replace_projection(
        self, incoming: dict[str, dict[str, Any]], *, baseline: bool = False,
        baseline_id: str | None = None, observed_at: str | None = None,
    ) -> None:
        observed_at = observed_at or _utcnow()
        for uid, asset in incoming.items():
            previous = self.current.get(uid)
            if baseline or previous is None or _fingerprint(previous) != _fingerprint(asset):
                self.streams["resources"].append({
                    "change_type": "BASELINE" if baseline else ("ADDED" if previous is None else "MODIFIED"),
                    "asset": asset, "observed_at": observed_at,
                    **({"baseline_id": baseline_id} if baseline_id else {}),
                })
        for uid, asset in list(self.current.items()):
            if uid not in incoming:
                self.streams["resources"].append({
                    "change_type": "DELETED", "asset": asset, "observed_at": observed_at
                })
        self.current = incoming

    def _watch_change(self, event_type: str, asset: dict[str, Any]) -> None:
        if event_type == "RELIST":
            api_version = str(asset.get("api_version") or "")
            kind = str(asset.get("kind") or "")
            scope_namespace = asset.get("scope_namespace")
            items = asset.get("items") if isinstance(asset.get("items"), list) else []
            with self.current_lock:
                self.raw_current = {
                    uid: current for uid, current in self.raw_current.items()
                    if not (
                        str(current.get("api_version") or "") == api_version
                        and str(current.get("kind") or "") == kind
                        and (scope_namespace is None or current.get("namespace") == scope_namespace)
                    )
                }
                self.raw_current.update({
                    str(item.get("uid") or ""): item for item in items
                    if isinstance(item, dict) and item.get("uid")
                })
                filtered, _ = _exclude_scaled_to_zero_assets(list(self.raw_current.values()))
                incoming = {str(item.get("uid") or ""): item for item in filtered if item.get("uid")}
                self._replace_projection(incoming)
                self.last_success["resources"] = _utcnow()
                self.last_error["resources"] = None
            return
        uid = str(asset.get("uid") or "")
        if not uid:
            return
        with self.current_lock:
            if event_type == "DELETED":
                self.raw_current.pop(uid, None)
            else:
                self.raw_current[uid] = asset
            filtered, _ = _exclude_scaled_to_zero_assets(list(self.raw_current.values()))
            incoming = {str(item.get("uid") or ""): item for item in filtered if item.get("uid")}
            self._replace_projection(incoming)
            self.last_success["resources"] = _utcnow()
            self.last_error["resources"] = None

    def _watch_health(self, key: str, state: str, details: dict[str, Any]) -> None:
        """Receive non-resource Watch state without treating it as an asset."""
        heartbeat = str(details.get("heartbeat_at") or _utcnow())
        with self.watch_lock:
            item = self.watchers.setdefault(key, {"restart_count": 0})
            item["state"] = state
            item["active"] = bool(details.get("active"))
            item["last_heartbeat_at"] = heartbeat
            if details.get("changed"):
                item["last_change_at"] = heartbeat
            if details.get("restart"):
                item["restart_count"] = int(item.get("restart_count") or 0) + 1
            if details.get("error_code"):
                item["last_error_code"] = str(details["error_code"])
            elif state == "RUNNING":
                item["last_error_code"] = None
        if state == "RUNNING":
            self.last_success["resources"] = heartbeat
        elif state in {"DEGRADED", "STOPPED"} and details.get("error_code"):
            self.last_error["resources"] = str(details["error_code"])

    def _resource_watch_status(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        lock = getattr(self, "watch_lock", None)
        if lock is None:
            values = []
            expected = 0
        else:
            with lock:
                values = [dict(value) for value in self.watchers.values()]
                expected = self.expected_watchers
        heartbeats = [_timestamp(value.get("last_heartbeat_at")) for value in values]
        heartbeats = [value for value in heartbeats if value is not None]
        last_heartbeat = max(heartbeats).isoformat().replace("+00:00", "Z") if heartbeats else None
        changes = [_timestamp(value.get("last_change_at")) for value in values]
        changes = [value for value in changes if value is not None]
        last_change = max(changes).isoformat().replace("+00:00", "Z") if changes else None
        active = sum(1 for value in values if value.get("active"))
        stale = (
            expected <= 0 or active < expected
            or not heartbeats or (now - max(heartbeats)).total_seconds() > 60
        )
        if not values:
            state = "STOPPED"
        elif stale:
            state = "STOPPED" if active == 0 else "DEGRADED"
        elif any(value.get("state") != "RUNNING" for value in values):
            state = "DEGRADED"
        else:
            state = "RUNNING"
        error = next((str(value["last_error_code"]) for value in values if value.get("last_error_code")), None)
        return {
            "state": state, "last_heartbeat_at": last_heartbeat,
            "last_change_at": last_change, "expected_watchers": expected,
            "active_watchers": active, "last_error_code": error,
            "restart_count": sum(int(value.get("restart_count") or 0) for value in values),
        }

    def _supervise_watches(self, now: float) -> None:
        status = self._resource_watch_status()
        if status["state"] == "RUNNING":
            return
        self.last_error["resources"] = status.get("last_error_code") or "RESOURCE_WATCH_STALE"
        if now - getattr(self, "last_auto_reconcile", 0.0) >= 300:
            self.last_auto_reconcile = now
            self.reconcile_requested.set()

    def _collect_events(self) -> None:
        result = self.service.client.current_events(self.cluster, {})
        for event in result.get("items", []):
            key = str(event.get("event_uid") or "")[:128] or _fingerprint({
                "namespace": event.get("namespace"), "object": event.get("object"),
                "reason": event.get("reason"), "first_timestamp": event.get("first_timestamp"),
            })
            version_key = _fingerprint({"uid": key, "count": event.get("count"), "last": event.get("last_timestamp")})
            if version_key not in self._event_keys:
                self.streams["events"].append({"event_uid": key, "event": event, "observed_at": _utcnow()})
                self._event_keys.add(version_key)
        if len(self._event_keys) > 10000:
            self._event_keys.clear()
        self.last_success["events"] = _utcnow()
        self.last_error["events"] = None

    def _watch_event(self, event: dict[str, Any]) -> None:
        self._record_event(event)
        self.last_success["events"] = _utcnow()
        self.last_error["events"] = None

    def _record_event(self, event: dict[str, Any]) -> None:
        key = str(event.get("event_uid") or "")[:128] or _fingerprint({
            "namespace": event.get("namespace"), "object": event.get("object"),
            "reason": event.get("reason"), "first_timestamp": event.get("first_timestamp"),
        })
        version_key = _fingerprint({"uid": key, "count": event.get("count"), "last": event.get("last_timestamp")})
        if version_key not in self._event_keys:
            self.streams["events"].append({"event_uid": key, "event": event, "observed_at": _utcnow()})
            self._event_keys.add(version_key)

    def _collect_logs(self, since_seconds: int) -> None:
        collect = getattr(self.service.client, "collect_logs", None)
        if collect is None:
            self.last_success["logs"] = _utcnow()
            return
        rows = collect(
            self.cluster, since_seconds=since_seconds,
            timeout=int(self.service.cfg.log_request_timeout_sec),
            concurrency=int(self.service.cfg.log_collection_concurrency),
            all_namespaces=bool(self.service.cfg.log_all_namespaces),
        )
        for row in rows:
            novel = []
            for line in str(row.get("content") or "").splitlines():
                key = _fingerprint({
                    "pod_uid": row.get("pod_uid"), "container": row.get("container"),
                    "previous": row.get("previous"), "line": line,
                })
                if key not in self._log_keys:
                    self._log_keys.add(key)
                    novel.append(line)
            if novel:
                row["content"] = "\n".join(novel)
                row["bytes"] = len(row["content"].encode("utf-8"))
                row["fingerprint"] = _fingerprint({
                    "pod_uid": row.get("pod_uid"), "container": row.get("container"),
                    "previous": row.get("previous"), "content": row.get("content"),
                })
                self.streams["logs"].append(row)
        if len(self._log_keys) > 100000:
            self._log_keys.clear()
        self.last_success["logs"] = _utcnow()
        self.last_error["logs"] = None

    def _run(self) -> None:
        interval = max(5, int(self.service.cfg.collection_interval_sec))
        reconcile_interval = max(300, int(self.service.cfg.reconcile_interval_sec))
        last_reconcile = 0.0
        first = True
        watcher = None
        event_watcher = None
        while not self.stop_event.is_set():
            started = time.monotonic()
            reconcile = first or self.reconcile_requested.is_set() or started - last_reconcile >= reconcile_interval
            if reconcile or not hasattr(self.service.client, "watch_assets"):
                try:
                    self._collect_resources(baseline=reconcile)
                    if reconcile:
                        last_reconcile = started
                        self.reconcile_requested.clear()
                except KubernetesBoundaryError as exc:
                    self.last_error["resources"] = exc.code
                except Exception:
                    self.last_error["resources"] = "RESOURCE_COLLECTION_FAILED"
            if first and hasattr(self.service.client, "watch_assets"):
                self.expected_watchers = (
                    len(getattr(self.service.client, "RESOURCES", ())) if not self.cluster.namespace_allowlist
                    else sum(
                        len(self.cluster.namespace_allowlist) if spec[2] else 1
                        for spec in getattr(self.service.client, "_WATCH_METHODS", {}).values()
                    )
                )
                watcher = threading.Thread(
                    target=self.service.client.watch_assets,
                    args=(self.cluster, self.stop_event, self._watch_change, self._watch_health), daemon=True,
                )
                watcher.start()
            elif watcher is not None and not watcher.is_alive():
                # The adapter normally retains its own Kind workers alive. This
                # guards a fatal outer-thread error so it cannot remain dead
                # until the six-hour scheduled reconciliation.
                watcher = threading.Thread(
                    target=self.service.client.watch_assets,
                    args=(self.cluster, self.stop_event, self._watch_change, self._watch_health), daemon=True,
                )
                watcher.start()
            if first and hasattr(self.service.client, "watch_events"):
                event_watcher = threading.Thread(
                    target=self.service.client.watch_events,
                    args=(self.cluster, self.stop_event, self._watch_event), daemon=True,
                )
                event_watcher.start()
            if first or not hasattr(self.service.client, "watch_events"):
                try:
                    self._collect_events()
                except KubernetesBoundaryError as exc:
                    self.last_error["events"] = exc.code
                except Exception:
                    self.last_error["events"] = "EVENT_COLLECTION_FAILED"
            try:
                self._collect_logs(60 if first else interval + 5)
            except KubernetesBoundaryError as exc:
                self.last_error["logs"] = exc.code
            except Exception:
                self.last_error["logs"] = "LOG_COLLECTION_FAILED"
            self._supervise_watches(started)
            first = False
            self.stop_event.wait(max(0.1, interval - (time.monotonic() - started)))
        if watcher is not None:
            watcher.join(timeout=2)
        if event_watcher is not None:
            event_watcher.join(timeout=2)

    def status(self) -> dict[str, Any]:
        status = self._resource_watch_status()
        return {
            "epoch": self.epoch, "started_at": self.started_at,
            "streams": {
                name: {
                    "last_success_at": self.last_success[name],
                    "last_error_code": self.last_error[name],
                    "queue_bytes": stream.bytes, "dropped": stream.dropped,
                    "next_sequence": stream.next_sequence,
                    **(status if name == "resources" else {}),
                }
                for name, stream in self.streams.items()
            },
            "last_reconcile_at": getattr(self, "last_reconcile_at", None),
        }


class KubernetesService:
    def __init__(self, cfg, runner_instance_id: str, *, client: ClusterClient | None = None, history: HistoryClient | None = None):
        self.cfg = cfg
        self.runner_instance_id = runner_instance_id
        self.inventory = KubernetesInventory(cfg.inventory_file)
        self.client = client or OfficialKubernetesClient()
        self.history = history or VolcengineHistoryClient()
        self._jobs: dict[str, SyncJob] = {}
        self._lock = threading.Lock()
        self._metric_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._collectors: dict[str, ClusterCollector] = {}
        os.makedirs(cfg.state_dir, exist_ok=True)
        self._recover_jobs()
        if getattr(cfg, "continuous_collection_enabled", False):
            for cluster in self._clusters().values():
                self._collectors[cluster.id] = ClusterCollector(self, cluster)

    def close(self) -> None:
        for collector in self._collectors.values():
            collector.close()

    def _collector(self, cluster: ClusterConfig) -> ClusterCollector:
        collector = self._collectors.get(cluster.id)
        if collector is None:
            raise KubernetesBoundaryError(
                "CONTINUOUS_COLLECTION_DISABLED", "continuous collection is disabled",
                status=503,
            )
        return collector

    def collection_status(self, cluster_id: str) -> dict[str, Any]:
        cluster = self._cluster(cluster_id)
        identity = self._identity(cluster)
        return self._envelope(cluster, identity, self._collector(cluster).status())

    def collection_reconcile(self, body: bytes) -> dict[str, Any]:
        request = _decode(body)
        _only_fields(request, {"runner_cluster_id", "expected_cluster_uid"})
        cluster = self._cluster(_bounded_string(request.get("runner_cluster_id"), "runner_cluster_id"))
        identity = self._identity(cluster)
        if identity["cluster_uid"] != _bounded_string(request.get("expected_cluster_uid"), "expected_cluster_uid"):
            raise KubernetesBoundaryError("CLUSTER_UID_CHANGED", "cluster UID changed; re-enrollment required", status=409)
        collector = self._collector(cluster)
        collector.reconcile_requested.set()
        return self._envelope(cluster, identity, {"accepted": True, "epoch": collector.epoch})

    def collection_pull(self, body: bytes) -> dict[str, Any]:
        request = _decode(body)
        _only_fields(request, {
            "runner_cluster_id", "expected_cluster_uid", "expected_runner_instance_id",
            "epoch", "sequences", "remaining_log_bytes", "limit",
        })
        cluster = self._cluster(_bounded_string(request.get("runner_cluster_id"), "runner_cluster_id"))
        identity = self._identity(cluster)
        if identity["cluster_uid"] != _bounded_string(request.get("expected_cluster_uid"), "expected_cluster_uid"):
            raise KubernetesBoundaryError("CLUSTER_UID_CHANGED", "cluster UID changed; re-enrollment required", status=409)
        if _bounded_string(request.get("expected_runner_instance_id"), "expected_runner_instance_id", maximum=64) != self.runner_instance_id:
            raise KubernetesBoundaryError("RUNNER_INSTANCE_CHANGED", "runner instance changed", status=409)
        collector = self._collector(cluster)
        sequences = request.get("sequences") or {}
        if not isinstance(sequences, dict):
            raise KubernetesBoundaryError("INVALID_FILTER", "sequences must be an object")
        try:
            limit = min(1000, max(1, int(request.get("limit", 500))))
            remaining = max(0, int(request.get("remaining_log_bytes", 0)))
        except (TypeError, ValueError) as exc:
            raise KubernetesBoundaryError("INVALID_FILTER", "collection limits are invalid") from exc
        result = {"epoch": collector.epoch, "status": collector.status(), "streams": {}}
        for name, stream in collector.streams.items():
            after = int(sequences.get(name, 0) or 0)
            if name == "logs" and remaining <= 0:
                result["streams"][name] = stream.skip_to_latest(after)
                continue
            maximum = min(2 * 1024 * 1024, remaining) if name == "logs" else 2 * 1024 * 1024
            result["streams"][name] = stream.read(after, limit=limit, maximum_bytes=maximum)
        return self._envelope(cluster, identity, result, truncated=any(
            len(value["items"]) >= limit for value in result["streams"].values()
        ))

    def _clusters(self) -> dict[str, ClusterConfig]:
        return self.inventory.load()

    def _cluster(self, cluster_id: str) -> ClusterConfig:
        cluster = self._clusters().get(cluster_id)
        if not cluster:
            raise KubernetesBoundaryError("CLUSTER_NOT_FOUND", "cluster not found", status=404)
        return cluster

    def _identity(self, cluster: ClusterConfig) -> dict[str, Any]:
        identity = self.client.identity(cluster)
        if not identity.get("cluster_uid"):
            raise KubernetesBoundaryError("CLUSTER_IDENTITY_INVALID", "cluster UID is unavailable", status=503)
        return identity

    def _envelope(self, cluster: ClusterConfig, identity: dict[str, Any], data: Any, *, truncated: bool = False) -> dict[str, Any]:
        envelope = {
            "protocol_version": PROTOCOL_VERSION,
            "runner_instance_id": self.runner_instance_id,
            "runner_cluster_id": cluster.id,
            "cluster_uid": identity["cluster_uid"],
            "generated_at": _utcnow(),
            "truncated": bool(truncated),
            "data": data,
        }
        envelope["content_fingerprint"] = _fingerprint(envelope)
        return envelope

    def clusters(self) -> dict[str, Any]:
        rows = []
        for cluster in self._clusters().values():
            identity = self._identity(cluster)
            capabilities = self.client.capabilities(cluster)
            if hasattr(self.history, "capabilities"):
                provider = {item["name"]: item for item in self.history.capabilities(cluster)}
                capabilities = [provider.get(item["name"], item) for item in capabilities]
            rows.append({
                "runner_cluster_id": cluster.id, "display_name": cluster.display_name,
                "environment": cluster.environment, **identity,
                "capabilities": capabilities,
            })
        return {"protocol_version": PROTOCOL_VERSION, "runner_instance_id": self.runner_instance_id, "generated_at": _utcnow(), "clusters": rows, "content_fingerprint": _fingerprint(rows)}

    def start_sync(self, body: bytes) -> dict[str, Any]:
        request = _decode(body)
        _only_fields(request, {"runner_cluster_id", "expected_cluster_uid", "idempotency_key"})
        cluster = self._cluster(_bounded_string(request.get("runner_cluster_id"), "runner_cluster_id"))
        identity = self._identity(cluster)
        expected = _bounded_string(request.get("expected_cluster_uid"), "expected_cluster_uid")
        if identity["cluster_uid"] != expected:
            raise KubernetesBoundaryError("CLUSTER_UID_CHANGED", "cluster UID changed; re-enrollment required", status=409)
        idem = _bounded_string(request.get("idempotency_key"), "idempotency_key", maximum=128)
        job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{self.runner_instance_id}:{cluster.id}:{idem}"))
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                job = SyncJob(job_id, cluster.id, identity["cluster_uid"])
                self._jobs[job_id] = job
                self._persist_job(job)
                threading.Thread(target=self._run_sync, args=(job, cluster), daemon=True).start()
        return self._envelope(cluster, identity, {"sync_id": job.id, "status": job.status})

    def _run_sync(self, job: SyncJob, cluster: ClusterConfig) -> None:
        job.status = "RUNNING"
        self._persist_job(job)
        try:
            collected = self.client.assets(cluster)
            job.assets, _ = _exclude_scaled_to_zero_assets(collected)
            job.status = "SUCCEEDED"
        except KubernetesBoundaryError as exc:
            job.error_code = exc.code
            job.status = "FAILED"
        except Exception:
            job.error_code = "SYNC_FAILED"
            job.status = "FAILED"
        job.finished_at = _utcnow()
        self._persist_job(job)

    def sync_status(self, sync_id: str) -> dict[str, Any]:
        job = self._job(sync_id)
        cluster = self._cluster(job.cluster_id)
        identity = {"cluster_uid": job.cluster_uid}
        return self._envelope(cluster, identity, {"sync_id": job.id, "status": job.status, "asset_count": len(job.assets), "error_code": job.error_code, "created_at": job.created_at, "finished_at": job.finished_at})

    def sync_assets(self, sync_id: str, cursor: str | None) -> dict[str, Any]:
        job = self._job(sync_id)
        if job.status != "SUCCEEDED":
            raise KubernetesBoundaryError("SYNC_NOT_COMPLETE", "sync is not complete", status=409)
        offset = 0
        if cursor:
            try:
                offset = int(base64.urlsafe_b64decode(cursor + "===").decode())
            except Exception as exc:
                raise KubernetesBoundaryError("CURSOR_INVALID", "cursor is invalid") from exc
        page = job.assets[offset:offset + 500]
        next_cursor = base64.urlsafe_b64encode(str(offset + len(page)).encode()).decode().rstrip("=") if offset + len(page) < len(job.assets) else None
        cluster = self._cluster(job.cluster_id)
        return self._envelope(cluster, {"cluster_uid": job.cluster_uid}, {"sync_id": job.id, "items": page, "next_cursor": next_cursor, "total": len(job.assets)}, truncated=next_cursor is not None)

    def cancel_sync(self, sync_id: str) -> dict[str, Any]:
        job = self._job(sync_id)
        if job.status in {"PENDING", "RUNNING"}:
            job.status = "CANCELLED"
            job.finished_at = _utcnow()
            self._persist_job(job)
        return self.sync_status(sync_id)

    def _object_request(
        self, request: dict[str, Any], cluster: ClusterConfig
    ) -> dict[str, Any]:
        raw = request.get("object")
        required = {"api_version", "kind", "namespace", "name", "uid"}
        if not isinstance(raw, dict) or set(raw) != required:
            raise KubernetesBoundaryError(
                "INVALID_OBJECT_REF",
                "object must contain exactly api_version, kind, namespace, name, and uid",
            )
        kind = _bounded_string(raw.get("kind"), "object.kind", maximum=64)
        allowed_kinds = {
            "Node", "Namespace", "Deployment", "StatefulSet", "DaemonSet",
            "Job", "CronJob", "Pod", "Service", "Ingress",
            "PersistentVolumeClaim", "PersistentVolume", "StorageClass",
            "HorizontalPodAutoscaler", "PodDisruptionBudget", "ResourceQuota",
            "LimitRange",
        }
        if kind not in allowed_kinds:
            raise KubernetesBoundaryError(
                "OBJECT_KIND_UNSUPPORTED", "object kind is not supported", status=400
            )
        namespace = _bounded_string(
            raw.get("namespace"), "object.namespace", required=False
        )
        if (
            namespace
            and cluster.namespace_allowlist
            and namespace not in cluster.namespace_allowlist
        ):
            raise KubernetesBoundaryError(
                "NAMESPACE_NOT_ALLOWED",
                "namespace is outside the runner allowlist",
                status=403,
            )
        return {
            "api_version": _bounded_string(
                raw.get("api_version"), "object.api_version", maximum=128
            ),
            "kind": kind,
            "namespace": namespace or None,
            "name": _bounded_string(raw.get("name"), "object.name"),
            "uid": _bounded_string(raw.get("uid"), "object.uid", maximum=128),
        }

    @staticmethod
    def _resolve_object(
        ref: dict[str, Any], assets: list[dict[str, Any]]
    ) -> dict[str, Any]:
        matching_name = [
            asset
            for asset in assets
            if asset.get("kind") == ref["kind"]
            and (asset.get("namespace") or None) == ref["namespace"]
            and asset.get("name") == ref["name"]
        ]
        exact = next(
            (asset for asset in matching_name if asset.get("uid") == ref["uid"]), None
        )
        if exact is not None:
            return exact
        if matching_name:
            raise KubernetesBoundaryError(
                "OBJECT_UID_CHANGED",
                "object UID changed; refresh the resource page",
                status=409,
            )
        raise KubernetesBoundaryError(
            "OBJECT_NOT_FOUND", "object was not found", status=404
        )

    @staticmethod
    def _descendant_uids(
        parent: dict[str, Any], assets: list[dict[str, Any]]
    ) -> set[str]:
        discovered = {str(parent.get("uid") or "")}
        changed = True
        while changed:
            changed = False
            for asset in assets:
                uid = str(asset.get("uid") or "")
                if not uid or uid in discovered:
                    continue
                owners = (
                    asset.get("owners")
                    if isinstance(asset.get("owners"), list)
                    else []
                )
                if any(
                    str(owner.get("uid") or "") in discovered
                    for owner in owners
                    if isinstance(owner, dict)
                ):
                    discovered.add(uid)
                    changed = True
        return discovered

    @staticmethod
    def _limited(items: list[dict[str, Any]], limit: int) -> dict[str, Any]:
        ordered = sorted(
            items,
            key=lambda item: str(
                item.get("object_created_at")
                or item.get("status_summary", {}).get("creation_timestamp")
                or ""
            ),
            reverse=True,
        )
        return {
            "items": ordered[:limit],
            "total": len(ordered),
            "truncated": len(ordered) > limit,
        }

    def object_query(self, operation: str, history: bool, body: bytes) -> dict[str, Any]:
        request = _decode(body)
        common = {"runner_cluster_id", "expected_cluster_uid", "object"}
        allowed = {
            ("instances", False): common | {"limit"},
            ("executions", False): common | {"limit"},
            ("revisions", False): common | {"limit"},
            ("events", False): common | {"scope", "type", "reason", "limit"},
            ("events", True): common | {"scope", "type", "reason", "range", "cursor"},
            ("logs", False): common | {"pod_uid", "container", "previous", "tail_lines"},
            ("logs", True): common | {"pod_uid", "container", "level", "range", "cursor"},
        }.get((operation, history))
        if allowed is None:
            raise KubernetesBoundaryError(
                "OBJECT_OPERATION_UNSUPPORTED",
                "object operation is not supported",
                status=404,
            )
        _only_fields(request, allowed)
        cluster = self._cluster(
            _bounded_string(request.get("runner_cluster_id"), "runner_cluster_id")
        )
        identity = self._identity(cluster)
        if identity["cluster_uid"] != _bounded_string(
            request.get("expected_cluster_uid"), "expected_cluster_uid"
        ):
            raise KubernetesBoundaryError(
                "CLUSTER_UID_CHANGED",
                "cluster UID changed; re-enrollment required",
                status=409,
            )
        ref = self._object_request(request, cluster)
        assets, _ = _exclude_scaled_to_zero_assets(self.client.assets(cluster))
        parent = self._resolve_object(ref, assets)
        descendants = self._descendant_uids(parent, assets)
        try:
            limit = min(
                OBJECT_QUERY_MAX_ITEMS, max(1, int(request.get("limit", 50)))
            )
        except (TypeError, ValueError) as exc:
            raise KubernetesBoundaryError(
                "INVALID_FILTER", "limit must be an integer"
            ) from exc

        if operation == "instances":
            if parent.get("kind") not in {
                "Deployment", "StatefulSet", "DaemonSet", "Job"
            }:
                raise KubernetesBoundaryError(
                    "INSTANCE_LIST_UNSUPPORTED",
                    "this object does not manage Pod instances",
                    status=400,
                )
            result = self._limited(
                [
                    asset
                    for asset in assets
                    if asset.get("kind") == "Pod"
                    and asset.get("uid") in descendants
                ],
                limit,
            )
        elif operation == "executions":
            if parent.get("kind") != "CronJob":
                raise KubernetesBoundaryError(
                    "EXECUTION_LIST_UNSUPPORTED",
                    "this object does not manage Job executions",
                    status=400,
                )
            result = self._limited(
                [
                    asset
                    for asset in assets
                    if asset.get("kind") == "Job"
                    and asset.get("uid") in descendants
                ],
                limit,
            )
        elif operation == "revisions":
            source = {
                "Deployment": "ReplicaSet",
                "StatefulSet": "ControllerRevision",
                "DaemonSet": "ControllerRevision",
            }.get(str(parent.get("kind")))
            if not source:
                raise KubernetesBoundaryError(
                    "REVISION_HISTORY_UNSUPPORTED",
                    "this object has no Kubernetes rollout revision history",
                    status=400,
                )
            revisions = []
            for asset in assets:
                if asset.get("kind") != source or asset.get("uid") not in descendants:
                    continue
                summary = (
                    asset.get("status_summary")
                    if isinstance(asset.get("status_summary"), dict)
                    else {}
                )
                revision = _integer(summary.get("revision"))
                if revision is None:
                    continue
                spec_summary = (
                    asset.get("spec_summary")
                    if isinstance(asset.get("spec_summary"), dict)
                    else {}
                )
                containers = spec_summary.get("containers", [])
                revisions.append({
                    "revision": revision,
                    "name": asset.get("name"),
                    "created_at": asset.get("object_created_at")
                    or summary.get("creation_timestamp"),
                    "containers": containers,
                    "status": summary,
                    "template_fingerprint": _fingerprint({"containers": containers}),
                })
            revisions.sort(key=lambda item: int(item["revision"]), reverse=True)
            result = {
                "items": revisions[:limit],
                "total": len(revisions),
                "truncated": len(revisions) > limit,
                "retention_limited": True,
            }
        elif operation == "events":
            scope = request.get("scope", "SELF")
            if scope not in {"SELF", "SELF_AND_INSTANCES"}:
                raise KubernetesBoundaryError(
                    "INVALID_FILTER", "scope must be SELF or SELF_AND_INSTANCES"
                )
            selected = {str(parent.get("uid") or "")}
            if scope == "SELF_AND_INSTANCES":
                selected = descendants
            if history:
                query = {
                    "namespace": parent.get("namespace"),
                    "type": request.get("type"),
                    "reason": request.get("reason"),
                    "range": request.get("range"),
                    "cursor": request.get("cursor"),
                }
                self._validate_query("events", True, query, cluster)
                result = self.history.events(cluster, query)
            else:
                raw = self.client.current_events(
                    cluster, {"namespace": parent.get("namespace")}
                )
                items = [
                    event
                    for event in raw.get("items", [])
                    if isinstance(event, dict)
                    and str((event.get("object") or {}).get("uid") or "") in selected
                    and (
                        not request.get("type")
                        or event.get("type") == request.get("type")
                    )
                    and (
                        not request.get("reason")
                        or event.get("reason") == request.get("reason")
                    )
                ]
                result = self._limited(items, limit)
        else:
            pod_uid = _bounded_string(
                request.get("pod_uid") or parent.get("uid"),
                "pod_uid",
                maximum=128,
            )
            pod = next(
                (
                    asset
                    for asset in assets
                    if asset.get("kind") == "Pod" and asset.get("uid") == pod_uid
                ),
                None,
            )
            if pod is None or (
                parent.get("kind") != "Pod" and pod_uid not in descendants
            ):
                raise KubernetesBoundaryError(
                    "RELATED_OBJECT_NOT_FOUND",
                    "selected Pod does not belong to this object",
                    status=404,
                )
            container = _bounded_string(request.get("container"), "container")
            spec_summary = (
                pod.get("spec_summary")
                if isinstance(pod.get("spec_summary"), dict)
                else {}
            )
            container_names = {
                str(item.get("name"))
                for item in spec_summary.get("containers", [])
                if isinstance(item, dict)
            }
            if container_names and container not in container_names:
                raise KubernetesBoundaryError(
                    "CONTAINER_NOT_FOUND",
                    "container does not belong to selected Pod",
                    status=404,
                )
            query = {
                "namespace": pod.get("namespace"),
                "pod": pod.get("name"),
                "container": container,
            }
            if history:
                query.update({
                    "level": request.get("level"),
                    "range": request.get("range"),
                    "cursor": request.get("cursor"),
                })
                self._validate_query("logs", True, query, cluster)
                result = self.history.logs(cluster, query)
            else:
                query.update({
                    "previous": request.get("previous", False),
                    "tail_lines": request.get("tail_lines", 500),
                })
                self._validate_query("logs", False, query, cluster)
                result = self.client.current_logs(cluster, query)
        return self._envelope(
            cluster,
            identity,
            result,
            truncated=bool(result.get("truncated", False)),
        )

    def query(self, kind: str, history: bool, body: bytes) -> dict[str, Any]:
        query = _decode(body)
        common = {"runner_cluster_id", "expected_cluster_uid"}
        allowed = {
            ("metrics", False): common | {"resource_type", "namespace"},
            ("metrics", True): common | {"resource_type", "resource_name", "namespace", "metric", "range"},
            ("logs", False): common | {"namespace", "pod", "container", "previous", "tail_lines"},
            ("logs", True): common | {"namespace", "pod", "container", "level", "range", "cursor"},
            ("events", False): common | {"namespace", "type", "reason"},
            ("events", True): common | {"namespace", "type", "reason", "range", "cursor"},
        }[(kind, history)]
        _only_fields(query, allowed)
        cluster = self._cluster(_bounded_string(query.get("runner_cluster_id"), "runner_cluster_id"))
        identity = self._identity(cluster)
        if identity["cluster_uid"] != _bounded_string(query.get("expected_cluster_uid"), "expected_cluster_uid"):
            raise KubernetesBoundaryError("CLUSTER_UID_CHANGED", "cluster UID changed; re-enrollment required", status=409)
        query.pop("runner_cluster_id", None)
        query.pop("expected_cluster_uid", None)
        self._validate_query(kind, history, query, cluster)
        if history:
            result = getattr(self.history, kind)(cluster, query)
        elif kind == "metrics":
            key = _fingerprint([cluster.id, query])
            cached = self._metric_cache.get(key)
            if cached and time.monotonic() - cached[0] < self.cfg.current_metrics_cache_sec:
                result = cached[1]
            else:
                result = self.client.current_metrics(cluster, query)
                self._metric_cache[key] = (time.monotonic(), result)
        else:
            result = getattr(self.client, f"current_{kind}")(cluster, query)
        return self._envelope(cluster, identity, result, truncated=bool(result.get("truncated", False)))

    def _validate_query(self, kind: str, history: bool, query: dict[str, Any], cluster: ClusterConfig) -> None:
        for field_name in ("namespace", "pod", "container", "resource_name", "metric", "level", "type", "reason", "cursor"):
            if field_name in query and query[field_name] is not None:
                query[field_name] = _bounded_string(query[field_name], field_name, maximum=512, required=False)
        namespace = query.get("namespace")
        if namespace and cluster.namespace_allowlist and namespace not in cluster.namespace_allowlist:
            raise KubernetesBoundaryError("NAMESPACE_NOT_ALLOWED", "namespace is outside the runner allowlist", status=403)
        if kind == "metrics":
            if query.get("resource_type") not in {"node", "pod"}:
                raise KubernetesBoundaryError("INVALID_FILTER", "resource_type must be node or pod")
            if history and query.get("metric") not in {"cpu_usage", "memory_usage", "cpu_utilization", "memory_utilization", "network_receive", "network_transmit"}:
                raise KubernetesBoundaryError("INVALID_FILTER", "metric is not allowed")
        if history and query.get("range") not in HISTORY_RANGES:
            raise KubernetesBoundaryError("INVALID_FILTER", "range must be 1h, 6h, 24h, 7d, or 30d")
        if kind == "logs" and not history:
            for required in ("namespace", "pod", "container"):
                if not query.get(required):
                    raise KubernetesBoundaryError("INVALID_FILTER", f"{required} is required")
            if not isinstance(query.get("previous", False), bool):
                raise KubernetesBoundaryError("INVALID_FILTER", "previous must be boolean")
            try:
                query["tail_lines"] = min(2000, max(1, int(query.get("tail_lines", 500))))
            except (TypeError, ValueError) as exc:
                raise KubernetesBoundaryError("INVALID_FILTER", "tail_lines must be an integer") from exc

    def _inspection_assets(self, cluster: ClusterConfig) -> AssetCollectionSnapshot:
        collector = self._collectors.get(cluster.id)
        if collector is not None:
            with collector.current_lock:
                items = list(collector.current.values())
            last = _timestamp(collector.last_success.get("resources"))
            if last is None or (datetime.now(timezone.utc) - last).total_seconds() > 60:
                raise KubernetesBoundaryError(
                    "COLLECTOR_STALE", "continuous collector is more than 60 seconds stale",
                    status=503, retriable=True,
                )
            counts: dict[str, int] = {}
            for item in items:
                kind = str(item.get("kind") or "Unknown")
                counts[kind] = counts.get(kind, 0) + 1
            return AssetCollectionSnapshot(items, [{
                "api_version": "", "kind": kind, "status": "COMPLETE", "checked_count": count,
            } for kind, count in counts.items()])
        collect = getattr(self.client, "collect_assets", None)
        if callable(collect):
            return collect(cluster)
        items = self.client.assets(cluster)
        counts: dict[str, int] = {}
        for item in items:
            counts[str(item.get("kind") or "Unknown")] = counts.get(
                str(item.get("kind") or "Unknown"), 0
            ) + 1
        return AssetCollectionSnapshot(
            items,
            [
                {
                    "api_version": "",
                    "kind": kind,
                    "status": "COMPLETE",
                    "checked_count": count,
                }
                for kind, count in sorted(counts.items())
            ],
        )

    def deterministic_health(self, cluster_id: str, namespaces: list[str] | None = None) -> dict[str, Any]:
        cluster = self._cluster(cluster_id)
        if namespaces:
            for namespace in namespaces:
                _bounded_string(namespace, "namespace")
                if cluster.namespace_allowlist and namespace not in cluster.namespace_allowlist:
                    raise KubernetesBoundaryError("NAMESPACE_NOT_ALLOWED", "namespace is outside the runner allowlist", status=403)
        collection = self._inspection_assets(cluster)
        assets, excluded_uids = _exclude_scaled_to_zero_assets(collection.items)
        resources = _filtered_resource_coverage(collection.resources, assets)
        if namespaces:
            assets = [asset for asset in assets if not asset.get("namespace") or asset.get("namespace") in namespaces]
        if getattr(self.cfg, "inspection_report_version", "v2") == "v1":
            return self._deterministic_health_v1(assets, namespaces)
        return self._deterministic_health_v2(
            cluster,
            assets,
            resources,
            namespaces,
            excluded_object_uids=excluded_uids,
        )

    @staticmethod
    def _deterministic_health_v1(
        assets: list[dict[str, Any]], namespaces: list[str] | None,
    ) -> dict[str, Any]:
        findings = []
        for asset in assets:
            summary = asset.get("status_summary") or {}
            severity = rule_id = None
            if asset.get("kind") == "Node":
                ready = _condition_map(summary).get("Ready")
                if ready and ready.get("status") != "True":
                    severity, rule_id = "CRITICAL", "K8S_NODE_NOT_READY"
            elif asset.get("kind") == "Pod" and summary.get("phase") in {"Failed", "Unknown", "Pending"}:
                severity, rule_id = "WARNING", "K8S_POD_UNHEALTHY"
            elif asset.get("kind") in {"Deployment", "StatefulSet"}:
                desired = _integer(summary.get("desired_replicas"))
                ready = _integer(summary.get("available_replicas"))
                if ready is None:
                    ready = _integer(summary.get("ready_replicas"))
                if desired is not None and ready is not None and ready < desired:
                    severity, rule_id = "WARNING", "K8S_WORKLOAD_REPLICA_GAP"
            if rule_id:
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "object_ref": _object_ref(asset),
                    "evidence": summary,
                    "impact_scope": asset.get("namespace") or "cluster",
                    "recommendation": "请人工核查对象状态和近期事件。",
                })
        return {
            "schema_version": "kubernetes-inspection/v1",
            "repair_supported": False,
            "scope": {"namespaces": namespaces or []},
            "checked_assets": len(assets),
            "findings": findings,
            "overall_status": (
                "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings)
                else "WARNING" if findings else "HEALTHY"
            ),
        }

    def _deterministic_health_v2(
        self,
        cluster: ClusterConfig,
        assets: list[dict[str, Any]],
        resource_coverage: list[dict[str, Any]],
        namespaces: list[str] | None,
        *,
        excluded_object_uids: set[str] | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        by_uid = {str(asset.get("uid")): asset for asset in assets if asset.get("uid")}
        by_key = {
            (str(asset.get("kind")), str(asset.get("namespace") or ""), str(asset.get("name"))): asset
            for asset in assets
        }

        def parent(asset: dict[str, Any]) -> dict[str, Any] | None:
            owners = [item for item in asset.get("owners", []) if isinstance(item, dict)]
            owners.sort(key=lambda item: not bool(item.get("controller")))
            for owner in owners:
                found = by_uid.get(str(owner.get("uid") or ""))
                if found is None:
                    found = by_key.get((
                        str(owner.get("kind") or ""),
                        str(asset.get("namespace") or ""),
                        str(owner.get("name") or ""),
                    ))
                if found is not None:
                    return found
            return None

        def root(asset: dict[str, Any]) -> dict[str, Any]:
            current = asset
            visited: set[str] = set()
            for _ in range(6):
                identity = str(current.get("uid") or "") or repr(
                    (current.get("kind"), current.get("namespace"), current.get("name"))
                )
                if identity in visited:
                    break
                visited.add(identity)
                owner = parent(current)
                if owner is None:
                    break
                current = owner
            return current

        grouped: dict[str, dict[str, Any]] = {}
        affected_keys: dict[str, set[str]] = {}
        evidence_gaps: set[str] = set()

        def add_finding(
            *, rule_id: str, category: str, severity: str, title: str,
            asset: dict[str, Any], evidence: dict[str, Any], recommendation: str,
            classification: str = "CURRENT_IMPACT",
        ) -> None:
            root_asset = root(asset)
            root_ref = _object_ref(root_asset)
            stable_root = root_ref.get("uid") or "/".join(
                str(root_ref.get(key) or "") for key in ("kind", "namespace", "name")
            )
            finding_id = hashlib.sha256(
                f"{rule_id}:{stable_root}".encode("utf-8")
            ).hexdigest()[:24]
            area = (
                "PLATFORM"
                if not root_ref.get("namespace")
                or root_ref.get("namespace") in _SYSTEM_NAMESPACES
                else "BUSINESS"
            )
            if finding_id not in grouped:
                grouped[finding_id] = {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "category": category,
                    "severity": severity,
                    "classification": classification,
                    "area": area,
                    "title": title,
                    "root_object_ref": root_ref,
                    "affected_object_count": 0,
                    "affected_object_refs": [],
                    "evidence": dict(evidence),
                    "impact_scope": root_ref.get("namespace") or "cluster",
                    "recommendation": recommendation,
                }
                affected_keys[finding_id] = set()
            row = grouped[finding_id]
            ref = _object_ref(asset)
            affected_key = str(ref.get("uid") or repr(ref))
            if affected_key not in affected_keys[finding_id]:
                affected_keys[finding_id].add(affected_key)
                row["affected_object_count"] += 1
                if len(row["affected_object_refs"]) < INSPECTION_MAX_AFFECTED_OBJECTS:
                    row["affected_object_refs"].append(ref)
            for key, value in evidence.items():
                if key not in row["evidence"]:
                    row["evidence"][key] = value

        for asset in assets:
            kind = asset.get("kind")
            summary = asset.get("status_summary") or {}
            conditions = _condition_map(summary)
            age = _integer(summary.get("age_seconds"))
            outside_grace = age is None or age >= INSPECTION_TRANSIENT_GRACE_SECONDS
            if kind == "Node":
                ready = conditions.get("Ready")
                if ready is None:
                    evidence_gaps.add("node")
                elif ready.get("status") != "True":
                    add_finding(
                        rule_id="K8S_NODE_NOT_READY", category="node", severity="CRITICAL",
                        title="节点未就绪", asset=asset,
                        evidence={"condition": "Ready", "status": ready.get("status"), "reason": ready.get("reason")},
                        recommendation="请人工核查节点 Conditions、关联事件、网络与 kubelet 状态。",
                    )
                for condition_type in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
                    condition = conditions.get(condition_type)
                    if condition and condition.get("status") == "True":
                        add_finding(
                            rule_id=f"K8S_NODE_{condition_type.upper()}", category="node", severity="WARNING",
                            title=f"节点出现 {condition_type}", asset=asset,
                            evidence={"condition": condition_type, "status": "True", "reason": condition.get("reason")},
                            recommendation="请人工核查节点资源、运行时和网络状态，并确认受影响工作负载。",
                        )
            elif kind in {"Deployment", "StatefulSet"}:
                desired = _integer(summary.get("desired_replicas"))
                ready_key = "available_replicas" if kind == "Deployment" else "ready_replicas"
                ready = _integer(summary.get(ready_key))
                if desired is not None and desired > 0 and not summary.get("replica_status_observed"):
                    evidence_gaps.add("workload")
                elif desired is not None and ready is not None and ready < desired and outside_grace:
                    add_finding(
                        rule_id="K8S_WORKLOAD_REPLICA_GAP", category="workload", severity="WARNING",
                        title="工作负载可用副本不足", asset=asset,
                        evidence={"desired_replicas": desired, "ready_replicas": ready, "kind": kind},
                        recommendation="请人工核查工作负载 Conditions、关联 Pod 与近期事件。",
                    )
            elif kind == "DaemonSet":
                desired = _integer(summary.get("desired_number_scheduled"))
                ready = _integer(summary.get("number_ready"))
                if desired is not None and desired > 0 and not summary.get("replica_status_observed"):
                    evidence_gaps.add("workload")
                elif desired is not None and ready is not None and ready < desired and outside_grace:
                    add_finding(
                        rule_id="K8S_DAEMONSET_READY_GAP", category="workload", severity="WARNING",
                        title="DaemonSet 就绪节点不足", asset=asset,
                        evidence={"desired_nodes": desired, "ready_nodes": ready},
                        recommendation="请人工核查 DaemonSet 状态、节点可调度性和关联 Pod。",
                    )
            elif kind == "Pod":
                root_asset = root(asset)
                root_kind = root_asset.get("kind")
                phase = summary.get("phase")
                if phase is None or (phase == "Running" and summary.get("ready") is None):
                    evidence_gaps.add("pod")
                waiting = [str(item) for item in summary.get("waiting_reasons", [])]
                bad_waiting = sorted(set(waiting) & _CONTAINER_WAITING_REASONS)
                if bad_waiting:
                    add_finding(
                        rule_id="K8S_POD_CONTAINER_WAITING", category="pod", severity="WARNING",
                        title="Pod 容器无法正常启动", asset=asset,
                        evidence={"waiting_reasons": bad_waiting, "restart_count": summary.get("restart_count", 0)},
                        recommendation="请人工核查容器状态、Pod 事件和所属工作负载。",
                    )
                elif phase == "Pending" and outside_grace:
                    add_finding(
                        rule_id="K8S_POD_PENDING", category="scheduling", severity="WARNING",
                        title="Pod 长时间处于 Pending", asset=asset,
                        evidence={"phase": phase, "age_seconds": age},
                        recommendation="请人工核查调度条件、资源配额、节点状态和近期事件。",
                    )
                elif phase == "Running" and summary.get("ready") is False and outside_grace:
                    add_finding(
                        rule_id="K8S_POD_NOT_READY", category="pod", severity="WARNING",
                        title="Pod 运行但未就绪", asset=asset,
                        evidence={"phase": phase, "ready": False, "restart_count": summary.get("restart_count", 0)},
                        recommendation="请人工核查 Readiness 条件、容器状态和所属工作负载。",
                    )
                elif phase == "Unknown":
                    add_finding(
                        rule_id="K8S_POD_STATUS_UNKNOWN", category="pod", severity="WARNING",
                        title="Pod 状态未知", asset=asset,
                        evidence={"phase": phase},
                        recommendation="请人工核查节点通信、Pod 状态和近期事件。",
                    )
                elif phase == "Failed" and root_kind not in {"Job", "Deployment", "StatefulSet", "DaemonSet"}:
                    add_finding(
                        rule_id="K8S_STANDALONE_POD_FAILED", category="pod", severity="WARNING",
                        title="独立 Pod 执行失败", asset=asset,
                        evidence={"phase": phase, "terminated_reasons": summary.get("terminated_reasons", []), "exit_codes": summary.get("exit_codes", [])},
                        recommendation="请人工确认该 Pod 是否仍承担服务，并核查退出原因与近期事件。",
                        classification="RECENT_HISTORY",
                    )
            elif kind == "Job":
                if not conditions and not any(
                    key in summary for key in ("active", "succeeded", "failed")
                ):
                    evidence_gaps.add("job")
                failed = _integer(summary.get("failed"))
                succeeded = _integer(summary.get("succeeded"))
                active = _integer(summary.get("active"))
                failed_condition = conditions.get("Failed")
                if (
                    (
                        failed is not None
                        and failed > 0
                        and succeeded == 0
                        and active == 0
                        and outside_grace
                    )
                    or (
                        failed_condition is not None
                        and failed_condition.get("status") == "True"
                    )
                ):
                    add_finding(
                        rule_id="K8S_JOB_FAILED", category="job", severity="WARNING",
                        title="Job 执行失败", asset=asset,
                        evidence={"failed_pods": failed, "succeeded_pods": succeeded, "active_pods": active, "reason": (failed_condition or {}).get("reason")},
                        recommendation="请人工核查 Job Conditions、失败 Pod 的退出原因和业务输入。",
                    )
                    for child in assets:
                        child_summary = child.get("status_summary") or {}
                        child_failed = (
                            child_summary.get("phase") == "Failed"
                            or any(
                                (_integer(code) or 0) != 0
                                for code in child_summary.get("exit_codes", [])
                            )
                        )
                        if (
                            child.get("kind") == "Pod"
                            and root(child).get("uid") == asset.get("uid")
                            and child_failed
                        ):
                            add_finding(
                                rule_id="K8S_JOB_FAILED", category="job", severity="WARNING",
                                title="Job 执行失败", asset=child,
                                evidence={"failed_pods": failed, "succeeded_pods": succeeded, "active_pods": active},
                                recommendation="请人工核查 Job Conditions、失败 Pod 的退出原因和业务输入。",
                            )
            elif kind == "HorizontalPodAutoscaler":
                if not conditions:
                    evidence_gaps.add("autoscaling")
                for condition_type in ("AbleToScale", "ScalingActive"):
                    condition = conditions.get(condition_type)
                    if condition and condition.get("status") == "False":
                        add_finding(
                            rule_id="K8S_HPA_CONDITION_ABNORMAL", category="autoscaling", severity="WARNING",
                            title="HPA 无法正常计算或执行伸缩", asset=asset,
                            evidence={"condition": condition_type, "status": "False", "reason": condition.get("reason")},
                            recommendation="请人工核查 HPA Conditions、指标可用性和目标工作负载。",
                        )
            elif kind == "PersistentVolumeClaim":
                phase = summary.get("phase")
                if phase is None:
                    evidence_gaps.add("storage")
                if phase == "Lost":
                    add_finding(
                        rule_id="K8S_PVC_LOST", category="storage", severity="CRITICAL",
                        title="PVC 已丢失绑定", asset=asset,
                        evidence={"phase": phase, "storage_class": summary.get("storage_class")},
                        recommendation="请人工核查 PVC/PV 绑定关系、存储后端和近期事件。",
                    )
                elif phase == "Pending" and outside_grace:
                    add_finding(
                        rule_id="K8S_PVC_PENDING", category="storage", severity="WARNING",
                        title="PVC 长时间等待绑定", asset=asset,
                        evidence={"phase": phase, "age_seconds": age, "storage_class": summary.get("storage_class")},
                        recommendation="请人工核查 StorageClass、容量、拓扑约束和近期事件。",
                    )

        resources_by_kind = {str(row.get("kind")): row for row in resource_coverage}
        endpoint_slice_coverage = resources_by_kind.get("EndpointSlice") or {}
        endpoint_slice_complete = endpoint_slice_coverage.get("status") == "COMPLETE"
        endpoint_ready: dict[tuple[str, str], int] = {}
        for asset in assets:
            if asset.get("kind") != "EndpointSlice":
                continue
            if "ready_endpoint_count" not in (asset.get("status_summary") or {}):
                evidence_gaps.add("network")
            service_name = (asset.get("labels") or {}).get("kubernetes.io/service-name")
            if service_name:
                key = (str(asset.get("namespace") or ""), str(service_name))
                endpoint_ready[key] = endpoint_ready.get(key, 0) + (
                    _integer((asset.get("status_summary") or {}).get("ready_endpoint_count"), 0) or 0
                )
        for asset in assets:
            if asset.get("kind") != "Service":
                continue
            summary = asset.get("status_summary") or {}
            if "selector_count" not in summary:
                evidence_gaps.add("network")
                continue
            service_age = _integer(summary.get("age_seconds"))
            if (
                (_integer(summary.get("selector_count"), 0) or 0) > 0
                and summary.get("service_type") != "ExternalName"
                and (
                    service_age is None
                    or service_age >= INSPECTION_TRANSIENT_GRACE_SECONDS
                )
            ):
                key = (str(asset.get("namespace") or ""), str(asset.get("name") or ""))
                if endpoint_slice_complete and endpoint_ready.get(key, 0) == 0:
                    add_finding(
                        rule_id="K8S_SERVICE_NO_READY_ENDPOINT", category="network", severity="WARNING",
                        title="Service 没有就绪后端", asset=asset,
                        evidence={"ready_endpoints": 0, "selector_count": summary.get("selector_count")},
                        recommendation="请人工核查 Service Selector、关联 Pod 就绪状态和 EndpointSlice。",
                    )

        event_status = "COMPLETE"
        event_failure_codes: set[str] = set()
        event_truncated = False
        event_items: list[dict[str, Any]] = []
        event_queries = [{"namespace": namespace} for namespace in namespaces or []] or [{}]
        successful_event_queries = 0
        for event_query in event_queries:
            try:
                event_result = self.client.current_events(cluster, event_query)
                event_items.extend(list(event_result.get("items") or []))
                event_truncated = event_truncated or bool(event_result.get("truncated"))
                successful_event_queries += 1
            except KubernetesBoundaryError as exc:
                event_failure_codes.add(exc.code)
            except Exception:
                event_failure_codes.add("EVENT_QUERY_FAILED")
        if successful_event_queries == 0:
            event_status = "UNAVAILABLE"
        elif successful_event_queries < len(event_queries):
            event_status = "PARTIAL"
        if event_truncated:
            event_failure_codes.add("EVENTS_TRUNCATED")
        event_cutoff = now - timedelta(seconds=INSPECTION_EVENT_WINDOW_SECONDS)
        for event in event_items:
            event_object = event.get("object") or {}
            if str(event_object.get("uid") or "") in (excluded_object_uids or set()):
                continue
            if str(event.get("type") or "") != "Warning":
                continue
            observed = _timestamp(event.get("last_timestamp"))
            if observed is None or observed < event_cutoff:
                continue
            reason = str(event.get("reason") or "Unknown")[:128]
            if reason not in _HIGH_SIGNAL_EVENT_REASONS:
                continue
            asset = by_uid.get(str(event_object.get("uid") or "")) or by_key.get((
                str(event_object.get("kind") or ""),
                str(event.get("namespace") or ""),
                str(event_object.get("name") or ""),
            ))
            if asset is None:
                asset = {
                    "kind": str(event_object.get("kind") or "Object"),
                    "namespace": event.get("namespace"),
                    "name": str(event_object.get("name") or "unknown"),
                    "uid": str(event_object.get("uid") or ""),
                    "owners": [],
                }
            add_finding(
                rule_id="K8S_WARNING_EVENT", category="event", severity="WARNING",
                title="近期出现高信号 Warning Event", asset=asset,
                evidence={"reason": reason, "count": _integer(event.get("count"), 1), "last_timestamp": str(event.get("last_timestamp") or "")[:64]},
                recommendation="请人工结合关联对象状态和事件原因确认当前影响。",
                classification="RECENT_HISTORY",
            )

        domain_kinds = {
            "node": {"Node"},
            "workload": {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"},
            "pod": {"Pod"},
            "scheduling": {"Pod", "Node", "ResourceQuota", "LimitRange"},
            "network": {"Service", "EndpointSlice", "Ingress"},
            "storage": {"PersistentVolumeClaim", "PersistentVolume", "StorageClass"},
            "job": {"Job", "CronJob"},
            "autoscaling": {"HorizontalPodAutoscaler"},
        }
        coverage: list[dict[str, Any]] = []
        for domain, kinds in domain_kinds.items():
            rows = [resources_by_kind[kind] for kind in kinds if kind in resources_by_kind]
            statuses = {str(row.get("status")) for row in rows}
            status = "COMPLETE"
            if not rows or statuses <= {"UNAVAILABLE", "UNAUTHORIZED"}:
                status = "UNAVAILABLE"
            elif statuses != {"COMPLETE"}:
                status = "PARTIAL"
            if domain in evidence_gaps and status == "COMPLETE":
                status = "PARTIAL"
            failure_codes = sorted({
                str(row.get("failure_code")) for row in rows if row.get("failure_code")
            })
            coverage.append({
                "domain": domain,
                "status": status,
                "checked_count": sum(1 for asset in assets if asset.get("kind") in kinds),
                "failure_codes": failure_codes,
            })
        coverage.append({
            "domain": "event",
            "status": "PARTIAL" if event_truncated or event_status == "PARTIAL" else event_status,
            "checked_count": len(event_items),
            "failure_codes": sorted(event_failure_codes),
        })

        findings = list(grouped.values())
        severity_order = {"CRITICAL": 0, "WARNING": 1, "UNKNOWN": 2}
        area_order = {"BUSINESS": 0, "PLATFORM": 1}
        findings.sort(key=lambda item: (
            severity_order.get(str(item.get("severity")), 3),
            area_order.get(str(item.get("area")), 2),
            str(item.get("category")),
            str((item.get("root_object_ref") or {}).get("namespace") or ""),
            str((item.get("root_object_ref") or {}).get("name") or ""),
        ))
        total_findings = len(findings)
        business_count = sum(1 for item in findings if item.get("area") == "BUSINESS")
        platform_count = total_findings - business_count
        issue_counts: dict[str, int] = {}
        for item in findings:
            issue_counts[str(item.get("category"))] = issue_counts.get(
                str(item.get("category")), 0
            ) + 1
        findings = findings[:INSPECTION_MAX_FINDINGS]
        if total_findings > len(findings):
            coverage.append({
                "domain": "report",
                "status": "PARTIAL",
                "checked_count": len(assets),
                "failure_codes": ["FINDINGS_TRUNCATED"],
            })
        for item in coverage:
            item["issue_count"] = issue_counts.get(str(item.get("domain")), 0)

        incomplete = [item for item in coverage if item.get("status") != "COMPLETE"]
        if any(item.get("severity") == "CRITICAL" for item in findings):
            overall = "CRITICAL"
        elif any(item.get("severity") == "WARNING" for item in findings):
            overall = "WARNING"
        elif incomplete:
            overall = "UNKNOWN"
        else:
            overall = "HEALTHY"
        if findings:
            summary = (
                f"检查 {len(assets)} 个集群对象，归并出 {total_findings} 个根因组；"
                f"业务区域 {business_count} 个，平台组件 {platform_count} 个。"
            )
        elif incomplete:
            summary = f"检查 {len(assets)} 个集群对象，未发现已确认异常，但有 {len(incomplete)} 个诊断域覆盖不完整。"
        else:
            summary = f"检查 {len(assets)} 个集群对象，确定性规则未发现异常。"
        return {
            "schema_version": INSPECTION_SCHEMA_VERSION,
            "target_type": "KUBERNETES_CLUSTER",
            "overall_status": overall,
            "completion_status": "PARTIAL" if incomplete else "COMPLETE",
            "summary": summary,
            "repair_supported": False,
            "scope": {"namespaces": namespaces or []},
            "checked_assets": len(assets),
            "snapshot": {
                "generated_at": now.isoformat().replace("+00:00", "Z"),
                "rule_set_version": INSPECTION_RULESET_VERSION,
                "event_window_seconds": INSPECTION_EVENT_WINDOW_SECONDS,
                "transient_grace_seconds": INSPECTION_TRANSIENT_GRACE_SECONDS,
                "truncated": total_findings > len(findings) or event_truncated,
                "finding_count": total_findings,
            },
            "coverage": coverage,
            "findings": findings,
            "interpretation": {"status": "PENDING", "priorities": [], "limitations": []},
        }

    def _job(self, sync_id: str) -> SyncJob:
        try:
            uuid.UUID(sync_id)
        except ValueError as exc:
            raise KubernetesBoundaryError("SYNC_NOT_FOUND", "sync not found", status=404) from exc
        job = self._jobs.get(sync_id)
        if not job:
            raise KubernetesBoundaryError("SYNC_NOT_FOUND", "sync not found", status=404)
        return job

    def _job_path(self, job_id: str) -> str:
        return os.path.join(self.cfg.state_dir, f"{job_id}.json")

    def _persist_job(self, job: SyncJob) -> None:
        # Raw assets are a bounded, credential-free inventory snapshot. Logs/events are never persisted.
        path = self._job_path(job.id)
        temp = path + ".tmp"
        with open(temp, "w", encoding="utf-8") as stream:
            json.dump(job.__dict__, stream, ensure_ascii=False, separators=(",", ":"))
        os.replace(temp, path)

    def _recover_jobs(self) -> None:
        for path in Path(self.cfg.state_dir).glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                job = SyncJob(**data)
                if job.status in {"PENDING", "RUNNING"}:
                    job.status = "FAILED"
                    job.error_code = "RUNNER_RESTARTED"
                    job.finished_at = _utcnow()
                    self._persist_job(job)
                self._jobs[job.id] = job
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, Any]]:
        try:
            route, _, query_string = path.partition("?")
            parts = [part for part in route[len("/kubernetes"):].split("/") if part]
            if method == "GET" and parts == ["clusters"]:
                return 200, self.clusters()
            if method == "GET" and len(parts) == 3 and parts[:2] == ["collections", "status"]:
                return 200, self.collection_status(parts[2])
            if method == "POST" and parts == ["collections", "pull"]:
                return 200, self.collection_pull(body)
            if method == "POST" and parts == ["collections", "reconcile"]:
                return 202, self.collection_reconcile(body)
            if method == "POST" and parts == ["syncs"]:
                return 202, self.start_sync(body)
            if len(parts) >= 2 and parts[0] == "syncs":
                if method == "GET" and len(parts) == 2:
                    return 200, self.sync_status(parts[1])
                if method == "GET" and parts[2:] == ["assets"]:
                    cursor = None
                    for pair in query_string.split("&"):
                        if pair.startswith("cursor="):
                            cursor = pair.split("=", 1)[1]
                    return 200, self.sync_assets(parts[1], cursor)
                if method == "POST" and parts[2:] == ["cancel"]:
                    return 200, self.cancel_sync(parts[1])
            if method == "POST" and len(parts) == 2 and parts[0] in {"metrics", "logs", "events"} and parts[1] in {"current", "history"}:
                return 200, self.query(parts[0], parts[1] == "history", body)
            if (
                method == "POST"
                and len(parts) == 2
                and parts[0] == "objects"
                and parts[1] in {"instances", "executions", "revisions"}
            ):
                return 200, self.object_query(parts[1], False, body)
            if (
                method == "POST"
                and len(parts) == 3
                and parts[0] == "objects"
                and parts[1] in {"logs", "events"}
                and parts[2] in {"current", "history"}
            ):
                return 200, self.object_query(
                    parts[1], parts[2] == "history", body
                )
            return 404, {"error_code": "NOT_FOUND"}
        except KubernetesBoundaryError as exc:
            return exc.status, {"error_code": exc.code, "message": str(exc), "retriable": exc.retriable}
