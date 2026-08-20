"""Runner 配置加载与安全校验。

token / 密钥只存"引用"（环境变量名），真实值运行时从 env 读，绝不写进 config 文件、
不入日志、不进 prompt。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import yaml

# 仓库根目录（本文件位于 <root>/runner/runner/config.py）。
# 用于把 config.yaml 里的相对路径锚定到仓库根，而不是依赖进程启动时的 cwd，
# 这样项目挪到任意目录都不用改配置文件。
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_LOCAL_CONFIG_PATH = os.path.join(_REPO_ROOT, "config", "runner.local.yaml")


class RunnerConfigError(ValueError):
    """runner 本地覆盖配置不合法。"""


def _parse_listen(value: object) -> tuple[str, int]:
    listen = str(value or "").strip()
    if not listen or any(character.isspace() for character in listen):
        raise RunnerConfigError(
            "webhook.listen must be host:port with port 1..65535"
        )
    try:
        parsed = urlsplit("//" + listen)
        port = parsed.port
    except ValueError as exc:
        raise RunnerConfigError(
            "webhook.listen must be host:port with port 1..65535"
        ) from exc
    if (
        not parsed.hostname
        or ":" in parsed.hostname
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RunnerConfigError(
            "webhook.listen must be host:port with port 1..65535"
        )
    return parsed.hostname, port


def _http_url(value: object, *, label: str, allow_empty: bool) -> str:
    url = str(value or "").strip()
    if not url and allow_empty:
        return ""
    try:
        parsed = urlsplit(url)
        # Accessing port also rejects malformed/out-of-range URL ports.
        _ = parsed.port
    except ValueError as exc:
        raise RunnerConfigError(
            f"{label} must be an absolute http(s) URL"
        ) from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or any(character.isspace() for character in url)
    ):
        raise RunnerConfigError(
            f"{label} must be an absolute http(s) URL"
        )
    return url


def _load_mapping(path: str, *, label: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise RunnerConfigError(f"{label}: expected a mapping at top level")
    return data


def _deep_merge(base: dict, overlay: dict) -> dict:
    """递归合并 mapping；list 与标量由覆盖层整体替换。"""
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _runner_local_overlay(path: str | None = None) -> dict:
    local_path = path or os.environ.get("RUNNER_LOCAL_CONFIG") or _LOCAL_CONFIG_PATH
    local = _load_mapping(local_path, label="local.yaml")
    allowed = {
        "webhook",
        "trusted_session",
        "trusted_inspection",
        "kubernetes",
    }
    unknown = set(local) - allowed
    if unknown:
        raise RunnerConfigError(f"runner.local.yaml: unsupported section(s): {', '.join(sorted(unknown))}")
    for section, fields in {
        "webhook": {"listen"},
        # Identity location/assertion are per-node facts.  A local overlay may
        # set them, but can never enable trusted mode or widen its target set.
        "trusted_session": {
            "runner_instance_id_file",
            "expected_runner_instance_id",
            "aiops_url",
        },
        # Callback destinations are deployment-local facts.  The local file
        # may replace them without enabling trusted capabilities or changing
        # any credential environment-variable names.
        "trusted_inspection": {"aiops_url"},
        # Kubernetes inventory and runtime tuning are node-local facts. The
        # inventory contains only references; credentials remain in local
        # files/environment variables and never enter the base configuration.
        "kubernetes": {
            "enabled",
            "inventory_file",
            "state_dir",
            "current_metrics_cache_sec",
            "sync_timeout_sec",
            "inspection_report_version",
            "continuous_collection_enabled",
            "collection_interval_sec",
            "collection_memory_limit_mb",
            "log_collection_concurrency",
            "log_all_namespaces",
            "log_request_timeout_sec",
            "reconcile_interval_sec",
        },
    }.items():
        value = local.get(section)
        if value is not None and not isinstance(value, dict):
            raise RunnerConfigError(f"runner.local.yaml: '{section}' must be a mapping")
        if isinstance(value, dict) and set(value) - fields:
            raise RunnerConfigError(
                f"runner.local.yaml: unsupported {section} field(s): {', '.join(sorted(set(value) - fields))}"
            )
    return local


def _resolve_path(path: str) -> str:
    """相对路径相对仓库根解析；绝对路径原样返回；空字符串原样返回（表示"未配置"）。"""
    if not path or os.path.isabs(path):
        return path
    return os.path.join(_REPO_ROOT, path)


@dataclass
class WebhookConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    shared_token_env: str = "RUNNER_SHARED_TOKEN"  # 环境变量名，非 token 本身
    hmac_secret_env: str | None = None  # 可选 HMAC，env 变量名
    ip_allowlist: tuple[str, ...] = ("127.0.0.0/8",)


def _safe_bool(value: object) -> bool:
    """安全侧布尔解析：只有字面 true（bool True 或字符串 "true"）才算开，其余一律关。"""
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def _safe_int(value: object, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(value))
    except (TypeError, ValueError):
        return default


@dataclass
class TrustedSessionConfig:
    """Linux-only Claude trusted-session core.  Every unsafe capability is opt-in."""

    enabled: bool = False
    # ``managed_inventory`` grants the runner's locally registered assets;
    # ``explicit_allowlist`` remains for existing narrow rollouts.
    target_scope: str = "managed_inventory"
    target_allowlist: tuple[str, ...] = ()
    inventory_dir: str = "config"
    project_dir: str = "agent-project-trusted"
    journal_dir: str = "state/trusted-sessions"
    transcript_dir: str = "state/trusted-transcripts"
    session_store_dir: str = "state/trusted-claude-config"
    aiops_url: str = ""
    token_env: str = "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"
    runner_provider_id: str = ""
    # Actual identity is loaded only from runner_instance_id_file at service
    # startup.  This runtime field is intentionally not accepted from YAML.
    runner_instance_id: str = ""
    runner_instance_id_file: str = "state/runner-instance-id"
    expected_runner_instance_id: str = ""
    runner_config_path: str = ""
    runner_config_version: str = ""
    admin_token_env: str = "RUNNER_SHARED_TOKEN"
    approval_ttl_sec: int = 1800
    diagnosis_timeout_sec: int = 300
    diagnosis_command_budget: int = 20
    execution_ttl_sec: int = 1800
    risk_ttl_sec: int = 600
    transcript_retention_days: int = 30
    encryption_key_env: str = ""
    encryption_key_file: str = "state/trusted-transcript.key"
    encryption_key_id: str = ""

    @classmethod
    def from_dict(
        cls, data: dict, *, platform: str | None = None
    ) -> "TrustedSessionConfig":
        data = data or {}
        allowed = {
            "enabled", "target_scope", "target_allowlist", "inventory_dir", "project_dir", "journal_dir", "transcript_dir",
            "session_store_dir", "aiops_url", "token_env", "approval_ttl_sec",
            "runner_provider_id", "admin_token_env",
            "runner_instance_id_file", "expected_runner_instance_id", "runner_config_version",
            "diagnosis_timeout_sec", "diagnosis_command_budget", "execution_ttl_sec", "risk_ttl_sec", "transcript_retention_days",
            "encryption_key_env", "encryption_key_file", "encryption_key_id",
        }
        unknown = set(data) - allowed
        if unknown:
            raise RunnerConfigError(
                f"trusted_session: unsupported field(s): {', '.join(sorted(unknown))}"
            )
        enabled = _safe_bool(data.get("enabled", False))
        target_scope = str(data.get("target_scope", "managed_inventory") or "").strip()
        if target_scope not in {"explicit_allowlist", "managed_inventory"}:
            raise RunnerConfigError(
                "trusted_session.target_scope must be explicit_allowlist or managed_inventory"
            )
        current_platform = platform or sys.platform
        if enabled and current_platform != "linux":
            raise RunnerConfigError(
                "trusted_session.enabled requires a Linux runner (fcntl persistence boundary)"
            )
        allowlist = data.get("target_allowlist", []) or []
        if not isinstance(allowlist, list) or any(
            not isinstance(item, str) or not item.strip() for item in allowlist
        ):
            raise RunnerConfigError("trusted_session.target_allowlist must be a list of non-empty strings")
        key_env = str(data.get("encryption_key_env", "") or "").strip()
        key_file = str(
            data.get("encryption_key_file", "state/trusted-transcript.key") or ""
        ).strip()
        key_id = str(data.get("encryption_key_id", "") or "").strip()
        aiops_url = _http_url(
            data.get("aiops_url", ""), label="trusted_session.aiops_url", allow_empty=True
        )
        token_env = str(
            data.get(
                "token_env", "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"
            )
            or ""
        ).strip()
        admin_token_env = str(
            data.get("admin_token_env", "RUNNER_SHARED_TOKEN")
            or ""
        ).strip()
        config_version = str(data.get("runner_config_version", "") or "").strip()
        if len(config_version) > 255:
            raise RunnerConfigError("trusted_session.runner_config_version is too long")
        ttl_values = {
            field_name: _trusted_positive_int(data, field_name, default)
            for field_name, default in {
                "approval_ttl_sec": 1800,
                "diagnosis_timeout_sec": 300,
                "diagnosis_command_budget": 20,
                "execution_ttl_sec": 1800,
                "risk_ttl_sec": 600,
                "transcript_retention_days": 30,
            }.items()
        }
        for field_name, maximum in {
            "approval_ttl_sec": 1800,
            "diagnosis_timeout_sec": 300,
            "diagnosis_command_budget": 40,
            "execution_ttl_sec": 1800,
            "risk_ttl_sec": 600,
        }.items():
            if ttl_values[field_name] > maximum:
                raise RunnerConfigError(
                    f"trusted_session.{field_name} must be <= {maximum}"
                )
        if enabled:
            if bool(key_env) == bool(key_file):
                raise RunnerConfigError(
                    "trusted_session requires exactly one of encryption_key_env or encryption_key_file"
                )
            if not key_id:
                raise RunnerConfigError("trusted_session.encryption_key_id is required when enabled")
            try:
                from .trusted_inventory import ManagedInventory
                ManagedInventory(_resolve_path(data.get("inventory_dir", "config"))).validate()
            except Exception as exc:
                raise RunnerConfigError(
                    "trusted_session managed inventory is unavailable or invalid"
                ) from exc
            if not aiops_url:
                raise RunnerConfigError("trusted_session.aiops_url is required when enabled")
            parsed_aiops_url = urlsplit(aiops_url)
            if (
                parsed_aiops_url.query
                or parsed_aiops_url.fragment
                or not parsed_aiops_url.path.endswith(
                    "/aiops/repair-sessions/callbacks/events"
                )
            ):
                raise RunnerConfigError(
                    "trusted_session.aiops_url must end with "
                    "/aiops/repair-sessions/callbacks/events and have no "
                    "query or fragment"
                )
            if token_env != "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN":
                raise RunnerConfigError(
                    "trusted_session.token_env must be "
                    "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"
                )
            if admin_token_env != "RUNNER_SHARED_TOKEN":
                raise RunnerConfigError(
                    "trusted_session.admin_token_env must be RUNNER_SHARED_TOKEN"
                )
            if key_env or not key_file:
                raise RunnerConfigError(
                    "trusted_session must use a local transcript key file"
                )
            expected_instance_id = str(data.get("expected_runner_instance_id", "") or "").strip()
            if expected_instance_id:
                try:
                    if str(uuid.UUID(expected_instance_id)) != expected_instance_id:
                        raise ValueError("non-canonical")
                except ValueError as exc:
                    raise RunnerConfigError(
                        "trusted_session.expected_runner_instance_id must be a canonical UUID when set"
                    ) from exc
        return cls(
            enabled=enabled,
            target_scope=target_scope,
            target_allowlist=tuple(dict.fromkeys(item.strip() for item in allowlist)),
            inventory_dir=_resolve_path(data.get("inventory_dir", "config")),
            project_dir=_resolve_path(data.get("project_dir", "agent-project-trusted")),
            journal_dir=_resolve_path(data.get("journal_dir", "state/trusted-sessions")),
            transcript_dir=_resolve_path(data.get("transcript_dir", "state/trusted-transcripts")),
            session_store_dir=_resolve_path(
                data.get("session_store_dir", "state/trusted-claude-config")
            ),
            aiops_url=aiops_url,
            token_env=token_env,
            runner_provider_id=str(data.get("runner_provider_id", "") or "").strip(),
            runner_instance_id_file=_resolve_path(
                str(data.get("runner_instance_id_file", "state/runner-instance-id") or "")
            ),
            expected_runner_instance_id=str(
                data.get("expected_runner_instance_id", "") or ""
            ).strip(),
            runner_config_version=config_version,
            admin_token_env=admin_token_env,
            approval_ttl_sec=ttl_values["approval_ttl_sec"],
            diagnosis_timeout_sec=ttl_values["diagnosis_timeout_sec"],
            diagnosis_command_budget=ttl_values["diagnosis_command_budget"],
            execution_ttl_sec=ttl_values["execution_ttl_sec"],
            risk_ttl_sec=ttl_values["risk_ttl_sec"],
            transcript_retention_days=ttl_values["transcript_retention_days"],
            encryption_key_env=key_env,
            encryption_key_file=_resolve_path(key_file),
            encryption_key_id=key_id,
        )


@dataclass
class TrustedInspectionConfig:
    """Manual multi-target inspection configuration."""

    enabled: bool = False
    journal_dir: str = "state/trusted-inspections"
    aiops_url: str = ""
    diagnosis_timeout_sec: int = 300
    diagnosis_command_budget: int = 20
    retention_days: int = 30

    @classmethod
    def from_dict(cls, data: dict) -> "TrustedInspectionConfig":
        data = data or {}
        allowed = {
            "enabled", "journal_dir", "aiops_url",
            "diagnosis_timeout_sec", "diagnosis_command_budget",
            "retention_days",
        }
        unknown = set(data) - allowed
        if unknown:
            raise RunnerConfigError(
                f"trusted_inspection: unsupported field(s): {', '.join(sorted(unknown))}"
            )
        timeout = _trusted_positive_int(data, "diagnosis_timeout_sec", 300)
        budget = _trusted_positive_int(data, "diagnosis_command_budget", 20)
        retention_days = _trusted_positive_int(data, "retention_days", 30)
        if timeout > 600:
            raise RunnerConfigError("trusted_inspection.diagnosis_timeout_sec must be <= 600")
        if budget > 40:
            raise RunnerConfigError("trusted_inspection.diagnosis_command_budget must be <= 40")
        aiops_url = _http_url(
            data.get("aiops_url", ""), label="trusted_inspection.aiops_url", allow_empty=True
        )
        enabled = _safe_bool(data.get("enabled", False))
        if enabled and (
            not aiops_url
            or not urlsplit(aiops_url).path.endswith(
                "/aiops/inspection-batches/callbacks/events"
            )
        ):
            raise RunnerConfigError(
                "trusted_inspection.aiops_url must end with "
                "/aiops/inspection-batches/callbacks/events"
            )
        return cls(
            enabled=enabled,
            journal_dir=_resolve_path(data.get("journal_dir", "state/trusted-inspections")),
            aiops_url=aiops_url,
            diagnosis_timeout_sec=timeout,
            diagnosis_command_budget=budget,
            retention_days=retention_days,
        )


@dataclass
class KubernetesConfig:
    """Read-only Kubernetes/VKE collection service configuration."""

    enabled: bool = False
    inventory_file: str = "config/kubernetes.local.yaml"
    state_dir: str = "state/kubernetes"
    current_metrics_cache_sec: int = 15
    sync_timeout_sec: int = 300
    inspection_report_version: str = "v1"
    continuous_collection_enabled: bool = False
    collection_interval_sec: int = 15
    collection_memory_limit_mb: int = 128
    log_collection_concurrency: int = 16
    log_all_namespaces: bool = True
    log_request_timeout_sec: int = 10
    reconcile_interval_sec: int = 6 * 60 * 60

    @classmethod
    def from_dict(cls, data: dict) -> "KubernetesConfig":
        data = data or {}
        allowed = {
            "enabled", "inventory_file", "state_dir",
            "current_metrics_cache_sec", "sync_timeout_sec",
            "inspection_report_version",
            "continuous_collection_enabled", "collection_interval_sec",
            "collection_memory_limit_mb", "log_collection_concurrency",
            "log_all_namespaces", "log_request_timeout_sec", "reconcile_interval_sec",
        }
        unknown = set(data) - allowed
        if unknown:
            raise RunnerConfigError(
                f"kubernetes: unsupported field(s): {', '.join(sorted(unknown))}"
            )
        cache_sec = _safe_int(data.get("current_metrics_cache_sec"), 15)
        timeout_sec = _safe_int(data.get("sync_timeout_sec"), 300)
        if cache_sec > 60:
            raise RunnerConfigError("kubernetes.current_metrics_cache_sec must be <= 60")
        if timeout_sec > 1800:
            raise RunnerConfigError("kubernetes.sync_timeout_sec must be <= 1800")
        collection_interval = _safe_int(data.get("collection_interval_sec"), 15)
        memory_limit = _safe_int(data.get("collection_memory_limit_mb"), 128)
        log_concurrency = _safe_int(data.get("log_collection_concurrency"), 16)
        log_timeout = _safe_int(data.get("log_request_timeout_sec"), 10)
        reconcile_interval = _safe_int(data.get("reconcile_interval_sec"), 6 * 60 * 60)
        if not 5 <= collection_interval <= 300:
            raise RunnerConfigError("kubernetes.collection_interval_sec must be between 5 and 300")
        if not 16 <= memory_limit <= 2048:
            raise RunnerConfigError("kubernetes.collection_memory_limit_mb must be between 16 and 2048")
        if not 1 <= log_concurrency <= 64:
            raise RunnerConfigError("kubernetes.log_collection_concurrency must be between 1 and 64")
        if not 1 <= log_timeout <= 60:
            raise RunnerConfigError("kubernetes.log_request_timeout_sec must be between 1 and 60")
        if not 300 <= reconcile_interval <= 24 * 60 * 60:
            raise RunnerConfigError("kubernetes.reconcile_interval_sec must be between 300 and 86400")
        inspection_report_version = str(
            data.get("inspection_report_version", "v1") or ""
        ).strip().lower()
        if inspection_report_version not in {"v1", "v2"}:
            raise RunnerConfigError(
                "kubernetes.inspection_report_version must be v1 or v2"
            )
        return cls(
            enabled=_safe_bool(data.get("enabled", False)),
            inventory_file=_resolve_path(
                str(data.get("inventory_file", "config/kubernetes.local.yaml") or "")
            ),
            state_dir=_resolve_path(str(data.get("state_dir", "state/kubernetes") or "")),
            current_metrics_cache_sec=cache_sec,
            sync_timeout_sec=timeout_sec,
            inspection_report_version=inspection_report_version,
            continuous_collection_enabled=_safe_bool(
                data.get("continuous_collection_enabled", False)
            ),
            collection_interval_sec=collection_interval,
            collection_memory_limit_mb=memory_limit,
            log_collection_concurrency=log_concurrency,
            log_all_namespaces=_safe_bool(data.get("log_all_namespaces", True)),
            log_request_timeout_sec=log_timeout,
            reconcile_interval_sec=reconcile_interval,
        )


def _trusted_positive_int(data: dict, field_name: str, default: int) -> int:
    value = data.get(field_name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RunnerConfigError(f"trusted_session.{field_name} must be a positive integer")
    return value


@dataclass
class RunnerConfig:
    backend: str = "claude-code-headless"
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    token_budget_per_hour: int = 200000
    dedup_window_sec: int = 300
    rate_limit_per_min: int = 60
    deadletter_dir: str = "state/deadletter"
    trusted_session: TrustedSessionConfig = field(default_factory=TrustedSessionConfig)
    trusted_inspection: TrustedInspectionConfig = field(
        default_factory=TrustedInspectionConfig
    )
    kubernetes: KubernetesConfig = field(default_factory=KubernetesConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "RunnerConfig":
        data = data or {}
        wh = data.get("webhook", {}) or {}
        listen = wh.get("listen", "127.0.0.1:8080")
        host, port = _parse_listen(listen)
        webhook = WebhookConfig(
            host=host,
            port=port,
            shared_token_env=wh.get("shared_token_env", "RUNNER_SHARED_TOKEN"),
            hmac_secret_env=wh.get("hmac_secret_env"),
            ip_allowlist=tuple(wh.get("ip_allowlist", ["127.0.0.0/8"]) or []),
        )
        trusted_session = TrustedSessionConfig.from_dict(
            data.get("trusted_session", {}) or {}
        )
        trusted_inspection = TrustedInspectionConfig.from_dict(
            data.get("trusted_inspection", {}) or {}
        )
        kubernetes = KubernetesConfig.from_dict(data.get("kubernetes", {}) or {})
        if trusted_inspection.enabled and not trusted_session.enabled:
            raise RunnerConfigError(
                "trusted_inspection.enabled requires trusted_session.enabled"
            )
        return cls(
            backend=data.get("backend", "claude-code-headless"),
            webhook=webhook,
            token_budget_per_hour=int(data.get("token_budget_per_hour", 200000)),
            dedup_window_sec=int(data.get("dedup_window_sec", 300)),
            rate_limit_per_min=int(data.get("rate_limit_per_min", 60)),
            deadletter_dir=_resolve_path(data.get("deadletter_dir", "state/deadletter")),
            trusted_session=trusted_session,
            trusted_inspection=trusted_inspection,
            kubernetes=kubernetes,
        )


def load_config(path: str | None = None) -> RunnerConfig:
    path = path or os.environ.get("RUNNER_CONFIG") or "config/runner.yaml"
    if not os.path.isfile(path):
        data = {}
    else:
        data = _load_mapping(path, label=os.path.basename(path))
    data = _deep_merge(data, _runner_local_overlay())
    config = RunnerConfig.from_dict(data)
    config.trusted_session.runner_config_path = os.path.abspath(path)
    return config
