import pytest

from runner.config import (
    RunnerConfig,
    RunnerConfigError,
    TrustedSessionConfig,
    TrustedInspectionConfig,
    load_config,
)


def test_runner_default_deadletter_dir_is_relative_to_repo_root():
    cfg = RunnerConfig.from_dict({})

    assert cfg.deadletter_dir.endswith("state/deadletter")
    assert "/var/lib" not in cfg.deadletter_dir


def test_kubernetes_continuous_collection_is_disabled_by_default():
    assert RunnerConfig.from_dict({}).kubernetes.continuous_collection_enabled is False


def test_trusted_session_defaults_to_callback_token_and_shared_admin_token():
    trusted = RunnerConfig.from_dict({}).trusted_session

    assert trusted.token_env == "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"
    assert trusted.admin_token_env == "RUNNER_SHARED_TOKEN"


def test_load_config_defaults_to_safe_public_runner_config(monkeypatch):
    monkeypatch.setattr("runner.config.sys.platform", "linux")

    config = load_config()

    assert (config.webhook.host, config.webhook.port) == ("0.0.0.0", 8002)
    assert config.trusted_session.enabled is False
    assert config.trusted_inspection.enabled is False


def test_trusted_session_rejects_alternate_callback_token_name():
    with pytest.raises(RunnerConfigError, match="token_env must be"):
        TrustedSessionConfig.from_dict(
            {
                "enabled": True,
                "target_allowlist": ["host"],
                "aiops_url": "http://aiops/aiops/repair-sessions/callbacks/events",
                "token_env": "SOME_OTHER_CALLBACK_TOKEN",
                    "admin_token_env": "RUNNER_SHARED_TOKEN",
                    "encryption_key_file": "state/trusted-transcript.key",
                "encryption_key_id": "v1",
            },
            platform="linux",
        )


def test_runner_local_config_rejects_unsafe_section(tmp_path, monkeypatch):
    local = tmp_path / "local.yaml"
    local.write_text("command_policy: {}\n")
    monkeypatch.setenv("RUNNER_LOCAL_CONFIG", str(local))

    with pytest.raises(RunnerConfigError, match="unsupported section"):
        load_config(str(tmp_path / "missing.yaml"))


def test_runner_local_config_accepts_kubernetes_wizard_overlay(
    tmp_path, monkeypatch
):
    local = tmp_path / "runner.local.yaml"
    local.write_text(
        """
kubernetes:
  enabled: true
  inventory_file: config/kubernetes.local.yaml
  state_dir: state/kubernetes
  current_metrics_cache_sec: 15
  sync_timeout_sec: 300
  inspection_report_version: v2
  continuous_collection_enabled: true
  collection_interval_sec: 15
  collection_memory_limit_mb: 128
  log_collection_concurrency: 16
  log_all_namespaces: true
  log_request_timeout_sec: 10
  reconcile_interval_sec: 21600
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("RUNNER_LOCAL_CONFIG", str(local))

    config = load_config(str(tmp_path / "missing.yaml"))

    assert config.kubernetes.enabled is True
    assert config.kubernetes.inventory_file.endswith(
        "config/kubernetes.local.yaml"
    )
    assert config.kubernetes.state_dir.endswith("state/kubernetes")
    assert config.kubernetes.current_metrics_cache_sec == 15
    assert config.kubernetes.sync_timeout_sec == 300
    assert config.kubernetes.inspection_report_version == "v2"
    assert config.kubernetes.continuous_collection_enabled is True
    assert config.kubernetes.collection_interval_sec == 15
    assert config.kubernetes.collection_memory_limit_mb == 128
    assert config.kubernetes.log_collection_concurrency == 16
    assert config.kubernetes.log_all_namespaces is True
    assert config.kubernetes.log_request_timeout_sec == 10
    assert config.kubernetes.reconcile_interval_sec == 21600


def test_runner_local_config_overrides_only_callback_destinations(
    tmp_path, monkeypatch
):
    base = tmp_path / "runner.yaml"
    base.write_text(
        """
trusted_session:
  enabled: false
  aiops_url: https://base.example/aiops/repair-sessions/callbacks/events
trusted_inspection:
  enabled: false
  aiops_url: https://base.example/aiops/inspection-batches/callbacks/events
""".lstrip(),
        encoding="utf-8",
    )
    local = tmp_path / "runner.local.yaml"
    local.write_text(
        """
trusted_session:
  aiops_url: https://local.example/aiops/repair-sessions/callbacks/events
trusted_inspection:
  aiops_url: https://local.example/aiops/inspection-batches/callbacks/events
""".lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("RUNNER_LOCAL_CONFIG", str(local))

    config = load_config(str(base))

    assert config.trusted_session.aiops_url.startswith("https://local.example/")
    assert config.trusted_inspection.aiops_url.startswith("https://local.example/")
    assert config.trusted_session.enabled is False
    assert config.trusted_inspection.enabled is False


@pytest.mark.parametrize(
    "local_config",
    [
        "trusted_session:\n  enabled: true\n",
        "trusted_session:\n  admin_token_env: RUNNER_TRUSTED_ADMIN_TOKEN\n",
        "trusted_inspection:\n  enabled: true\n",
    ],
)
def test_runner_local_config_rejects_trusted_policy_overrides(
    tmp_path, monkeypatch, local_config
):
    local = tmp_path / "runner.local.yaml"
    local.write_text(local_config, encoding="utf-8")
    monkeypatch.setenv("RUNNER_LOCAL_CONFIG", str(local))

    with pytest.raises(RunnerConfigError, match="unsupported"):
        load_config(str(tmp_path / "missing.yaml"))


@pytest.mark.parametrize(
    "data, message",
    [
        (
            {"webhook": {"listen": "127.0.0.1:99999"}},
            "1..65535",
        ),
    ],
)
def test_runner_rejects_invalid_network_endpoints(data, message):
    with pytest.raises(RunnerConfigError, match=message):
        RunnerConfig.from_dict(data)


def test_runner_rejects_ipv6_until_server_supports_it():
    with pytest.raises(RunnerConfigError, match="host:port"):
        RunnerConfig.from_dict(
            {"webhook": {"listen": "[::1]:8002"}}
        )


def test_trusted_inspection_accepts_ten_minute_timeout():
    cfg = TrustedInspectionConfig.from_dict({"diagnosis_timeout_sec": 600})

    assert cfg.diagnosis_timeout_sec == 600


def test_trusted_inspection_rejects_timeout_above_ten_minutes():
    with pytest.raises(
        RunnerConfigError,
        match=r"trusted_inspection\.diagnosis_timeout_sec must be <= 600",
    ):
        TrustedInspectionConfig.from_dict({"diagnosis_timeout_sec": 601})
