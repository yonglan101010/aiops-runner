import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "configure_wizard.py"
)
SPEC = importlib.util.spec_from_file_location(
    "aiops_runner_configure_wizard", SCRIPT_PATH
)
assert SPEC is not None and SPEC.loader is not None
configure_wizard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = configure_wizard
SPEC.loader.exec_module(configure_wizard)


class FakeTransaction:
    def __init__(self, files):
        self.files = files
        self.staged = {}
        self.deleted = set()

    def read(self, path):
        if path in self.staged:
            value = self.staged[path]
            return value.encode() if isinstance(value, str) else value
        if path in self.files:
            return self.files[path]
        return path.read_bytes() if path.is_file() else None

    def stage_text(self, path, text, _mode=0o600):
        self.staged[path] = text

    def stage_bytes(self, path, data, _mode=0o600):
        self.staged[path] = data

    def delete(self, path):
        self.deleted.add(path)
        self.staged.pop(path, None)

    def watch(self, _path):
        return None


def test_configure_env_modify_prompts_for_existing_trusted_tokens(monkeypatch):
    env_path = configure_wizard.ROOT / ".env"
    runner_path = configure_wizard.CONFIG / "runner.yaml"
    tx = FakeTransaction(
        {
            env_path: (
                b"RUNNER_SHARED_TOKEN='existing-shared'\n"
                b"RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN='existing-callback'\n"
            ),
            runner_path: configure_wizard.dump_yaml(
                {
                    "trusted_session": {
                        "enabled": True,
                        "token_env": "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN",
                        "admin_token_env": "RUNNER_SHARED_TOKEN",
                    }
                }
            ).encode(),
        }
    )
    monkeypatch.setattr(configure_wizard, "action", lambda *_args: "m")
    prompts = []
    monkeypatch.setattr(
        configure_wizard,
        "secret",
        lambda name, current=None: prompts.append((name, current)) or current,
    )

    configure_wizard.configure_env(tx)

    configured = configure_wizard.env_values(tx.staged[env_path].encode())
    assert prompts == [
        ("RUNNER_SHARED_TOKEN", "existing-shared"),
        ("RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN", "existing-callback"),
    ]
    assert configured["RUNNER_SHARED_TOKEN"] == "existing-shared"
    assert configured["RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"] == "existing-callback"


def test_stage_kubernetes_env_merges_into_staged_env():
    env_path = configure_wizard.ROOT / ".env"
    tx = FakeTransaction(
        {env_path: b"RUNNER_SHARED_TOKEN='existing-shared'\n"}
    )
    setup = configure_wizard.KubernetesEnvSetup(
        values={name: f"configured-{name.lower()}" for name in configure_wizard.VOLCENGINE_ENV_NAMES}
    )

    configure_wizard._stage_kubernetes_env(tx, setup)

    configured = configure_wizard.env_values(tx.staged[env_path].encode())
    assert configured["RUNNER_SHARED_TOKEN"] == "existing-shared"
    for name, value in setup.values.items():
        assert configured[name] == value


def test_inspection_callback_url_preserves_reverse_proxy_prefix():
    repair_url = (
        "https://aiops.example:8443/control"
        "/aiops/repair-sessions/callbacks/events"
    )

    assert configure_wizard._inspection_callback_url(repair_url) == (
        "https://aiops.example:8443/control"
        "/aiops/inspection-batches/callbacks/events"
    )
    assert configure_wizard._repair_callback_url(
        "https://aiops.example:8443/control"
        "/aiops/inspection-batches/callbacks/events"
    ) == repair_url


@pytest.mark.parametrize(
    "invalid_url",
    [
        "https://aiops.example/aiops/inspection-batches/callbacks/events",
        "https://aiops.example/aiops/repair-sessions/callbacks/events?x=1",
    ],
)
def test_inspection_callback_url_rejects_invalid_repair_endpoint(invalid_url):
    with pytest.raises(ValueError, match="回调 URL 无效"):
        configure_wizard._inspection_callback_url(invalid_url)


def test_configure_runner_syncs_repair_and_inspection_callbacks(monkeypatch):
    runner_path = configure_wizard.CONFIG / "runner.yaml"
    local_path = configure_wizard.CONFIG / "runner.local.yaml"
    tx = FakeTransaction(
        {
            local_path: configure_wizard.dump_yaml(
                {"webhook": {"listen": "127.0.0.1:8002"}}
            ).encode(),
            runner_path: configure_wizard.dump_yaml(
                {
                    "trusted_session": {
                        "enabled": True,
                        "aiops_url": (
                            "http://old.example"
                            "/aiops/repair-sessions/callbacks/events"
                        ),
                    },
                    "trusted_inspection": {
                        "enabled": True,
                        "journal_dir": "state/trusted-inspections",
                        "aiops_url": (
                            "http://old.example"
                            "/aiops/inspection-batches/callbacks/events"
                        ),
                    },
                }
            ).encode(),
        }
    )
    repair_url = (
        "http://new.example:8080"
        "/aiops/repair-sessions/callbacks/events"
    )
    monkeypatch.setattr(configure_wizard, "action", lambda *_args: "m")
    monkeypatch.setattr(
        configure_wizard, "required", lambda *_args, **_kwargs: "0.0.0.0:8002"
    )
    monkeypatch.setattr(
        configure_wizard, "_trusted_url", lambda *_args: repair_url
    )

    configure_wizard.configure_runner(tx)

    updated_base = configure_wizard.load_yaml(
        tx.staged[runner_path].encode(), "runner.yaml"
    )
    updated_local = configure_wizard.load_yaml(
        tx.staged[local_path].encode(), "runner.local.yaml"
    )
    assert "aiops_url" not in updated_base["trusted_session"]
    assert "aiops_url" not in updated_base["trusted_inspection"]
    assert updated_local["trusted_session"]["aiops_url"] == repair_url
    assert updated_local["trusted_inspection"]["aiops_url"] == (
        "http://new.example:8080"
        "/aiops/inspection-batches/callbacks/events"
    )
    assert updated_base["trusted_inspection"]["enabled"] is True
    assert updated_base["trusted_inspection"]["journal_dir"] == (
        "state/trusted-inspections"
    )
    assert updated_local["webhook"]["listen"] == "0.0.0.0:8002"


def test_configure_runner_migrates_legacy_callback_and_is_idempotent(monkeypatch):
    runner_path = configure_wizard.CONFIG / "runner.yaml"
    local_path = configure_wizard.CONFIG / "runner.local.yaml"
    legacy_url = (
        "https://legacy.example/control"
        "/aiops/repair-sessions/callbacks/events"
    )
    tx = FakeTransaction(
        {
            local_path: configure_wizard.dump_yaml(
                {"webhook": {"listen": "127.0.0.1:8002"}}
            ).encode(),
            runner_path: configure_wizard.dump_yaml(
                {
                    "trusted_session": {
                        "enabled": True,
                        "aiops_url": legacy_url,
                    },
                    "trusted_inspection": {
                        "enabled": True,
                        "aiops_url": (
                            "https://legacy.example/control"
                            "/aiops/inspection-batches/callbacks/events"
                        ),
                    },
                }
            ).encode(),
        }
    )
    monkeypatch.setattr(configure_wizard, "action", lambda *_args: "m")
    monkeypatch.setattr(
        configure_wizard,
        "required",
        lambda prompt, default, **_kwargs: default,
    )

    configure_wizard.configure_runner(tx)
    configure_wizard.configure_runner(tx)

    updated_base = configure_wizard.load_yaml(
        tx.staged[runner_path].encode(), "runner.yaml"
    )
    updated_local = configure_wizard.load_yaml(
        tx.staged[local_path].encode(), "runner.local.yaml"
    )
    assert "aiops_url" not in updated_base["trusted_session"]
    assert "aiops_url" not in updated_base["trusted_inspection"]
    assert updated_local["trusted_session"]["aiops_url"] == legacy_url
    assert updated_local["trusted_inspection"]["aiops_url"] == (
        "https://legacy.example/control"
        "/aiops/inspection-batches/callbacks/events"
    )


def test_kubeconfig_document_rejects_exec_authentication():
    payload = yaml.safe_dump(
        {
            "current-context": "vke-prod",
            "contexts": [{"name": "vke-prod", "context": {}}],
            "users": [
                {
                    "name": "operator",
                    "user": {"exec": {"command": "credential-helper"}},
                }
            ],
        }
    ).encode()

    with pytest.raises(ValueError, match="exec 认证插件"):
        configure_wizard._kubeconfig_document(payload)


def test_env_values_and_update_support_volcengine_credentials():
    raw = (
        b"RUNNER_SHARED_TOKEN='runner-token'\n"
        b"VOLCENGINE_ACCESS_KEY_ID='old-ak'\n"
        b"PRESERVE_ME='yes'\n"
    )

    parsed = configure_wizard.env_values(raw)
    assert parsed["VOLCENGINE_ACCESS_KEY_ID"] == "old-ak"
    updated = configure_wizard._update_env_file(
        raw,
        {
            "VOLCENGINE_ACCESS_KEY_ID": "new-ak",
            "VOLCENGINE_ACCESS_KEY_SECRET": "new-sk",
        },
        preserve_existing=True,
    )
    assert "VOLCENGINE_ACCESS_KEY_ID='new-ak'" in updated
    assert "VOLCENGINE_ACCESS_KEY_SECRET='new-sk'" in updated
    assert "PRESERVE_ME='yes'" in updated


def test_configure_kubernetes_stages_cluster_and_provider_env(tmp_path, monkeypatch):
    source = tmp_path / "vke.kubeconfig"
    source.write_text(
        yaml.safe_dump(
            {
                "current-context": "vke-prod",
                "contexts": [{"name": "vke-prod", "context": {}}],
                "users": [{"name": "operator", "user": {"token": "local-token"}}],
            }
        ),
        encoding="utf-8",
    )
    tx = FakeTransaction({})
    choices = iter(("b", "a", "f", "c"))
    monkeypatch.setattr(configure_wizard, "choose", lambda *_args: next(choices))
    monkeypatch.setattr(
        configure_wizard,
        "_ask_bool",
        lambda prompt, _default=False: prompt.startswith("配置 VMP")
        or prompt.startswith("配置 TLS"),
    )
    values = {
        "Runner 集群 ID": "vke-prod",
        "集群显示名称": "火山云生产集群",
        "环境标识": "prod",
        "kubeconfig 来源文件": str(source),
        "使用的 context": "vke-prod",
        "VMP Region": "cn-beijing",
        "VMP Workspace ID": "workspace-1",
        "TLS Region": "cn-beijing",
        "TLS 日志 Topic ID": "log-topic-1",
        "TLS 事件 Topic ID": "event-topic-1",
    }
    monkeypatch.setattr(
        configure_wizard,
        "required",
        lambda prompt, *_args, **_kwargs: values[prompt],
    )
    monkeypatch.setattr(
        configure_wizard,
        "ask",
        lambda prompt, *_args, **_kwargs: "prod,ops"
        if prompt.startswith("Namespace")
        else "",
    )
    monkeypatch.setattr(
        configure_wizard,
        "secret",
        lambda name, _current=None: "configured-ak"
        if name.endswith("_ID")
        else "configured-sk",
    )

    setup = configure_wizard.configure_kubernetes(tx)

    assert setup is not None
    assert setup.values == {
        "VOLCENGINE_ACCESS_KEY_ID": "configured-ak",
        "VOLCENGINE_ACCESS_KEY_SECRET": "configured-sk",
    }
    inventory = yaml.safe_load(tx.staged[configure_wizard.KUBERNETES_INVENTORY_PATH])
    assert inventory["clusters"][0]["namespace_allowlist"] == ["prod", "ops"]
    assert inventory["clusters"][0]["vmp"]["workspace_id"] == "workspace-1"
    assert inventory["clusters"][0]["tls"]["event_topic_id"] == "event-topic-1"
    runner_local = yaml.safe_load(
        tx.staged[configure_wizard.CONFIG / "runner.local.yaml"]
    )
    assert runner_local["kubernetes"]["enabled"] is True
    assert not (
        set(runner_local["kubernetes"])
        & set(configure_wizard.KUBERNETES_PARAMETER_FIELDS)
    )
    target = configure_wizard.CONFIG / "keys" / "vke-prod.kubeconfig"
    assert tx.staged[target] == source.read_bytes()


def test_configure_kubernetes_parameters_are_opt_in(monkeypatch):
    runner_local_path = configure_wizard.CONFIG / "runner.local.yaml"
    inventory_path = configure_wizard.KUBERNETES_INVENTORY_PATH
    tx = FakeTransaction(
        {
            runner_local_path: configure_wizard.dump_yaml(
                {"kubernetes": {"enabled": True}}
            ).encode(),
            inventory_path: configure_wizard.dump_yaml(
                {"clusters": [{"id": "vke-prod"}]}
            ).encode(),
        }
    )
    monkeypatch.setattr(configure_wizard, "choose", lambda *_args: "p")
    monkeypatch.setattr(
        configure_wizard,
        "_ask_bool",
        lambda prompt, _default=False: prompt.startswith("启用 Kubernetes"),
    )
    values = {
        "当前指标缓存秒数": "20",
        "资产同步超时秒数": "600",
        "持续采集间隔秒数": "30",
        "采集内存队列上限 MiB": "256",
        "日志采集并发数": "8",
        "单次日志请求超时秒数": "20",
        "资源全量校准间隔秒数": "43200",
    }
    monkeypatch.setattr(
        configure_wizard,
        "required",
        lambda prompt, *_args, **_kwargs: values[prompt],
    )

    assert configure_wizard.configure_kubernetes(tx) is None

    updated = yaml.safe_load(tx.staged[runner_local_path])
    assert updated["kubernetes"] == {
        "enabled": True,
        "inventory_file": "config/kubernetes.local.yaml",
        "state_dir": "state/kubernetes",
        "inspection_report_version": "v2",
        "current_metrics_cache_sec": 20,
        "sync_timeout_sec": 600,
        "continuous_collection_enabled": True,
        "collection_interval_sec": 30,
        "collection_memory_limit_mb": 256,
        "log_collection_concurrency": 8,
        "log_all_namespaces": False,
        "log_request_timeout_sec": 20,
        "reconcile_interval_sec": 43200,
    }
    assert inventory_path not in tx.staged


def test_kubernetes_validation_uses_transaction_candidate(tmp_path, monkeypatch):
    inventory_path = configure_wizard.KUBERNETES_INVENTORY_PATH
    kubeconfig_path = configure_wizard.CONFIG / "keys" / "vke-prod.kubeconfig"
    inventory = yaml.safe_dump(
        {
            "clusters": [
                {
                    "id": "vke-prod",
                    "display_name": "VKE",
                    "environment": "prod",
                    "kubeconfig_path": "config/keys/vke-prod.kubeconfig",
                    "context": "vke-prod",
                    "namespace_allowlist": [],
                    "vmp": {"region": "cn-beijing", "workspace_id": "workspace-1"},
                    "tls": {},
                }
            ]
        }
    ).encode()
    kubeconfig = yaml.safe_dump(
        {
            "current-context": "vke-prod",
            "contexts": [{"name": "vke-prod", "context": {}}],
            "users": [{"name": "operator", "user": {"token": "local-token"}}],
        }
    ).encode()
    tx = FakeTransaction(
        {inventory_path: inventory, kubeconfig_path: kubeconfig}
    )
    tx.dir = tmp_path / "transaction"
    tx.dir.mkdir()
    import runner.kubernetes as kubernetes_module

    class FakeOfficialClient:
        def identity(self, cluster):
            kubernetes_module.KubernetesInventory.validate_local_file(cluster)
            return {"cluster_uid": "cluster-uid-1", "version": "v1.30.1"}

    monkeypatch.setattr(
        kubernetes_module,
        "OfficialKubernetesClient",
        FakeOfficialClient,
    )
    runner_config = SimpleNamespace(
        kubernetes=SimpleNamespace(
            enabled=True,
            inventory_file=str(inventory_path),
        )
    )

    configure_wizard._validate_kubernetes_configuration(
        tx,
        runner_config,
        {
            "VOLCENGINE_ACCESS_KEY_ID": "ak",
            "VOLCENGINE_ACCESS_KEY_SECRET": "sk",
        },
    )
