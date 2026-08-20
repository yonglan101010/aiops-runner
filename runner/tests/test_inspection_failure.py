import json
import threading
from types import SimpleNamespace
from uuid import uuid4

import pytest

from runner.inspection import (
    _CLAUDE_REPORT_VALIDATOR,
    _COMMAND_BUDGET_SUMMARY_PREFIX,
    InspectionManager,
    _is_command_budget_exhausted,
    _mark_command_budget_limited,
    _normalize_report_status,
    _public_inspection_failure,
    _unknown_fallback_report,
    _validated_kubernetes_interpretation,
    _validated_model_report,
    _validate_report_semantics,
)
from runner.config import TrustedInspectionConfig
from runner.trusted_session import TrustedSessionError


_BASELINE_CATEGORIES = (
    "cpu",
    "memory",
    "disk",
    "inode",
    "service",
    "network",
    "process",
    "container",
)


def _report(*, overall_status="HEALTHY", unknown_category=None, findings=None):
    return {
        "overall_status": overall_status,
        "baseline_checks": [
            {
                "category": category,
                "status": "UNKNOWN" if category == unknown_category else "PASS",
            }
            for category in _BASELINE_CATEGORIES
        ],
        "findings": findings or [],
    }


def _complete_report() -> dict:
    report = _unknown_fallback_report()
    report["summary"] = "基于前二十次只读命令收集到的证据生成报告。"
    for check in report["baseline_checks"]:
        check["status"] = "PASS"
        check["summary"] = "已有只读命令证据"
    return report


class _Journal:
    def __init__(self):
        self.created = []
        self.events = []
        self.updates = []

    def create(self, metadata):
        self.created.append(metadata)

    def append_event(self, session_id, event):
        self.events.append((session_id, event))

    def update(self, session_id, **changes):
        self.updates.append((session_id, changes))


class _Inventory:
    def ssh_profile(self, target_id):
        assert target_id == "target-1"
        return {"command_timeout_sec": 1}


class _Sender:
    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [(200, "")])

    def post(self, url, body, headers, *, timeout):
        self.requests.append((url, json.loads(body), headers, timeout))
        return self.responses.pop(0) if self.responses else (200, "")


class _BudgetAdapter:
    def __init__(self, *, recovery_report=None, recovery_error=None, initial_error=None):
        self.calls = []
        self.recovery_report = recovery_report
        self.recovery_error = recovery_error
        self.initial_error = initial_error

    def run(self, **kwargs):
        self.calls.append(kwargs)
        if len(self.calls) == 1:
            for index in range(20):
                kwargs["event_sink"]({
                    "event_type": "command_started",
                    "command": f"read-only-{index}",
                })
            if self.initial_error is not None:
                raise self.initial_error
            return SimpleNamespace(events=({
                "event_type": "inspection_report_created",
                "inspection_report": _complete_report(),
            },))
        if self.recovery_error is not None:
            raise self.recovery_error
        return SimpleNamespace(events=({
            "event_type": "inspection_report_created",
            "inspection_report": self.recovery_report or _complete_report(),
        },))


def _manager_for_budget_test(tmp_path, monkeypatch, adapter):
    journal = _Journal()
    sender = _Sender()
    orchestrator = SimpleNamespace(
        adapter=adapter,
        journal=journal,
        config=SimpleNamespace(
            runner_instance_id=str(uuid4()),
            runner_config_path="",
            project_dir=str(tmp_path),
            session_store_dir=str(tmp_path / "sessions"),
            runner_config_version="test",
        ),
        os_user="runner-test",
        _lifecycle_gate=object(),
        _pre_spawn=lambda *_args: None,
        _persist_live_event=lambda session_id, event: journal.append_event(session_id, event),
    )
    config = TrustedInspectionConfig(
        enabled=True,
        journal_dir=str(tmp_path / "inspection-journals"),
        aiops_url="https://aiops.example/aiops/inspection-batches/callbacks/events",
        diagnosis_timeout_sec=30,
        diagnosis_command_budget=20,
        retention_days=1,
    )
    manager = object.__new__(InspectionManager)
    manager.config = config
    manager.inventory = _Inventory()
    manager.orchestrator = orchestrator
    manager.sender = sender
    manager.token_env = "BUDGET_TEST_CALLBACK_TOKEN"
    manager.proposal_ready = None
    manager.context_provider = None
    manager.kubernetes = None
    manager.callback_failure = None
    from runner.inspection import InspectionStore
    manager.store = InspectionStore(config.journal_dir)
    manager._gate = threading.RLock()
    manager._callback_replay_gate = threading.Lock()
    manager._cancelled = set()
    manager._collect_service_inventory = lambda _profile, **_kwargs: {
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
    monkeypatch.setattr(
        "runner.inspection.config_fingerprint", lambda _config: "sha256:test"
    )
    monkeypatch.setenv("BUDGET_TEST_CALLBACK_TOKEN", "test-token")
    batch_id = str(uuid4())
    session_id = str(uuid4())
    manager.store.save({
        "batch_id": batch_id,
        "tenant_id": "workspace-test",
        "runner_provider_id": str(uuid4()),
        "runner_instance_id": str(uuid4()),
        "status": "RUNNING",
        "targets": [{
            "session_id": session_id,
            "logical_target_id": "target-1",
            "display_name": "target-1",
            "environment": "test",
            "target_type": "LINUX_HOST",
            "status": "QUEUED",
            "failure": {"code": "INSPECTION_COMMAND_BUDGET_EXHAUSTED"},
        }],
        "request_fingerprint": "sha256:test",
        "snapshot_revision": 0,
        "started_at": None,
        "finished_at": None,
    })
    return manager, batch_id, session_id, journal, sender


def test_model_authentication_failure_is_public_safe():
    error = TrustedSessionError(
        "TRUSTED_CLAUDE_RESULT_ERROR",
        "Failed to authenticate with api_key=secret-value",
        failure_code="MODEL_AUTHENTICATION_FAILED",
        http_status=401,
    )

    assert _public_inspection_failure(error) == {
        "code": "MODEL_AUTHENTICATION_FAILED",
        "http_status": 401,
    }


def test_unknown_exception_has_closed_generic_classification():
    assert _public_inspection_failure(RuntimeError("api_key=secret-value")) == {
        "code": "INSPECTION_FAILED",
    }


def test_target_and_inventory_failures_are_classified_by_layer():
    target_error = TrustedSessionError(
        "TRUSTED_TARGET_CONNECTION_UNAVAILABLE", "SSH config contains a secret"
    )
    inventory_error = TrustedSessionError(
        "TRUSTED_INVENTORY_UNAVAILABLE", "inventory contains a secret"
    )

    assert _public_inspection_failure(target_error) == {
        "code": "TARGET_CONNECTION_FAILED",
    }
    assert _public_inspection_failure(inventory_error) == {
        "code": "INSPECTION_CONFIGURATION_INVALID",
    }


def test_report_status_is_forced_to_warning_when_a_warning_finding_exists():
    report = _report(
        findings=[{"severity": "WARNING", "recommendation": "review evidence"}]
    )

    _normalize_report_status(report)
    _validate_report_semantics(report)

    assert report["overall_status"] == "WARNING"


def test_report_status_is_forced_to_unknown_when_baseline_evidence_is_missing():
    report = _report(unknown_category="container")

    _normalize_report_status(report)
    _validate_report_semantics(report)

    assert report["overall_status"] == "UNKNOWN"


def test_unrepairable_report_semantics_remain_closed():
    report = _report()
    report["baseline_checks"].pop()

    _normalize_report_status(report)

    with pytest.raises(TrustedSessionError) as caught:
        _validate_report_semantics(report)
    assert caught.value.code == "TRUSTED_INSPECTION_BASELINE_INCOMPLETE"


def test_missing_structured_output_has_schema_valid_unknown_fallback():
    report = _unknown_fallback_report()

    assert list(_CLAUDE_REPORT_VALIDATOR.iter_errors(report)) == []
    _normalize_report_status(report)
    _validate_report_semantics(report)

    assert report["overall_status"] == "UNKNOWN"
    assert len(report["baseline_checks"]) == 8
    assert {item["status"] for item in report["baseline_checks"]} == {"UNKNOWN"}


def test_invalid_model_report_requests_format_recovery():
    assert _validated_model_report(None) is None
    assert _validated_model_report({"overall_status": "HEALTHY"}) is None


def test_kubernetes_interpretation_must_reference_known_findings_and_forbid_commands():
    evidence = {"findings": [{"finding_id": "finding-1"}]}
    valid = {
        "executive_summary": "存在一个需要关注的根因组。",
        "priorities": [{
            "finding_id": "finding-1",
            "explanation": "事实：工作负载可用副本不足。",
            "impact": "可能降低服务容量。",
            "recommendation": "请人工核查工作负载 Conditions 和近期事件。",
        }],
        "limitations": [],
    }

    assert _validated_kubernetes_interpretation(valid, evidence) == valid
    assert _validated_kubernetes_interpretation(
        {**valid, "priorities": [{**valid["priorities"][0], "finding_id": "invented"}]},
        evidence,
    ) is None
    assert _validated_kubernetes_interpretation(
        {**valid, "priorities": [{**valid["priorities"][0], "recommendation": "kubectl delete pod api"}]},
        evidence,
    ) is None
    assert _validated_kubernetes_interpretation(
        {**valid, "priorities": [{**valid["priorities"][0], "impact": "影响 99 个 Pod。"}]},
        evidence,
    ) is None
    assert _validated_kubernetes_interpretation(
        {**valid, "priorities": [{**valid["priorities"][0], "explanation": "Pod/invented 未就绪。"}]},
        evidence,
    ) is None
    assert _validated_kubernetes_interpretation(
        {**valid, "executive_summary": "存在一个严重根因。"},
        evidence,
    ) is None


def test_command_budget_failure_is_recoverable_and_report_is_labeled():
    error = TrustedSessionError(
        "TRUSTED_DIAGNOSIS_COMMAND_BUDGET_EXHAUSTED", "budget exhausted"
    )
    report = _report()

    assert _is_command_budget_exhausted(error) is True
    _mark_command_budget_limited(report)

    assert report["summary"].startswith(_COMMAND_BUDGET_SUMMARY_PREFIX)
    assert len(report["summary"]) <= 600
    assert _public_inspection_failure(error) == {
        "code": "INSPECTION_COMMAND_BUDGET_EXHAUSTED",
    }


def test_command_budget_limited_summary_is_idempotent_and_bounded():
    report = _report()
    report["summary"] = "x" * 600

    _mark_command_budget_limited(report)
    first = report["summary"]
    _mark_command_budget_limited(report)

    assert report["summary"] == first
    assert len(report["summary"]) == 600


def test_budget_exhaustion_resumes_without_tools_and_callbacks_report(tmp_path, monkeypatch):
    adapter = _BudgetAdapter(
        initial_error=TrustedSessionError(
            "TRUSTED_DIAGNOSIS_COMMAND_BUDGET_EXHAUSTED", "budget exhausted"
        )
    )
    manager, batch_id, session_id, journal, sender = _manager_for_budget_test(
        tmp_path, monkeypatch, adapter
    )

    manager._inspect_target(batch_id, session_id)
    manager.store.update(batch_id, manager._finish_batch)
    manager._callback(manager.store.load(batch_id))

    assert len(adapter.calls) == 2
    first, recovery = adapter.calls
    assert first["resume"] is False
    assert recovery["resume"] is True
    assert recovery["claude_session_id"] == first["claude_session_id"]
    assert recovery["allow_tools"] is False
    assert recovery["command_budget"] == 0
    assert recovery["target_ssh"] is None
    assert any(event[1]["event_type"] == "inspection_command_budget_reached" for event in journal.events)
    assert sum(event[1].get("event_type") == "command_started" for event in journal.events) == 20

    completed = manager.store.load(batch_id)
    target = completed["targets"][0]
    assert completed["status"] == "SUCCEEDED"
    assert target["status"] == "HEALTHY"
    assert target["failure"] is None
    assert target["terminal_reason"] is None
    assert target["report"]["summary"].startswith(_COMMAND_BUDGET_SUMMARY_PREFIX)
    assert sender.requests[-1][1]["status"] == "SUCCEEDED"
    assert sender.requests[-1][1]["targets"][0]["report"] == target["report"]


def test_budget_exhaustion_uses_unknown_report_when_recovery_fails(tmp_path, monkeypatch):
    adapter = _BudgetAdapter(
        initial_error=TrustedSessionError(
            "TRUSTED_DIAGNOSIS_COMMAND_BUDGET_EXHAUSTED", "budget exhausted"
        ),
        recovery_error=TrustedSessionError("TRUSTED_PROCESS_TIMEOUT", "format timeout"),
    )
    manager, batch_id, session_id, _journal, sender = _manager_for_budget_test(
        tmp_path, monkeypatch, adapter
    )

    manager._inspect_target(batch_id, session_id)
    manager.store.update(batch_id, manager._finish_batch)
    manager._callback(manager.store.load(batch_id))

    completed = manager.store.load(batch_id)
    target = completed["targets"][0]
    assert len(adapter.calls) == 2
    assert completed["status"] == "SUCCEEDED"
    assert target["status"] == "UNKNOWN"
    assert target["failure"] is None
    assert target["terminal_reason"] is None
    assert target["report"]["summary"].startswith(_COMMAND_BUDGET_SUMMARY_PREFIX)
    assert {check["status"] for check in target["report"]["baseline_checks"]} == {"UNKNOWN"}
    assert sender.requests[-1][1]["targets"][0]["failure"] is None


def test_inspection_callback_retries_and_persists_safe_failure_state(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([(503, "http_503"), (503, "http_503"), (503, "http_503")])
    failures = []
    manager.callback_failure = lambda: failures.append(True)
    monkeypatch.setattr("runner.inspection.time.sleep", lambda _seconds: None)

    delivered = manager._callback(manager.store.load(batch_id))

    assert delivered is False
    assert len(manager.sender.requests) == 3
    assert failures == [True]
    stored = manager.store.load(batch_id)
    delivery = stored["callback_delivery"]
    assert delivery["status"] == "RETRY_PENDING"
    assert delivery["retryable"] is True
    assert delivery["retry_count"] == 1
    assert delivery["attempts"] == 3
    assert delivery["http_status"] == 503
    assert delivery["error"] == "http_503"
    assert delivery["next_retry_at"] > 0
    assert "callback_delivery" not in manager._public(stored)


def test_inspection_callback_retries_transient_failure_then_succeeds(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([(503, "http_503"), (200, "")])
    monkeypatch.setattr("runner.inspection.time.sleep", lambda _seconds: None)

    assert manager._callback(manager.store.load(batch_id)) is True
    assert len(manager.sender.requests) == 2
    assert "callback_delivery" not in manager.store.load(batch_id)


def test_terminal_callback_failure_replays_after_persisted_backoff(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([
        (503, "http_503"),
        (503, "http_503"),
        (503, "http_503"),
        (200, ""),
    ])
    monkeypatch.setattr("runner.inspection.time.sleep", lambda _seconds: None)
    completed = manager.store.update(
        batch_id,
        lambda value: value.update(status="SUCCEEDED", finished_at="2026-08-17T00:00:00Z"),
    )

    assert manager._callback(completed) is False
    failed = manager.store.load(batch_id)
    next_retry_at = failed["callback_delivery"]["next_retry_at"]

    assert manager.replay_due_callbacks(now=next_retry_at - 0.01) == 0
    assert manager.replay_due_callbacks(now=next_retry_at) == 1
    assert len(manager.sender.requests) == 4
    assert "callback_delivery" not in manager.store.load(batch_id)


def test_terminal_callback_does_not_retry_invalid_callback_credentials(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([(401, "http_401")])
    completed = manager.store.update(
        batch_id,
        lambda value: value.update(status="SUCCEEDED", finished_at="2026-08-17T00:00:00Z"),
    )

    assert manager._callback(completed) is False
    stored = manager.store.load(batch_id)
    assert stored["callback_delivery"]["status"] == "FAILED"
    assert stored["callback_delivery"]["retryable"] is False
    assert manager.replay_due_callbacks(now=float("inf")) == 0
    assert len(manager.sender.requests) == 1


def test_terminal_callback_backoff_increases_after_each_failed_replay(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([(503, "http_503")] * 6)
    monkeypatch.setattr("runner.inspection.time.sleep", lambda _seconds: None)
    clock = [100.0]
    monkeypatch.setattr("runner.inspection.time.time", lambda: clock[0])
    completed = manager.store.update(
        batch_id,
        lambda value: value.update(status="SUCCEEDED", finished_at="2026-08-17T00:00:00Z"),
    )

    assert manager._callback(completed) is False
    first = manager.store.load(batch_id)["callback_delivery"]
    assert first["retry_count"] == 1

    clock[0] = first["next_retry_at"]
    assert manager.replay_due_callbacks() == 0
    second = manager.store.load(batch_id)["callback_delivery"]
    assert second["retry_count"] == 2
    assert second["attempts"] == 6
    assert second["next_retry_at"] - first["next_retry_at"] == 10


def test_legacy_terminal_callback_failure_is_replayed_after_runner_upgrade(tmp_path, monkeypatch):
    manager, batch_id, _session_id, _journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )
    manager.sender = _Sender([(200, "")])
    manager.store.update(
        batch_id,
        lambda value: value.update(
            status="SUCCEEDED",
            finished_at="2026-08-17T00:00:00Z",
            callback_delivery={
                "status": "FAILED",
                "attempts": 3,
                "http_status": None,
                "error": "urlerror:[Errno 111] Connection refused",
            },
        ),
    )

    assert manager.replay_due_callbacks(now=0) == 1
    assert "callback_delivery" not in manager.store.load(batch_id)


def test_exactly_twenty_commands_with_report_does_not_resume(tmp_path, monkeypatch):
    manager, batch_id, session_id, journal, _sender = _manager_for_budget_test(
        tmp_path, monkeypatch, _BudgetAdapter()
    )

    manager._inspect_target(batch_id, session_id)

    target = manager.store.load(batch_id)["targets"][0]
    assert len(manager.orchestrator.adapter.calls) == 1
    assert target["status"] == "HEALTHY"
    assert not target["report"]["summary"].startswith(_COMMAND_BUDGET_SUMMARY_PREFIX)
    assert not any(
        event[1]["event_type"] == "inspection_command_budget_reached"
        for event in journal.events
    )


def test_non_budget_error_is_not_recovered(tmp_path, monkeypatch):
    adapter = _BudgetAdapter(
        initial_error=TrustedSessionError("TRUSTED_PROCESS_TIMEOUT", "inspection timeout")
    )
    manager, batch_id, session_id, _journal, sender = _manager_for_budget_test(
        tmp_path, monkeypatch, adapter
    )

    manager._inspect_target(batch_id, session_id)

    target = manager.store.load(batch_id)["targets"][0]
    assert len(adapter.calls) == 1
    assert target["status"] == "UNKNOWN"
    assert target["failure"] == {"code": "INSPECTION_TIMEOUT"}
    assert "report" not in target
    assert sender.requests[-1][1]["targets"][0]["failure"] == target["failure"]


def test_report_semantic_failure_has_safe_public_classification():
    error = TrustedSessionError(
        "TRUSTED_INSPECTION_STATUS_INCONSISTENT",
        "model report contains protected details",
    )

    assert _public_inspection_failure(error) == {
        "code": "INSPECTION_OUTPUT_INVALID",
    }


def test_batch_exposes_failure_only_when_every_target_matches():
    failure = {"code": "MODEL_AUTHENTICATION_FAILED", "http_status": 401}
    batch = {
        "status": "RUNNING",
        "targets": [
            {"status": "FAILED", "failure": failure},
            {"status": "FAILED", "failure": failure},
        ],
    }

    InspectionManager._finish_batch(None, batch)

    assert batch["status"] == "FAILED"
    assert batch["failure"] == failure
