from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

try:
    from aiops.api.ops_agent import trusted_repair_contract as contract
except (ImportError, ModuleNotFoundError):
    from runner import trusted_repair_contract as contract


HERE = Path(__file__).resolve()


def _find_file(*relative_candidates: str) -> Path:
    for parent in HERE.parents:
        for relative in relative_candidates:
            candidate = parent / relative
            if candidate.is_file():
                return candidate
    raise AssertionError(f"contract fixture not found: {relative_candidates!r}")


SCHEMA_PATH = _find_file(
    "docs/architecture/specs/trusted-repair-contract-v1.schema.json",
    "agent-project-trusted/references/trusted-repair-contract-v1.schema.json",
)
VECTORS_PATH = _find_file(
    "aiops/tests/ops_agent/fixtures/trusted-repair-vectors.json",
    "runner/tests/fixtures/trusted-repair-vectors.json",
)
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
WIRE = VECTORS["valid_wire_objects"]


def _set_path(value: dict, path: list, replacement: object) -> None:
    target = value
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = replacement


def _assert_error(expected: str, callback) -> None:
    with pytest.raises(contract.TrustedRepairContractError) as captured:
        callback()
    assert captured.value.error_code.value == expected


def _event_indexes(count: int) -> tuple[dict, dict]:
    events = WIRE["execution_event_batch"]["events"][:count]
    by_id = {
        event["event_id"]: (event["event_sequence"], event["event_fingerprint"])
        for event in events
    }
    by_sequence = {
        event["event_sequence"]: (event["event_id"], event["event_fingerprint"])
        for event in events
    }
    return by_id, by_sequence


def _batch_with_events(*indexes: int) -> dict:
    batch = copy.deepcopy(WIRE["execution_event_batch"])
    batch["events"] = [batch["events"][index] for index in indexes]
    batch["first_sequence"] = batch["events"][0]["event_sequence"]
    batch["last_sequence"] = batch["events"][-1]["event_sequence"]
    return batch


def _changed_session(changes: dict) -> dict:
    session = copy.deepcopy(WIRE["repair_session"])
    session.update(changes)
    return session


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(SCHEMA)


def test_all_nine_wire_kinds_share_the_closed_v1_schema() -> None:
    assert set(WIRE) == {
        "repair_proposal",
        "repair_session",
        "execution_event_batch",
        "approval_request",
        "risk_decision_request",
        "control_intent",
        "control_receipt",
        "trusted_repair_proposal_callback",
        "terminal_callback",
    }
    for payload in WIRE.values():
        contract.validate_wire_object(payload, SCHEMA)


def test_proposal_schema_semantics_and_hash_use_one_entry_point() -> None:
    assert contract.PROPOSAL_HASH_ALGORITHM_ID == VECTORS["proposal_hash_algorithm_id"]
    assert (
        contract.validate_and_hash_proposal(WIRE["repair_proposal"], SCHEMA)
        == VECTORS["expected_proposal_hash"]
    )


def test_control_intent_hash_and_receipt_fingerprint_are_frozen() -> None:
    assert (
        contract.CONTROL_INTENT_HASH_ALGORITHM_ID
        == VECTORS["control_intent_hash_algorithm_id"]
    )
    assert (
        contract.validate_and_hash_control_intent(WIRE["control_intent"], SCHEMA)
        == VECTORS["expected_control_intent_hash"]
    )
    assert (
        contract.validate_control_receipt(WIRE["control_receipt"], SCHEMA)
        == WIRE["control_receipt"]["receipt_fingerprint"]
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"kind":"control_intent","kind":"alias"}',
        '{"\u00e9":1,"e\u0301":2}',
        '{"kind":"control_intent","ttl":1.5}',
    ],
)
def test_strict_wire_decoder_rejects_duplicate_alias_and_float(raw: str) -> None:
    _assert_error(
        "TRUSTED_REPAIR_VALIDATION_FAILED",
        lambda: contract.parse_wire_json(raw),
    )


@pytest.mark.parametrize(
    "vector", VECTORS["valid_repair_session_semantics"], ids=lambda item: item["id"]
)
def test_valid_repair_session_semantics(vector: dict) -> None:
    previous = None
    if "previous_changes" in vector:
        previous = _changed_session(vector["previous_changes"])
    contract.validate_repair_session_semantics(
        _changed_session(vector["changes"]),
        SCHEMA,
        previous=previous,
        runner_event_received=vector["runner_event_received"],
    )


@pytest.mark.parametrize(
    "vector", VECTORS["invalid_repair_session_semantics"], ids=lambda item: item["id"]
)
def test_invalid_repair_session_semantics(vector: dict) -> None:
    previous = None
    if "previous_changes" in vector:
        previous = _changed_session(vector["previous_changes"])
    _assert_error(
        vector["error_code"],
        lambda: contract.validate_repair_session_semantics(
            _changed_session(vector["changes"]),
            SCHEMA,
            previous=previous,
            runner_event_received=vector["runner_event_received"],
        ),
    )


@pytest.mark.parametrize(
    "vector", VECTORS["invalid_wire_mutations"], ids=lambda item: item["id"]
)
def test_invalid_wire_vectors_fail_with_exact_category(vector: dict) -> None:
    payload = copy.deepcopy(WIRE[vector["object"]])
    _set_path(payload, vector["path"], vector["value"])
    if vector["object"] == "repair_proposal":
        callback = lambda: contract.validate_and_hash_proposal(payload, SCHEMA)
    elif vector["object"] == "control_intent":
        callback = lambda: contract.validate_and_hash_control_intent(payload, SCHEMA)
    elif vector["object"] == "control_receipt":
        callback = lambda: contract.validate_control_receipt(payload, SCHEMA)
    else:
        callback = lambda: contract.validate_wire_object(payload, SCHEMA)
    _assert_error(vector["error_code"], callback)


def test_every_wire_kind_rejects_unknown_version_as_unsupported() -> None:
    for payload in WIRE.values():
        changed = copy.deepcopy(payload)
        changed["schema_version"] = "99.0"
        _assert_error(
            "TRUSTED_REPAIR_UNSUPPORTED_SCHEMA_VERSION",
            lambda changed=changed: contract.validate_wire_object(changed, SCHEMA),
        )


def test_risk_route_body_cannot_smuggle_a_decision() -> None:
    changed = copy.deepcopy(WIRE["risk_decision_request"])
    changed["decision"] = "grant"
    _assert_error(
        "TRUSTED_REPAIR_VALIDATION_FAILED",
        lambda: contract.validate_wire_object(changed, SCHEMA),
    )


def test_golden_state_matrix_is_complete_and_exact() -> None:
    expected = {
        (contract.RepairSessionStatus(current), contract.RepairSessionEvent(event)): contract.RepairSessionStatus(result)
        for current, event, result in VECTORS["state_transitions"]
    }
    assert contract.TRANSITIONS == expected
    for (current, event), result in expected.items():
        assert contract.next_status(current, event) is result
    invalid = VECTORS["invalid_transition"]
    _assert_error(
        invalid["error_code"],
        lambda: contract.next_status(invalid["from"], invalid["event"]),
    )
    for terminal in contract.TERMINAL_STATUSES:
        for event in contract.RepairSessionEvent:
            _assert_error(
                "TRUSTED_REPAIR_STATE_TRANSITION_INVALID",
                lambda terminal=terminal, event=event: contract.next_status(terminal, event),
            )


def test_all_statuses_have_frozen_chinese_display_labels() -> None:
    expected = {
        contract.RepairSessionStatus(status): label
        for status, label in VECTORS["status_display_zh_cn"].items()
    }
    assert contract.STATUS_DISPLAY_ZH_CN == expected
    assert set(expected) == set(contract.RepairSessionStatus)


def test_runner_acceptance_and_audit_event_names_are_unambiguous() -> None:
    semantics = VECTORS["event_type_semantics"]
    assert contract.RepairSessionEvent.RUNNER_ACCEPTED.value == semantics["state_transition"]
    assert semantics == {
        "state_transition": "runner_accepted",
        "runner_acceptance_audit_event": "session_created",
        "diagnosis_process_audit_event": "diagnosis_started",
    }
    assert "diagnosis_started" not in {event.value for event in contract.RepairSessionEvent}


@pytest.mark.parametrize(
    "vector", VECTORS["event_ingest_cases"], ids=lambda item: item["id"]
)
def test_event_ingest_golden_decisions(vector: dict) -> None:
    batch = copy.deepcopy(WIRE["execution_event_batch"])
    by_id, by_sequence = _event_indexes(vector["existing_count"])
    result = contract.decide_event_ingest(
        batch,
        last_accepted_sequence=vector["last_accepted_sequence"],
        existing_by_id=by_id,
        existing_by_sequence=by_sequence,
    )
    assert result.decision.value == vector["expected_decision"]
    new_sequences = [
        event["event_sequence"]
        for event in batch["events"]
        if event["event_id"] in result.new_event_ids
    ]
    assert new_sequences == vector["expected_new_sequences"]


@pytest.mark.parametrize(
    "vector", VECTORS["event_ingest_conflicts"], ids=lambda item: item["id"]
)
def test_event_ingest_conflicts_have_exact_category(vector: dict) -> None:
    if vector["mode"] == "id_fingerprint":
        batch = _batch_with_events(0)
        event = batch["events"][0]
        by_id, by_sequence = _event_indexes(1)
        event["occurred_at"] = "2026-07-22T09:01:00Z"
        event["event_fingerprint"] = contract.compute_event_fingerprint(event)
        last = 1
    elif vector["mode"] == "sequence_occupied":
        batch = _batch_with_events(0)
        by_id = {}
        by_sequence = {1: ("99999999-9999-4999-8999-999999999999", "sha256:" + "9" * 64)}
        last = 1
    elif vector["mode"] == "gap":
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(1)
        last = 1
    elif vector["mode"] == "history_missing_reverse_id":
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(3)
        del by_id[WIRE["execution_event_batch"]["events"][0]["event_id"]]
        last = 3
    elif vector["mode"] == "history_missing_reverse_sequence":
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(3)
        del by_sequence[1]
        last = 3
    elif vector["mode"] == "history_last_mismatch":
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(2)
        last = 3
    elif vector["mode"] == "history_boolean_sequence_key":
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(1)
        event_id, fingerprint = by_sequence.pop(1)
        by_sequence[True] = (event_id, fingerprint)
        last = 1
    else:
        batch = _batch_with_events(2)
        by_id, by_sequence = _event_indexes(1)
        event_id, fingerprint = by_sequence.pop(1)
        by_sequence[2] = (event_id, fingerprint)
        by_id[event_id] = (2, fingerprint)
        last = 1
    _assert_error(
        vector["error_code"],
        lambda: contract.decide_event_ingest(
            batch,
            last_accepted_sequence=last,
            existing_by_id=by_id,
            existing_by_sequence=by_sequence,
        ),
    )
