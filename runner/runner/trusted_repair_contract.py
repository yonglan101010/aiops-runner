"""Pure v1 contract primitives for ``trusted_claude_session``.

No database, HTTP, Claude, or runner behavior belongs here. Both repositories share
this contract and exercise it with the same golden vectors.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_VERSION = "1.0"
PROPOSAL_HASH_ALGORITHM_ID = "aiops-trusted-repair-proposalhash-v1"
CONTROL_INTENT_HASH_ALGORITHM_ID = "aiops-trusted-repair-control-intent-hash-v1"
CONTROL_INTENT_MAX_TTL_SECONDS = 600
CONTROL_INTENT_CLOCK_SKEW_SECONDS = 60

PROPOSAL_HASH_FIELDS = (
    "schema_version",
    "proposal_revision",
    "diagnosis_summary",
    "root_cause",
    "evidence",
    "confidence",
    "target",
    "initial_commands",
    "expected_impact",
    "affected_scope",
    "rollback_instructions",
    "verification_steps",
    "risk_summary",
)

CONTROL_INTENT_HASH_FIELDS = (
    "schema_version",
    "kind",
    "command_id",
    "tenant_id",
    "run_id",
    "repair_id",
    "session_id",
    "runner_provider_id",
    "runner_instance_id",
    "logical_target_id",
    "platform",
    "action",
    "desired_terminal",
    "reason_code",
    "requested_at",
    "expires_at",
)



class RepairSessionStatus(str, Enum):
    PREPARING = "PREPARING"
    DIAGNOSING = "DIAGNOSING"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    DIAGNOSIS_ONLY = "DIAGNOSIS_ONLY"
    DIAGNOSIS_FAILED = "DIAGNOSIS_FAILED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTING = "EXECUTING"
    AWAITING_RISK_CONFIRMATION = "AWAITING_RISK_CONFIRMATION"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    MANUAL_INTERVENTION = "MANUAL_INTERVENTION"


class RepairSessionEvent(str, Enum):
    RUNNER_ACCEPTED = "runner_accepted"
    DISPATCH_FAILED_DEFINITIVE = "dispatch_failed_definitive"
    DISPATCH_UNCERTAIN = "dispatch_uncertain"
    DIAGNOSIS_COMPLETED_NO_REPAIR = "diagnosis_completed_no_repair"
    DIAGNOSIS_FAILED = "diagnosis_failed"
    DIAGNOSIS_UNCERTAIN = "diagnosis_uncertain"
    PROPOSAL_CREATED = "proposal_created"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    CANCEL_CONFIRMED = "cancel_confirmed"
    CANCEL_UNCERTAIN = "cancel_uncertain"
    EXECUTION_SUCCEEDED = "execution_succeeded"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_UNCERTAIN = "execution_uncertain"
    RISK_CONFIRMATION_REQUESTED = "risk_confirmation_requested"
    RISK_CONFIRMATION_GRANTED = "risk_confirmation_granted"
    RISK_CONFIRMATION_REJECTED = "risk_confirmation_rejected"
    RISK_CONFIRMATION_EXPIRED = "risk_confirmation_expired"


class TrustedRepairErrorCode(str, Enum):
    VALIDATION_FAILED = "TRUSTED_REPAIR_VALIDATION_FAILED"
    UNSUPPORTED_SCHEMA_VERSION = "TRUSTED_REPAIR_UNSUPPORTED_SCHEMA_VERSION"
    PROPOSAL_HASH_MISMATCH = "TRUSTED_REPAIR_PROPOSAL_HASH_MISMATCH"
    IDEMPOTENCY_CONFLICT = "TRUSTED_REPAIR_IDEMPOTENCY_CONFLICT"
    EVENT_SEQUENCE_CONFLICT = "TRUSTED_REPAIR_EVENT_SEQUENCE_CONFLICT"
    EVENT_CONTENT_CONFLICT = "TRUSTED_REPAIR_EVENT_CONTENT_CONFLICT"
    BINDING_MISMATCH = "TRUSTED_REPAIR_BINDING_MISMATCH"
    STATE_TRANSITION_INVALID = "TRUSTED_REPAIR_STATE_TRANSITION_INVALID"
    APPROVAL_EXPIRED = "TRUSTED_REPAIR_APPROVAL_EXPIRED"
    RISK_CONFIRMATION_EXPIRED = "TRUSTED_REPAIR_RISK_CONFIRMATION_EXPIRED"
    SESSION_NOT_FOUND = "TRUSTED_REPAIR_SESSION_NOT_FOUND"
    SESSION_BUSY = "TRUSTED_REPAIR_SESSION_BUSY"
    SESSION_RESUME_FAILED = "TRUSTED_REPAIR_SESSION_RESUME_FAILED"
    FEATURE_DISABLED = "TRUSTED_REPAIR_FEATURE_DISABLED"
    TARGET_NOT_ALLOWED = "TRUSTED_REPAIR_TARGET_NOT_ALLOWED"
    AUTHENTICATION_REQUIRED = "TRUSTED_REPAIR_AUTHENTICATION_REQUIRED"
    AUTHORIZATION_DENIED = "TRUSTED_REPAIR_AUTHORIZATION_DENIED"


class EventIngestDecision(str, Enum):
    NEW = "new"
    IDEMPOTENT = "idempotent"


TERMINAL_STATUSES = frozenset(
    {
        RepairSessionStatus.DISPATCH_FAILED,
        RepairSessionStatus.DIAGNOSIS_ONLY,
        RepairSessionStatus.DIAGNOSIS_FAILED,
        RepairSessionStatus.SUCCEEDED,
        RepairSessionStatus.FAILED,
        RepairSessionStatus.REJECTED,
        RepairSessionStatus.EXPIRED,
        RepairSessionStatus.CANCELLED,
        RepairSessionStatus.MANUAL_INTERVENTION,
    }
)

STATUS_DISPLAY_ZH_CN = {
    RepairSessionStatus.PREPARING: "准备中",
    RepairSessionStatus.DIAGNOSING: "诊断中",
    RepairSessionStatus.DISPATCH_FAILED: "派发失败",
    RepairSessionStatus.DIAGNOSIS_ONLY: "诊断完成（无需修复）",
    RepairSessionStatus.DIAGNOSIS_FAILED: "诊断失败",
    RepairSessionStatus.PENDING_APPROVAL: "待审批",
    RepairSessionStatus.EXECUTING: "修复执行中",
    RepairSessionStatus.AWAITING_RISK_CONFIRMATION: "待高风险确认",
    RepairSessionStatus.SUCCEEDED: "修复成功",
    RepairSessionStatus.FAILED: "修复失败",
    RepairSessionStatus.REJECTED: "已驳回",
    RepairSessionStatus.EXPIRED: "已过期",
    RepairSessionStatus.CANCELLED: "已取消",
    RepairSessionStatus.MANUAL_INTERVENTION: "需人工介入",
}

TRANSITIONS = {
    (RepairSessionStatus.PREPARING, RepairSessionEvent.RUNNER_ACCEPTED): RepairSessionStatus.DIAGNOSING,
    (RepairSessionStatus.PREPARING, RepairSessionEvent.DISPATCH_FAILED_DEFINITIVE): RepairSessionStatus.DISPATCH_FAILED,
    (RepairSessionStatus.PREPARING, RepairSessionEvent.DISPATCH_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
    (RepairSessionStatus.PREPARING, RepairSessionEvent.CANCEL_CONFIRMED): RepairSessionStatus.CANCELLED,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.DIAGNOSIS_COMPLETED_NO_REPAIR): RepairSessionStatus.DIAGNOSIS_ONLY,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.DIAGNOSIS_FAILED): RepairSessionStatus.DIAGNOSIS_FAILED,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.DIAGNOSIS_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.PROPOSAL_CREATED): RepairSessionStatus.PENDING_APPROVAL,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.CANCEL_CONFIRMED): RepairSessionStatus.CANCELLED,
    (RepairSessionStatus.DIAGNOSING, RepairSessionEvent.CANCEL_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
    (RepairSessionStatus.PENDING_APPROVAL, RepairSessionEvent.APPROVAL_GRANTED): RepairSessionStatus.EXECUTING,
    (RepairSessionStatus.PENDING_APPROVAL, RepairSessionEvent.APPROVAL_REJECTED): RepairSessionStatus.REJECTED,
    (RepairSessionStatus.PENDING_APPROVAL, RepairSessionEvent.APPROVAL_EXPIRED): RepairSessionStatus.EXPIRED,
    (RepairSessionStatus.PENDING_APPROVAL, RepairSessionEvent.CANCEL_CONFIRMED): RepairSessionStatus.CANCELLED,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.EXECUTION_SUCCEEDED): RepairSessionStatus.SUCCEEDED,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.EXECUTION_FAILED): RepairSessionStatus.FAILED,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.EXECUTION_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.CANCEL_CONFIRMED): RepairSessionStatus.CANCELLED,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.CANCEL_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
    (RepairSessionStatus.EXECUTING, RepairSessionEvent.RISK_CONFIRMATION_REQUESTED): RepairSessionStatus.AWAITING_RISK_CONFIRMATION,
    (RepairSessionStatus.AWAITING_RISK_CONFIRMATION, RepairSessionEvent.RISK_CONFIRMATION_GRANTED): RepairSessionStatus.EXECUTING,
    (RepairSessionStatus.AWAITING_RISK_CONFIRMATION, RepairSessionEvent.RISK_CONFIRMATION_REJECTED): RepairSessionStatus.REJECTED,
    (RepairSessionStatus.AWAITING_RISK_CONFIRMATION, RepairSessionEvent.RISK_CONFIRMATION_EXPIRED): RepairSessionStatus.EXPIRED,
    (RepairSessionStatus.AWAITING_RISK_CONFIRMATION, RepairSessionEvent.CANCEL_CONFIRMED): RepairSessionStatus.CANCELLED,
    (RepairSessionStatus.AWAITING_RISK_CONFIRMATION, RepairSessionEvent.EXECUTION_UNCERTAIN): RepairSessionStatus.MANUAL_INTERVENTION,
}


class TrustedRepairContractError(ValueError):
    def __init__(self, error_code: TrustedRepairErrorCode, message: str):
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class EventIngestResult:
    decision: EventIngestDecision
    new_event_ids: tuple[str, ...]


def _fail(error_code: TrustedRepairErrorCode, message: str) -> None:
    raise TrustedRepairContractError(error_code, message)


def next_status(
    status: RepairSessionStatus | str, event: RepairSessionEvent | str
) -> RepairSessionStatus:
    """Return the only legal next status; terminal and unlisted transitions fail closed."""
    try:
        current = RepairSessionStatus(status)
        trigger = RepairSessionEvent(event)
        return TRANSITIONS[(current, trigger)]
    except (ValueError, KeyError) as exc:
        raise TrustedRepairContractError(
            TrustedRepairErrorCode.STATE_TRANSITION_INVALID,
            f"invalid transition: {status!s} + {event!s}",
        ) from exc


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "floating-point values are forbidden")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "object keys must be strings")
        return {key: _normalize(value[key]) for key in sorted(value)}
    _fail(
        TrustedRepairErrorCode.VALIDATION_FAILED,
        f"unsupported contract value: {type(value).__name__}",
    )


def parse_wire_json(raw: str | bytes | bytearray) -> Mapping[str, Any]:
    """Decode one wire object while rejecting duplicate/NFC-alias keys and floats."""
    def reject_float(value: str) -> Any:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"floating-point value is forbidden: {value}")

    def reject_constant(value: str) -> Any:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"non-finite value is forbidden: {value}")

    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            normalized = unicodedata.normalize("NFC", key)
            if normalized in result:
                _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "duplicate object key is forbidden")
            result[normalized] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=closed_object,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TrustedRepairContractError(
            TrustedRepairErrorCode.VALIDATION_FAILED, "wire body is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, Mapping):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "wire body must be an object")
    return _normalize(value)


def validate_wire_object(payload: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate a v1 wire object and classify unknown versions before schema errors."""
    if not isinstance(payload, Mapping):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "wire payload must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        _fail(
            TrustedRepairErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            f"unsupported schema_version: {payload.get('schema_version')!r}",
        )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            f"schema validation failed at {path}: {errors[0].message}",
        )


def validate_repair_session_semantics(
    session: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    previous: Mapping[str, Any] | None = None,
    runner_event_received: bool = False,
) -> None:
    """Validate the lifecycle invariants of a ``repair_session`` snapshot.

    AIOps creates a ``PREPARING`` snapshot before dispatch.  ``runner_accepted``
    atomically binds the Claude session and enters ``DIAGNOSING``.  A null Claude
    binding is otherwise legal only for a terminal reached directly from
    ``PREPARING`` before delivery was confirmed.  Once established, the binding
    is immutable; a late callback may only fill the previously unknown binding on
    such a ``MANUAL_INTERVENTION`` snapshot and never resumes the session.
    """
    validate_wire_object(session, schema)
    if session.get("kind") != "repair_session":
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "kind must be repair_session")
    status = RepairSessionStatus(session["status"])
    claude_session_id = session["claude_session_id"]

    previous_status: RepairSessionStatus | None = None
    previous_claude_session_id: str | None = None
    if previous is not None:
        validate_wire_object(previous, schema)
        if previous.get("kind") != "repair_session":
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "previous kind must be repair_session")
        if previous.get("session_id") != session.get("session_id"):
            _fail(TrustedRepairErrorCode.BINDING_MISMATCH, "session_id cannot change")
        previous_status = RepairSessionStatus(previous["status"])
        previous_claude_session_id = previous.get("claude_session_id")
        if (
            previous_claude_session_id is not None
            and claude_session_id != previous_claude_session_id
        ):
            _fail(
                TrustedRepairErrorCode.BINDING_MISMATCH,
                "claude_session_id is immutable once bound",
            )
        if previous_claude_session_id is None and claude_session_id is not None:
            runner_acceptance = (
                previous_status is RepairSessionStatus.PREPARING
                and status is RepairSessionStatus.DIAGNOSING
            )
            late_uncertain_dispatch_binding = (
                previous_status is RepairSessionStatus.MANUAL_INTERVENTION
                and status is RepairSessionStatus.MANUAL_INTERVENTION
                and runner_event_received
            )
            if not (runner_acceptance or late_uncertain_dispatch_binding):
                _fail(
                    TrustedRepairErrorCode.BINDING_MISMATCH,
                    "Claude binding may only be established by runner acceptance "
                    "or a late callback that preserves MANUAL_INTERVENTION",
                )

    if status is RepairSessionStatus.PREPARING and claude_session_id is not None:
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "PREPARING cannot bind claude_session_id before runner acceptance",
        )
    if status is RepairSessionStatus.DISPATCH_FAILED and (
        claude_session_id is not None or previous_status is not RepairSessionStatus.PREPARING
    ):
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "DISPATCH_FAILED must be unbound and reached directly from PREPARING",
        )

    if (
        previous_status is RepairSessionStatus.PREPARING
        and status is RepairSessionStatus.DIAGNOSING
        and claude_session_id is None
    ):
        _fail(
            TrustedRepairErrorCode.BINDING_MISMATCH,
            "runner_accepted must atomically bind claude_session_id",
        )

    predispatch_null_terminals = {
        RepairSessionStatus.DISPATCH_FAILED,
        RepairSessionStatus.CANCELLED,
        RepairSessionStatus.MANUAL_INTERVENTION,
    }
    if claude_session_id is None and status is not RepairSessionStatus.PREPARING:
        if status not in predispatch_null_terminals or previous_status is not RepairSessionStatus.PREPARING:
            _fail(
                TrustedRepairErrorCode.VALIDATION_FAILED,
                "an unbound terminal must be reached directly from PREPARING",
            )
    if runner_event_received and claude_session_id is None:
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "runner events require a bound claude_session_id",
        )
    proposal_fields = (
        session["proposal_revision"],
        session["proposal_hash_algorithm_id"],
        session["proposal_hash"],
    )
    if any(value is None for value in proposal_fields) and not all(
        value is None for value in proposal_fields
    ):
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "proposal revision, algorithm, and hash must be all null or all bound",
        )
    if status is RepairSessionStatus.PREPARING and not all(value is None for value in proposal_fields):
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "PREPARING cannot have a proposal binding",
        )
    if status in {
        RepairSessionStatus.PENDING_APPROVAL,
        RepairSessionStatus.EXECUTING,
        RepairSessionStatus.AWAITING_RISK_CONFIRMATION,
        RepairSessionStatus.SUCCEEDED,
        RepairSessionStatus.FAILED,
        RepairSessionStatus.REJECTED,
        RepairSessionStatus.EXPIRED,
    } and any(value is None for value in proposal_fields):
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "proposal binding is required after proposal creation",
        )

def _proposal_hash_payload(proposal: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize({key: proposal[key] for key in PROPOSAL_HASH_FIELDS})


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def validate_and_hash_proposal(
    proposal: Mapping[str, Any], schema: Mapping[str, Any]
) -> str:
    """The sole proposal entry point: schema, semantics, canonicalization, then hash."""
    validate_wire_object(proposal, schema)
    if proposal.get("kind") != "repair_proposal":
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "kind must be repair_proposal")
    if proposal.get("proposal_hash_algorithm_id") != PROPOSAL_HASH_ALGORITHM_ID:
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            "unsupported proposal_hash_algorithm_id",
        )
    for field in ("initial_commands", "verification_steps"):
        values = proposal[field]
        sequences = [item["sequence"] for item in values]
        if sequences != list(range(1, len(values) + 1)):
            _fail(
                TrustedRepairErrorCode.VALIDATION_FAILED,
                f"{field} sequence must start at 1 and be contiguous",
            )
    canonical = _canonical_json(_proposal_hash_payload(proposal)).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if proposal.get("proposal_hash") != expected:
        _fail(
            TrustedRepairErrorCode.PROPOSAL_HASH_MISMATCH,
            "proposal_hash does not match the validated proposal",
        )
    return expected


def compute_event_fingerprint(event: Mapping[str, Any]) -> str:
    """Fingerprint every event field except the fingerprint itself."""
    if "event_fingerprint" not in event:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "event_fingerprint is required")
    payload = {key: value for key, value in event.items() if key != "event_fingerprint"}
    canonical = _canonical_json(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _parse_wire_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustedRepairContractError(
            TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be an RFC3339 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_control_intent_semantics(
    intent: Mapping[str, Any], *, now: datetime | None = None
) -> None:
    for field in (
        "command_id", "run_id", "session_id", "runner_provider_id", "runner_instance_id"
    ):
        value = intent.get(field)
        try:
            canonical = str(UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise TrustedRepairContractError(
                TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be a UUID"
            ) from exc
        if value != canonical:
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be canonical UUID")
    repair_id = intent.get("repair_id")
    if repair_id is not None:
        try:
            canonical_repair = str(UUID(str(repair_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise TrustedRepairContractError(
                TrustedRepairErrorCode.VALIDATION_FAILED, "repair_id must be null or a UUID"
            ) from exc
        if repair_id != canonical_repair:
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "repair_id must be canonical UUID")
    requested_at = _parse_wire_timestamp(intent.get("requested_at"), "requested_at")
    expires_at = _parse_wire_timestamp(intent.get("expires_at"), "expires_at")
    ttl = (expires_at - requested_at).total_seconds()
    if ttl <= 0 or ttl > CONTROL_INTENT_MAX_TTL_SECONDS:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "control intent TTL must be in (0, 600] seconds")
    if now is not None:
        current = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        skew = timedelta(seconds=CONTROL_INTENT_CLOCK_SKEW_SECONDS)
        if requested_at > current + skew:
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "control intent is too far in the future")
        if expires_at < current - skew:
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "control intent has expired")


def compute_control_intent_hash(intent: Mapping[str, Any]) -> str:
    """Hash the frozen v1 field set and domain-separated canonical JSON."""
    missing = [field for field in CONTROL_INTENT_HASH_FIELDS if field not in intent]
    if missing:
        _fail(
            TrustedRepairErrorCode.VALIDATION_FAILED,
            f"control intent hash fields are missing: {', '.join(missing)}",
        )
    _validate_control_intent_semantics(intent)
    canonical = _canonical_json(
        {field: intent[field] for field in CONTROL_INTENT_HASH_FIELDS}
    )
    preimage = f"{CONTROL_INTENT_HASH_ALGORITHM_ID}\n{canonical}".encode("utf-8")
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def validate_and_hash_control_intent(
    intent: Mapping[str, Any],
    schema: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> str:
    validate_wire_object(intent, schema)
    if intent.get("kind") != "control_intent":
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "kind must be control_intent")
    if intent.get("intent_hash_algorithm_id") != CONTROL_INTENT_HASH_ALGORITHM_ID:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "unsupported control intent hash algorithm")
    _validate_control_intent_semantics(intent, now=now)
    expected = compute_control_intent_hash(intent)
    if intent.get("intent_hash") != expected:
        _fail(TrustedRepairErrorCode.IDEMPOTENCY_CONFLICT, "control intent hash mismatch")
    return expected


def compute_control_receipt_fingerprint(receipt: Mapping[str, Any]) -> str:
    if "receipt_fingerprint" not in receipt:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "receipt_fingerprint is required")
    payload = {key: value for key, value in receipt.items() if key != "receipt_fingerprint"}
    canonical = _canonical_json(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def validate_control_receipt(
    receipt: Mapping[str, Any], schema: Mapping[str, Any]
) -> str:
    validate_wire_object(receipt, schema)
    if receipt.get("kind") != "control_receipt":
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "kind must be control_receipt")
    if receipt.get("intent_hash_algorithm_id") != CONTROL_INTENT_HASH_ALGORITHM_ID:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "unsupported control intent hash algorithm")
    for field in (
        "receipt_id", "command_id", "run_id", "session_id", "runner_provider_id",
        "runner_instance_id",
    ):
        value = receipt.get(field)
        try:
            canonical = str(UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise TrustedRepairContractError(
                TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be a UUID"
            ) from exc
        if value != canonical:
            _fail(TrustedRepairErrorCode.VALIDATION_FAILED, f"{field} must be canonical UUID")
    prior = (receipt.get("prior_outcome"), receipt.get("prior_command_result_certain"))
    outcome = receipt.get("outcome")
    reason = receipt.get("reason_code")
    certain = receipt.get("command_result_certain")
    if outcome == "ALREADY_APPLIED":
        if prior[0] not in {"CLOSED", "STOPPED_CONFIRMED", "STOP_UNCERTAIN", "INVALID_INTENT"} \
                or not isinstance(prior[1], bool) or certain is not prior[1] \
                or reason != "ALREADY_APPLIED":
            _fail(
                TrustedRepairErrorCode.VALIDATION_FAILED,
                "ALREADY_APPLIED must carry its prior final outcome and certainty",
            )
    elif prior != (None, None):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "prior result is only valid for ALREADY_APPLIED")
    if outcome in {"CLOSED", "STOPPED_CONFIRMED"} and (
        certain is not True or reason != "CONTROL_APPLIED"
    ):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "confirmed control result must be certain")
    if outcome == "STOP_UNCERTAIN" and (certain is not False or reason != "STOP_UNCERTAIN"):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "uncertain stop must remain uncertain")
    if outcome == "INVALID_INTENT" and (
        certain is not False or reason not in {"INTENT_CONFLICT", "INTENT_EXPIRED", "INVALID_INTENT"}
    ):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "invalid intent reason is inconsistent")
    expected = compute_control_receipt_fingerprint(receipt)
    if receipt.get("receipt_fingerprint") != expected:
        _fail(TrustedRepairErrorCode.EVENT_CONTENT_CONFLICT, "control receipt fingerprint mismatch")
    return expected


def validate_event_batch_semantics(batch: Mapping[str, Any]) -> None:
    """Validate batch-local invariants which JSON Schema cannot express."""
    events = batch.get("events")
    if not isinstance(events, list) or not events:
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "event batch must contain events")
    first = batch.get("first_sequence")
    last = batch.get("last_sequence")
    sequences = [event.get("event_sequence") for event in events]
    if not isinstance(first, int) or not isinstance(last, int):
        _fail(TrustedRepairErrorCode.VALIDATION_FAILED, "batch sequence bounds must be integers")
    if sequences != list(range(first, last + 1)):
        _fail(
            TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
            "event batch sequences must be strictly contiguous",
        )
    if len({event.get("event_id") for event in events}) != len(events):
        _fail(
            TrustedRepairErrorCode.EVENT_CONTENT_CONFLICT,
            "event_id must be unique within a batch",
        )
    for event in events:
        if event.get("session_id") != batch.get("session_id"):
            _fail(TrustedRepairErrorCode.BINDING_MISMATCH, "event session_id does not match batch")
        if event.get("event_fingerprint") != compute_event_fingerprint(event):
            _fail(TrustedRepairErrorCode.EVENT_CONTENT_CONFLICT, "event_fingerprint mismatch")


def decide_event_ingest(
    batch: Mapping[str, Any],
    *,
    last_accepted_sequence: int,
    existing_by_id: Mapping[str, tuple[int, str]],
    existing_by_sequence: Mapping[int, tuple[str, str]],
) -> EventIngestResult:
    """Purely classify a validated batch against persisted event fingerprints.

    A replayed prefix followed by a contiguous new suffix is accepted as ``new``.
    Database locking and atomic insertion deliberately remain a later slice.
    """
    validate_event_batch_semantics(batch)
    if (
        isinstance(last_accepted_sequence, bool)
        or not isinstance(last_accepted_sequence, int)
        or last_accepted_sequence < 0
    ):
        _fail(
            TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
            "last accepted sequence must be a non-negative integer",
        )
    expected_sequences = set(range(1, last_accepted_sequence + 1))
    if any(
        type(sequence) is not int or sequence not in expected_sequences
        for sequence in existing_by_sequence
    ):
        _fail(
            TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
            "sequence index keys must be integers in the accepted history",
        )
    if set(existing_by_sequence) != expected_sequences:
        _fail(
            TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
            "sequence index must exactly cover the accepted history",
        )
    if len(existing_by_id) != last_accepted_sequence:
        _fail(
            TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
            "event id index must exactly cover the accepted history",
        )
    for event_id, indexed in existing_by_id.items():
        if not isinstance(indexed, tuple) or len(indexed) != 2:
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "event id index entry is malformed",
            )
        sequence, fingerprint = indexed
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence not in expected_sequences
            or existing_by_sequence.get(sequence) != (event_id, fingerprint)
        ):
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "existing event indexes disagree",
            )
    for sequence, indexed in existing_by_sequence.items():
        if not isinstance(indexed, tuple) or len(indexed) != 2:
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "sequence index entry is malformed",
            )
        event_id, fingerprint = indexed
        if existing_by_id.get(event_id) != (sequence, fingerprint):
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "existing event indexes disagree",
            )
    new_ids: list[str] = []
    expected_new_sequence = last_accepted_sequence + 1
    seen_new = False
    for event in batch["events"]:
        event_id = event["event_id"]
        sequence = event["event_sequence"]
        fingerprint = event["event_fingerprint"]
        by_id = existing_by_id.get(event_id)
        by_sequence = existing_by_sequence.get(sequence)
        if by_id is not None:
            if by_id != (sequence, fingerprint):
                _fail(
                    TrustedRepairErrorCode.EVENT_CONTENT_CONFLICT,
                    "existing event_id has different sequence or content",
                )
            if by_sequence != (event_id, fingerprint):
                _fail(
                    TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                    "existing event indexes disagree",
                )
            if seen_new:
                _fail(
                    TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                    "an idempotent replay cannot follow a new event",
                )
            continue
        if by_sequence is not None:
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "event sequence is already occupied",
            )
        if sequence != expected_new_sequence:
            _fail(
                TrustedRepairErrorCode.EVENT_SEQUENCE_CONFLICT,
                "new event does not extend the accepted sequence",
            )
        seen_new = True
        new_ids.append(event_id)
        expected_new_sequence += 1
    return EventIngestResult(
        EventIngestDecision.NEW if new_ids else EventIngestDecision.IDEMPOTENT,
        tuple(new_ids),
    )


__all__ = [
    "SCHEMA_VERSION",
    "PROPOSAL_HASH_ALGORITHM_ID",
    "PROPOSAL_HASH_FIELDS",
    "CONTROL_INTENT_HASH_ALGORITHM_ID",
    "CONTROL_INTENT_HASH_FIELDS",
    "CONTROL_INTENT_MAX_TTL_SECONDS",
    "CONTROL_INTENT_CLOCK_SKEW_SECONDS",
    "RepairSessionStatus",
    "RepairSessionEvent",
    "TrustedRepairErrorCode",
    "EventIngestDecision",
    "EventIngestResult",
    "TERMINAL_STATUSES",
    "STATUS_DISPLAY_ZH_CN",
    "TRANSITIONS",
    "TrustedRepairContractError",
    "next_status",
    "parse_wire_json",
    "validate_wire_object",
    "validate_repair_session_semantics",
    "validate_and_hash_proposal",
    "compute_event_fingerprint",
    "compute_control_intent_hash",
    "validate_and_hash_control_intent",
    "compute_control_receipt_fingerprint",
    "validate_control_receipt",
    "validate_event_batch_semantics",
    "decide_event_ingest",
]
