"""Fail-closed Linux core for one persistent Claude trusted repair session.

This module deliberately has no HTTP/server integration.  It owns only local
process, journal, transcript and same-session invariants so a later API slice can
compose it without weakening the same-session boundary.
"""

from __future__ import annotations

import base64
import contextlib
import getpass
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, ContextManager, Iterable, Mapping, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import TrustedSessionConfig
from .trusted_proposal_draft import (
    diagnosis_draft_schema_json,
    expand_diagnosis_draft_to_v1,
    validate_diagnosis_draft,
)


ACTIVE_STATUSES = {
    "DIAGNOSING",
    "PROPOSAL_GENERATING",
    "PENDING_APPROVAL",
    "EXECUTING",
    "AWAITING_RISK_CONFIRMATION",
}
LOCAL_TERMINAL_STATUSES = {
    "DIAGNOSIS_ONLY", "DIAGNOSIS_FAILED", "DISPATCH_FAILED", "SUCCEEDED", "FAILED",
    "REJECTED", "EXPIRED", "CANCELLED", "MANUAL_INTERVENTION",
}
SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)([^\s,;]+)"),
    re.compile(r"(?i)((?:token|password|passwd|secret|api[_-]?key)\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(https?://[^\s/:]+:)([^@\s]+)(@)"),
)


def _diagnosis_uncertain_reason(error_code: str) -> str:
    if error_code in {
        "TRUSTED_STREAM_INVALID_JSON", "TRUSTED_PROCESS_IO_UNAVAILABLE",
        "TRUSTED_PROCESS_EXIT_UNCERTAIN", "TRUSTED_PROCESS_TIMEOUT",
    }:
        return "TRUSTED_DIAGNOSIS_STREAM_INTERRUPTED"
    if error_code in {
        "TRUSTED_STREAM_UNCLOSED_TOOL", "TRUSTED_STREAM_NO_TERMINAL",
        "TRUSTED_CLAUDE_RESULT_ERROR", "TRUSTED_PROPOSAL_MISSING",
        "TRUSTED_PROPOSAL_DRAFT_INVALID",
    }:
        return "TRUSTED_DIAGNOSIS_OUTPUT_INCOMPLETE"
    if error_code.startswith("TRUSTED_TRANSCRIPT_"):
        return "TRUSTED_TRANSCRIPT_INCOMPLETE"
    if error_code in {"TRUSTED_SESSION_JOURNAL_MISSING", "TRUSTED_EVENT_JOURNAL_CORRUPT"}:
        return "TRUSTED_RUNNER_JOURNAL_CORRUPT"
    if error_code in {"TRUSTED_CLAUDE_SESSION_MISSING", "TRUSTED_SESSION_RESUME_FAILED"}:
        return "TRUSTED_CLAUDE_SESSION_MISSING"
    return "TRUSTED_DIAGNOSIS_RESULT_UNKNOWN"


@dataclass(frozen=True)
class InspectionFailure:
    """Public-safe inspection failure classification."""

    code: str
    http_status: int | None = None


_HTTP_STATUS_PATTERN = re.compile(
    r"(?i)\b(?:http(?:\s+status)?|status|api error)\s*[:=]?\s*([1-5]\d{2})\b"
)
_INSPECTION_PROVIDER_UNAVAILABLE_RETRY_LIMIT = 3


def _claude_result_failure(payload: Mapping[str, Any]) -> InspectionFailure:
    """Classify a Claude result without exposing its untrusted text."""

    fragments = [
        value
        for value in (payload.get("result"), payload.get("error"))
        if isinstance(value, str)
    ]
    text = " ".join(fragments)[:8192]
    match = _HTTP_STATUS_PATTERN.search(text)
    http_status = int(match.group(1)) if match else None

    if http_status in {401, 403} or re.search(
        r"(?i)\b(?:invalid api key|authentication failed|unauthorized|forbidden)\b",
        text,
    ):
        return InspectionFailure("MODEL_AUTHENTICATION_FAILED", http_status)
    if http_status == 402 or re.search(
        r"(?i)\b(?:quota exhausted|insufficient (?:credit|balance)|credit balance)\b",
        text,
    ):
        return InspectionFailure("MODEL_QUOTA_EXHAUSTED", http_status)
    if http_status == 429 or re.search(
        r"(?i)\b(?:rate limit(?:ed| exceeded)?|too many requests)\b", text
    ):
        return InspectionFailure("MODEL_RATE_LIMITED", http_status)
    if http_status is not None and 500 <= http_status <= 599:
        return InspectionFailure("MODEL_PROVIDER_UNAVAILABLE", http_status)
    if re.search(
        r"(?i)\b(?:connection (?:failed|refused|reset|timed out)|"
        r"dns|tls handshake|name or service not known|temporary failure in name resolution)\b",
        text,
    ):
        return InspectionFailure("MODEL_CONNECTION_FAILED", http_status)
    return InspectionFailure("INSPECTION_FAILED", http_status)


class TrustedSessionError(RuntimeError):
    """Stable local failure with a machine-oriented code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        failure_code: str | None = None,
        http_status: int | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.failure_code = failure_code
        self.http_status = http_status if http_status in range(100, 600) else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def redact_sensitive(value: str, *, limit: int = 4096) -> str:
    text = " ".join((value or "").split())
    for pattern in SECRET_PATTERNS:
        if pattern.groups == 3:
            text = pattern.sub(r"\1<redacted>\3", text)
        else:
            text = pattern.sub(r"\1<redacted>", text)
    return text[:limit]


def command_fingerprint(command: str) -> str:
    return "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()


def _strict_json_loads(value: str) -> Any:
    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=closed_object)


def _record_fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _may_start_remote_process(command: str) -> bool:
    # Deliberately conservative: false positives cause human intervention; false
    # negatives could incorrectly claim cancellation of a remote operation.
    return bool(
        re.search(
            r"(?<![\w-])(?:[\w./-]+/)?(?:ssh(?:\.exe)?|target-exec)(?=\s|$)",
            command,
            re.IGNORECASE,
        )
    )


def _validated_session_id(session_id: str) -> str:
    try:
        parsed = uuid.UUID(str(session_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TrustedSessionError("TRUSTED_SESSION_ID_INVALID", "session_id must be a canonical UUID") from exc
    canonical = str(parsed)
    if str(session_id) != canonical:
        raise TrustedSessionError("TRUSTED_SESSION_ID_INVALID", "session_id must be a canonical UUID")
    return canonical


class LockBackend(Protocol):
    def acquire(self, session_id: str) -> ContextManager[None]: ...


class FcntlLockBackend:
    """Production lock backend.  Construction itself fails closed off Linux."""

    def __init__(self, directory: str):
        if sys.platform != "linux":
            raise TrustedSessionError("TRUSTED_SESSION_LINUX_REQUIRED", "fcntl locks require Linux")
        self.directory = Path(directory)

    @contextlib.contextmanager
    def acquire(self, session_id: str):
        session_id = _validated_session_id(session_id)
        import fcntl

        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{session_id}.lock"
        with path.open("a+b") as stream:
            os.chmod(path, 0o600)
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise TrustedSessionError("TRUSTED_SESSION_BUSY", "session is already active") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class SessionJournal:
    """Atomic metadata and append-only redacted event journal."""

    def __init__(self, directory: str):
        self.directory = Path(directory)
        self._mutex_guard = threading.Lock()
        self._mutexes: dict[str, threading.RLock] = {}

    def _mutex(self, session_id: str) -> threading.RLock:
        session_id = _validated_session_id(session_id)
        with self._mutex_guard:
            return self._mutexes.setdefault(session_id, threading.RLock())

    def metadata_path(self, session_id: str) -> Path:
        return self.directory / _validated_session_id(session_id) / "metadata.json"

    def events_path(self, session_id: str) -> Path:
        return self.directory / _validated_session_id(session_id) / "events.jsonl"

    def proposal_path(self, session_id: str) -> Path:
        return self.directory / _validated_session_id(session_id) / "proposal.json"

    def proposal_outbox_path(self, session_id: str) -> Path:
        return self.directory / _validated_session_id(session_id) / "outbox" / "proposal.json"

    def proposal_fingerprint_path(self, session_id: str) -> Path:
        return self.directory / _validated_session_id(session_id) / "proposal.fingerprint"

    def risk_path(self, session_id: str, risk_confirmation_id: str) -> Path:
        return (
            self.directory
            / _validated_session_id(session_id)
            / "risk-confirmations"
            / f"{_validated_session_id(risk_confirmation_id)}.json"
        )

    def control_result_path(self, session_id: str, command_id: str) -> Path:
        return (
            self.directory
            / _validated_session_id(session_id)
            / "control-intents"
            / f"{_validated_session_id(command_id)}.json"
        )

    def create(self, metadata: Mapping[str, Any]) -> dict[str, Any]:
        session_id = str(metadata["session_id"])
        with self._mutex(session_id):
            path = self.metadata_path(session_id)
            if path.exists():
                raise TrustedSessionError("TRUSTED_SESSION_EXISTS", "session journal already exists")
            value = dict(metadata)
            value.setdefault("next_event_sequence", 1)
            value.setdefault("created_at", _utc_now())
            _atomic_json(path, value)
            return value

    def load(self, session_id: str) -> dict[str, Any]:
        with self._mutex(session_id):
            try:
                with self.metadata_path(session_id).open("r", encoding="utf-8") as stream:
                    value = json.load(stream)
            except (OSError, ValueError) as exc:
                raise TrustedSessionError("TRUSTED_SESSION_JOURNAL_MISSING", "session journal unavailable") from exc
            if value.get("session_id") != session_id:
                raise TrustedSessionError("TRUSTED_SESSION_BINDING_MISMATCH", "journal session binding mismatch")
            return value

    def update(self, session_id: str, **changes: Any) -> dict[str, Any]:
        with self._mutex(session_id):
            value = self.load(session_id)
            value.update(changes)
            value["updated_at"] = _utc_now()
            _atomic_json(self.metadata_path(session_id), value)
            return value

    def update_if(
        self,
        session_id: str,
        predicate: Callable[[Mapping[str, Any]], bool],
        **changes: Any,
    ) -> dict[str, Any]:
        with self._mutex(session_id):
            value = self.load(session_id)
            if not predicate(value):
                return value
            value.update(changes)
            value["updated_at"] = _utc_now()
            _atomic_json(self.metadata_path(session_id), value)
            return value

    def compare_and_update(
        self,
        session_id: str,
        predicate: Callable[[Mapping[str, Any]], bool],
        **changes: Any,
    ) -> tuple[bool, dict[str, Any]]:
        with self._mutex(session_id):
            value = self.load(session_id)
            if not predicate(value):
                return False, value
            value.update(changes)
            value["updated_at"] = _utc_now()
            _atomic_json(self.metadata_path(session_id), value)
            return True, value

    def save_proposal(self, session_id: str, proposal: Mapping[str, Any]) -> str:
        with self._mutex(session_id):
            self.load(session_id)
            path = self.proposal_path(session_id)
            if path.exists():
                raise TrustedSessionError("TRUSTED_PROPOSAL_ALREADY_BOUND", "proposal is immutable once saved")
            if _contains_detectable_secret(proposal):
                raise TrustedSessionError(
                    "TRUSTED_PROPOSAL_CONTAINS_SECRET", "proposal contains a credential-like value"
                )
            _atomic_json(path, proposal)
            _atomic_json(self.proposal_outbox_path(session_id), proposal)
            fingerprint = _record_fingerprint(proposal)
            self.proposal_fingerprint_path(session_id).write_text(fingerprint + "\n", encoding="ascii")
            os.chmod(self.proposal_fingerprint_path(session_id), 0o600)
            return fingerprint

    def load_proposal(self, session_id: str) -> dict[str, Any]:
        with self._mutex(session_id):
            try:
                value = json.loads(self.proposal_path(session_id).read_text(encoding="utf-8"))
                expected = self.proposal_fingerprint_path(session_id).read_text(encoding="ascii").strip()
            except (OSError, ValueError) as exc:
                raise TrustedSessionError("TRUSTED_PROPOSAL_MISSING", "immutable proposal is unavailable") from exc
            if not isinstance(value, dict) or _record_fingerprint(value) != expected:
                raise TrustedSessionError("TRUSTED_PROPOSAL_CORRUPT", "proposal record fingerprint mismatch")
            return value

    def save_risk(
        self, session_id: str, risk_confirmation_id: str, risk: Mapping[str, Any]
    ) -> str:
        with self._mutex(session_id):
            path = self.risk_path(session_id, risk_confirmation_id)
            if path.exists():
                raise TrustedSessionError("TRUSTED_RISK_ALREADY_BOUND", "risk record already exists")
            if _contains_detectable_secret(risk):
                raise TrustedSessionError(
                    "TRUSTED_RISK_CONTAINS_SECRET", "risk record contains a credential-like value"
                )
            fingerprint = _record_fingerprint(risk)
            envelope = {"record": dict(risk), "record_fingerprint": fingerprint}
            _atomic_json(path, envelope)
            return fingerprint

    def load_risk(self, session_id: str, risk_confirmation_id: str) -> dict[str, Any]:
        with self._mutex(session_id):
            try:
                envelope = json.loads(
                    self.risk_path(session_id, risk_confirmation_id).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise TrustedSessionError("TRUSTED_RISK_RECORD_MISSING", "immutable risk record is unavailable") from exc
            if not isinstance(envelope, dict) or not isinstance(envelope.get("record"), dict):
                raise TrustedSessionError("TRUSTED_RISK_RECORD_CORRUPT", "risk record is malformed")
            record = envelope["record"]
            if envelope.get("record_fingerprint") != _record_fingerprint(record):
                raise TrustedSessionError("TRUSTED_RISK_RECORD_CORRUPT", "risk record fingerprint mismatch")
            return record

    def save_control_result(
        self,
        session_id: str,
        command_id: str,
        intent: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Persist one immutable control result before any receipt callback.

        Returns ``(created, receipt)``.  A byte-equivalent intent replay returns
        the original receipt.  Reusing a command id for different canonical
        content fails closed and cannot overwrite the first local decision.
        """
        claim, existing = self.claim_control_intent(session_id, command_id, intent)
        if claim == "FINAL":
            return False, dict(existing["receipt"])
        if claim == "PROCESSING":
            raise TrustedSessionError(
                "TRUSTED_CONTROL_RESULT_UNCERTAIN",
                "control intent was claimed but its result is not durable",
            )
        return True, self.finalize_control_result(session_id, command_id, receipt)

    def claim_control_intent(
        self, session_id: str, command_id: str, intent: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        """Durably bind an immutable intent before performing its side effect."""
        with self._mutex(session_id):
            self.load(session_id)
            path = self.control_result_path(session_id, command_id)
            intent_value = dict(intent)
            intent_fingerprint = _record_fingerprint(intent_value)
            if path.exists():
                existing = self.load_control_result(session_id, command_id)
                existing_hash = existing["intent"].get("intent_hash")
                incoming_hash = intent_value.get("intent_hash")
                same_intent = (
                    existing_hash == incoming_hash
                    if existing_hash is not None and incoming_hash is not None
                    else existing["intent_fingerprint"] == intent_fingerprint
                )
                if not same_intent:
                    raise TrustedSessionError(
                        "TRUSTED_REPAIR_IDEMPOTENCY_CONFLICT",
                        "control command id is already bound to different content",
                    )
                return (
                    "FINAL" if isinstance(existing.get("receipt"), dict) else "PROCESSING",
                    existing,
                )
            envelope = {
                "intent": intent_value,
                "intent_fingerprint": intent_fingerprint,
                "receipt": None,
                "receipt_fingerprint": None,
                "processing_started_at": _utc_now(),
            }
            _atomic_json(path, envelope)
            return "NEW", envelope

    def finalize_control_result(
        self, session_id: str, command_id: str, receipt: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self._mutex(session_id):
            envelope = self.load_control_result(session_id, command_id)
            if isinstance(envelope.get("receipt"), dict):
                if envelope.get("receipt_fingerprint") != _record_fingerprint(receipt):
                    raise TrustedSessionError(
                        "TRUSTED_REPAIR_IDEMPOTENCY_CONFLICT",
                        "control result is already finalized with different content",
                    )
                return dict(envelope["receipt"])
            receipt_value = dict(receipt)
            envelope["receipt"] = receipt_value
            envelope["receipt_fingerprint"] = _record_fingerprint(receipt_value)
            envelope["finalized_at"] = _utc_now()
            _atomic_json(self.control_result_path(session_id, command_id), envelope)
            return receipt_value

    def load_control_result(self, session_id: str, command_id: str) -> dict[str, Any]:
        with self._mutex(session_id):
            try:
                envelope = json.loads(
                    self.control_result_path(session_id, command_id).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise TrustedSessionError(
                    "TRUSTED_CONTROL_RESULT_MISSING", "control result is unavailable"
                ) from exc
            if (
                not isinstance(envelope, dict)
                or not isinstance(envelope.get("intent"), dict)
                or envelope.get("intent_fingerprint")
                != _record_fingerprint(envelope["intent"])
                or (
                    envelope.get("receipt") is not None
                    and (
                        not isinstance(envelope.get("receipt"), dict)
                        or envelope.get("receipt_fingerprint")
                        != _record_fingerprint(envelope["receipt"])
                    )
                )
            ):
                raise TrustedSessionError(
                    "TRUSTED_CONTROL_RESULT_CORRUPT", "control result integrity check failed"
                )
            return envelope

    def list_control_receipts(self, session_id: str) -> list[dict[str, Any]]:
        directory = self.directory / _validated_session_id(session_id) / "control-intents"
        if not directory.exists():
            return []
        receipts = []
        for path in sorted(directory.glob("*.json")):
            receipt = self.load_control_result(session_id, path.stem).get("receipt")
            if isinstance(receipt, dict):
                receipts.append(dict(receipt))
        return receipts

    def append_event(self, session_id: str, event: Mapping[str, Any]) -> dict[str, Any]:
        with self._mutex(session_id):
            metadata = self.load(session_id)
            last_sequence = self._last_event_sequence(session_id)
            sequence = int(metadata["next_event_sequence"])
            if sequence <= last_sequence:
                # Event fsync succeeded but metadata replace did not: recover forward.
                sequence = last_sequence + 1
            elif sequence != last_sequence + 1:
                raise TrustedSessionError(
                    "TRUSTED_EVENT_JOURNAL_GAP", "metadata and append-only event journal disagree"
                )
            value = dict(event)
            value.update(
                event_id=str(uuid.uuid4()),
                session_id=session_id,
                event_sequence=sequence,
                occurred_at=value.get("occurred_at") or _utc_now(),
            )
            canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            value["event_fingerprint"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
            path = self.events_path(session_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(path, 0o600)
            self.update(session_id, next_event_sequence=sequence + 1)
            return value

    def _last_event_sequence(self, session_id: str) -> int:
        path = self.events_path(session_id)
        if not path.exists():
            return 0
        last = 0
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    value = json.loads(line)
                    sequence = value.get("event_sequence")
                    if type(sequence) is not int or sequence != last + 1:
                        raise TrustedSessionError(
                            "TRUSTED_EVENT_JOURNAL_GAP", "event journal is not contiguous"
                        )
                    last = sequence
        except (OSError, ValueError) as exc:
            raise TrustedSessionError("TRUSTED_EVENT_JOURNAL_CORRUPT", "event journal unavailable") from exc
        return last

    def iter_metadata(self) -> Iterable[dict[str, Any]]:
        if not self.directory.exists():
            return
        for path in self.directory.glob("*/metadata.json"):
            try:
                with path.open("r", encoding="utf-8") as stream:
                    value = json.load(stream)
            except (OSError, ValueError):
                continue
            yield value

    def read_events(self, session_id: str) -> list[dict[str, Any]]:
        """Read the complete redacted journal after validating contiguity.

        The HTTP/callback layer uses this as a reconciliation source.  It never
        reads the encrypted raw transcript.
        """
        path = self.events_path(session_id)
        if not path.exists():
            return []
        values: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8") as stream:
                for expected, line in enumerate(stream, 1):
                    value = json.loads(line)
                    if not isinstance(value, dict) or value.get("event_sequence") != expected:
                        raise TrustedSessionError(
                            "TRUSTED_EVENT_JOURNAL_GAP", "event journal is not contiguous"
                        )
                    values.append(value)
        except (OSError, ValueError) as exc:
            raise TrustedSessionError(
                "TRUSTED_EVENT_JOURNAL_CORRUPT", "event journal unavailable"
            ) from exc
        return values


class EncryptedTranscriptStore:
    """AES-256-GCM append-only transcript records bound to one session."""

    def __init__(self, directory: str, *, key: bytes, key_id: str):
        if len(key) != 32:
            raise TrustedSessionError("TRUSTED_TRANSCRIPT_KEY_INVALID", "AES-256-GCM key must be 32 bytes")
        if not key_id:
            raise TrustedSessionError("TRUSTED_TRANSCRIPT_KEY_INVALID", "key_id is required")
        self.directory = Path(directory)
        self.key = key
        self.key_id = key_id
        self.aes = AESGCM(key)

    @classmethod
    def from_config(
        cls, config: TrustedSessionConfig, *, environ: Mapping[str, str] | None = None
    ) -> "EncryptedTranscriptStore":
        env = environ if environ is not None else os.environ
        if bool(config.encryption_key_env) == bool(config.encryption_key_file):
            raise TrustedSessionError(
                "TRUSTED_TRANSCRIPT_KEY_INVALID", "exactly one transcript key source is required"
            )
        if config.encryption_key_env:
            encoded = env.get(config.encryption_key_env, "")
        else:
            try:
                key_path = Path(config.encryption_key_file)
                encoded = cls._read_or_create_key_file(key_path)
            except OSError as exc:
                raise TrustedSessionError("TRUSTED_TRANSCRIPT_KEY_UNAVAILABLE", "key file unavailable") from exc
        try:
            key = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise TrustedSessionError("TRUSTED_TRANSCRIPT_KEY_INVALID", "key must be valid base64") from exc
        return cls(config.transcript_dir, key=key, key_id=config.encryption_key_id)

    @staticmethod
    def _read_or_create_key_file(key_path: Path) -> str:
        """Create the Runner-local transcript key atomically on first use."""
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform == "linux":
            os.chmod(key_path.parent, 0o700)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(key_path, flags, 0o600)
        except FileExistsError:
            info = os.lstat(key_path)
            if not stat.S_ISREG(info.st_mode):
                raise TrustedSessionError(
                    "TRUSTED_TRANSCRIPT_KEY_UNAVAILABLE", "key file must be a regular file"
                )
            if sys.platform == "linux" and info.st_mode & 0o077:
                raise TrustedSessionError(
                    "TRUSTED_TRANSCRIPT_KEY_PERMISSIONS", "key file must not be accessible by group/other"
                )
            return key_path.read_text(encoding="ascii").strip()
        try:
            encoded = base64.b64encode(os.urandom(32)).decode("ascii")
            os.write(fd, (encoded + "\n").encode("ascii"))
            os.fsync(fd)
            if sys.platform == "linux":
                os.fchmod(fd, 0o600)
            return encoded
        finally:
            os.close(fd)

    def append(self, session_id: str, raw_line: str) -> None:
        session_id = _validated_session_id(session_id)
        path = self.directory / f"{session_id}.jsonl.enc"
        path.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        aad = f"trusted-transcript-v1:{session_id}:{self.key_id}".encode()
        ciphertext = self.aes.encrypt(nonce, raw_line.encode("utf-8"), aad)
        record = {
            "v": 1,
            "key_id": self.key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        with path.open("a", encoding="ascii", newline="\n") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)

    def decrypt(self, session_id: str) -> list[str]:
        session_id = _validated_session_id(session_id)
        path = self.directory / f"{session_id}.jsonl.enc"
        aad = f"trusted-transcript-v1:{session_id}:{self.key_id}".encode()
        output = []
        with path.open("r", encoding="ascii") as stream:
            for line in stream:
                record = json.loads(line)
                if record["key_id"] != self.key_id:
                    raise TrustedSessionError("TRUSTED_TRANSCRIPT_KEY_MISMATCH", "record key_id mismatch")
                output.append(
                    self.aes.decrypt(
                        base64.b64decode(record["nonce"]),
                        base64.b64decode(record["ciphertext"]),
                        aad,
                    ).decode("utf-8")
                )
        return output

    def cleanup(
        self,
        *,
        retention_days: int = 30,
        now: float | None = None,
        active_session_ids: Iterable[str] = (),
    ) -> list[Path]:
        cutoff = (now if now is not None else time.time()) - retention_days * 86400
        active = {_validated_session_id(item) for item in active_session_ids}
        removed = []
        if not self.directory.exists():
            return removed
        for path in self.directory.glob("*.jsonl.enc"):
            if path.stem.split(".", 1)[0] not in active and path.stat().st_mtime < cutoff:
                path.unlink()
                removed.append(path)
        return removed


@dataclass
class ParsedStream:
    events: list[dict[str, Any]] = field(default_factory=list)
    terminal_seen: bool = False
    risk_pause_seen: bool = False
    remote_command_seen: bool = False
    open_tools: set[str] = field(default_factory=set)
    result_error_seen: bool = False
    result_failure: InspectionFailure | None = None
    provider_unavailable_retry_count: int = 0
    early_failure: InspectionFailure | None = None
    verification_outcome: str | None = None
    verification_marker_count: int = 0


class StreamJsonParser:
    """Map only known Claude stream messages; unknown records stay transcript-only."""

    def __init__(self, *, phase: str = "diagnosing"):
        if phase not in {"diagnosing", "executing", "inspecting", "proposing", "initializing"}:
            raise ValueError("unsupported trusted stream phase")
        self.phase = phase
        self.state = ParsedStream()

    def parse_line(self, line: str) -> list[dict[str, Any]]:
        try:
            payload = _strict_json_loads(line)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TrustedSessionError("TRUSTED_STREAM_INVALID_JSON", "Claude stream contains invalid JSON") from exc
        if not isinstance(payload, dict):
            return []
        kind = payload.get("type")
        if self.state.terminal_seen:
            raise TrustedSessionError(
                "TRUSTED_STREAM_AFTER_TERMINAL", "Claude emitted data after the result marker"
            )
        events: list[dict[str, Any]] = []
        if kind == "system":
            if payload.get("subtype") == "init":
                events.append({"event_type": "diagnosis_started", "actor": "runner"})
            elif payload.get("subtype") == "api_retry":
                self._api_retry(payload, events)
        elif kind == "assistant":
            self.state.provider_unavailable_retry_count = 0
            events.extend(self._assistant(payload))
        elif kind == "user":
            self.state.provider_unavailable_retry_count = 0
            if self.state.risk_pause_seen:
                raise TrustedSessionError(
                    "TRUSTED_RISK_MARKER_VIOLATION", "tool activity followed a risk pause marker"
                )
            if self.state.verification_marker_count:
                raise TrustedSessionError(
                    "TRUSTED_VERIFICATION_MARKER_VIOLATION",
                    "tool activity followed a verification marker",
                )
            events.extend(self._tool_results(payload))
        elif kind == "result":
            self.state.terminal_seen = True
            if payload.get("is_error") or payload.get("subtype") != "success":
                self.state.result_error_seen = True
                self.state.result_failure = _claude_result_failure(payload)
                events.append(
                    {
                        "event_type": "session_failed",
                        "stderr_summary": "Claude reported failure",
                    }
                )
            else:
                events.extend(self._terminal_structured_output(payload.get("structured_output")))
                events.append({"event_type": "session_finished"})
        # stream_event, rate_limit_event and future types are intentionally ignored.
        self.state.events.extend(events)
        return events

    def _api_retry(
        self, payload: Mapping[str, Any], events: list[dict[str, Any]]
    ) -> None:
        if self.state.early_failure is not None:
            return
        if self.phase != "inspecting" or type(payload.get("error_status")) is not int:
            self.state.provider_unavailable_retry_count = 0
            return
        if payload["error_status"] != 503:
            self.state.provider_unavailable_retry_count = 0
            return
        self.state.provider_unavailable_retry_count += 1
        if (
            self.state.provider_unavailable_retry_count
            < _INSPECTION_PROVIDER_UNAVAILABLE_RETRY_LIMIT
        ):
            return
        self.state.early_failure = InspectionFailure(
            "MODEL_PROVIDER_UNAVAILABLE", 503
        )
        events.append(
            {
                "event_type": "session_failed",
                "stderr_summary": "Claude provider retry limit reached",
            }
        )

    def _content(self, payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        message = payload.get("message")
        content = message.get("content") if isinstance(message, Mapping) else payload.get("content")
        return content if isinstance(content, list) else []

    def _assistant(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        events = []
        for block in self._content(payload):
            if not isinstance(block, Mapping):
                continue
            if self.state.risk_pause_seen:
                raise TrustedSessionError(
                    "TRUSTED_RISK_MARKER_VIOLATION", "business content followed a risk pause marker"
                )
            if block.get("type") == "tool_use":
                if self.state.verification_marker_count:
                    raise TrustedSessionError(
                        "TRUSTED_VERIFICATION_MARKER_VIOLATION",
                        "tool activity followed a verification marker",
                    )
                tool_id = str(block.get("id") or "")
                if not tool_id or tool_id in self.state.open_tools:
                    raise TrustedSessionError(
                        "TRUSTED_STREAM_TOOL_ID_INVALID", "tool_use requires a unique non-empty id"
                    )
                self.state.open_tools.add(tool_id)
                name = str(block.get("name") or "")
                tool_input = block.get("input") if isinstance(block.get("input"), Mapping) else {}
                command = str(tool_input.get("command") or "")
                event: dict[str, Any] = {"event_type": "tool_started", "metadata": {"tool": name}}
                if name.lower() in {"bash", "shell", "terminal"} and command:
                    event.update(
                        event_type="command_started",
                        command_redacted=redact_sensitive(command),
                        command_fingerprint=command_fingerprint(command),
                        cwd=tool_input.get("cwd"),
                    )
                    if _may_start_remote_process(command):
                        self.state.remote_command_seen = True
                events.append(event)
            elif block.get("type") == "text":
                events.extend(self._assistant_control_marker(str(block.get("text") or "")))
        return events

    def _assistant_control_marker(self, text: str) -> list[dict[str, Any]]:
        """Accept execution markers only from an exact assistant JSON object.

        Diagnosis proposals never enter here.  Tool results and terminal
        ``result.result`` are also excluded, so target output cannot forge a
        control marker.
        """
        if self.phase != "executing":
            return []
        try:
            marker = _strict_json_loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            if self.state.verification_marker_count:
                self.state.verification_outcome = "unknown"
            return []
        if not isinstance(marker, Mapping):
            if self.state.verification_marker_count:
                self.state.verification_outcome = "unknown"
            return []
        if self.state.verification_marker_count and marker.get("kind") != "verification":
            raise TrustedSessionError(
                "TRUSTED_VERIFICATION_MARKER_VIOLATION",
                "business content followed a verification marker",
            )
        if marker.get("kind") == "plan_delta":
            delta = dict(marker.get("plan_delta", marker))
            if delta.get("actual_command"):
                delta["actual_command_fingerprint"] = command_fingerprint(str(delta["actual_command"]))
                delta["actual_command"] = redact_sensitive(str(delta["actual_command"]))
            return [{"event_type": "plan_delta", "plan_delta": delta}]
        kind = marker.get("kind")
        if kind == "verification":
            self.state.verification_marker_count += 1
            raw_result = marker.get("result")
            status = marker.get("status")
            exact_shape = set(marker) == {"kind", "status", "result"}
            if (
                self.state.verification_marker_count != 1
                or not exact_shape
                or not isinstance(raw_result, str)
                or not raw_result.strip()
            ):
                outcome = "unknown"
            elif status == "succeeded":
                outcome = "success"
            elif status == "failed":
                outcome = "failed"
            else:
                outcome = "unknown"
            self.state.verification_outcome = outcome
            return [{
                "event_type": "verification_finished",
                "metadata": {
                    "result": redact_sensitive(
                        raw_result if isinstance(raw_result, str) else ""
                    ),
                    "outcome": outcome,
                },
            }]
        if kind == "risk_confirmation_required":
            required = {
                "risk_confirmation_id", "command", "reason", "affected_scope",
                "rollback_instructions", "consequence_if_not_executed", "requested_at", "expires_at",
            }
            if set(marker) != {"kind", *required} or any(
                not marker.get(field) for field in required
            ):
                raise TrustedSessionError(
                    "TRUSTED_RISK_MARKER_INVALID", "risk confirmation marker is incomplete"
                )
            try:
                _validated_session_id(str(marker["risk_confirmation_id"]))
                requested = datetime.fromisoformat(str(marker["requested_at"]).replace("Z", "+00:00"))
                expires = datetime.fromisoformat(str(marker["expires_at"]).replace("Z", "+00:00"))
                if requested.tzinfo is None or expires.tzinfo is None or expires <= requested:
                    raise ValueError("invalid risk TTL")
            except (ValueError, TrustedSessionError) as exc:
                raise TrustedSessionError(
                    "TRUSTED_RISK_MARKER_INVALID", "risk confirmation ID or TTL is invalid"
                ) from exc
            self.state.risk_pause_seen = True
            risk = dict(marker)
            raw_command = str(risk.get("command") or "")
            risk["command"] = redact_sensitive(raw_command)
            return [{
                "event_type": "risk_confirmation_requested",
                "risk_confirmation": risk,
                "command_fingerprint": command_fingerprint(raw_command),
            }]
        return []

    def _terminal_structured_output(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, Mapping):
            return []
        if self.phase == "inspecting":
            return [{
                "event_type": "inspection_report_created",
                "inspection_report": dict(value),
            }]
        if self.phase == "initializing":
            return [{
                "event_type": "host_context_created",
                "host_context": dict(value),
            }]
        if self.phase not in {"diagnosing", "proposing"}:
            return []
        try:
            draft = validate_diagnosis_draft(value)
        except Exception as exc:
            raise TrustedSessionError(
                "TRUSTED_PROPOSAL_DRAFT_INVALID",
                "terminal diagnosis structured_output is invalid",
            ) from exc
        return [{"event_type": "proposal_draft_created", "proposal_draft": draft}]

    def _tool_results(self, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        events = []
        for block in self._content(payload):
            if not isinstance(block, Mapping) or block.get("type") != "tool_result":
                continue
            tool_id = str(block.get("tool_use_id") or "")
            if not tool_id or tool_id not in self.state.open_tools:
                raise TrustedSessionError(
                    "TRUSTED_STREAM_TOOL_RESULT_UNKNOWN", "tool_result does not match an open tool"
                )
            self.state.open_tools.remove(tool_id)
            content = block.get("content", "")
            if isinstance(content, list):
                content = json.dumps(content, ensure_ascii=False)
            events.append(
                {
                    "event_type": "tool_finished",
                    "stdout_summary": redact_sensitive(str(content), limit=1000),
                    "metadata": {"is_error": bool(block.get("is_error"))},
                }
            )
        return events

    def finalize(self, *, returncode: int) -> None:
        if self.state.result_failure is not None:
            raise TrustedSessionError(
                "TRUSTED_CLAUDE_RESULT_ERROR",
                "Claude returned an error result",
                failure_code=self.state.result_failure.code,
                http_status=self.state.result_failure.http_status,
            )
        if returncode != 0:
            raise TrustedSessionError(
                "TRUSTED_PROCESS_EXIT_UNCERTAIN",
                f"Claude exited with {returncode}",
            )
        if self.state.open_tools:
            raise TrustedSessionError("TRUSTED_STREAM_UNCLOSED_TOOL", "Claude stream ended with an open tool")
        if not self.state.terminal_seen:
            raise TrustedSessionError("TRUSTED_STREAM_NO_TERMINAL", "Claude stream lacks a result marker")
        if self.state.result_error_seen:
            raise TrustedSessionError(
                "TRUSTED_CLAUDE_RESULT_ERROR", "Claude returned an error result"
            )


class ProcessRegistry:
    def __init__(self):
        self._processes: dict[str, Any] = {}
        self._lock = threading.RLock()

    def register(self, session_id: str, process: Any) -> None:
        with self._lock:
            if session_id in self._processes:
                raise TrustedSessionError("TRUSTED_SESSION_BUSY", "process already registered")
            self._processes[session_id] = process

    def unregister(self, session_id: str) -> None:
        with self._lock:
            self._processes.pop(session_id, None)

    def contains(self, session_id: str) -> bool:
        with self._lock:
            return session_id in self._processes

    def cancel(self, session_id: str, *, timeout: float = 5.0) -> bool:
        with self._lock:
            process = self._processes.get(session_id)
        if process is None:
            return False
        _signal_process_tree(process, force=False)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _signal_process_tree(process, force=True)
            process.wait(timeout=timeout)
        stopped = process.poll() is not None
        if stopped:
            self.unregister(session_id)
        return stopped

    def cancel_all(self) -> dict[str, bool]:
        with self._lock:
            session_ids = tuple(self._processes)
        results: dict[str, bool] = {}
        for session_id in session_ids:
            try:
                results[session_id] = self.cancel(session_id)
            except Exception:
                results[session_id] = False
        return results


def _signal_process_tree(process: Any, *, force: bool) -> None:
    if sys.platform == "linux" and getattr(process, "pid", None):
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL if force else signal.SIGTERM)
            return
        except (OSError, ProcessLookupError):
            pass
    if force:
        process.kill()
    else:
        process.terminate()


def _process_start_fingerprint(pid: int | None) -> str | None:
    if sys.platform != "linux" or not pid:
        return None
    try:
        stat_fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        start_ticks = stat_fields[21]
        executable = os.readlink(f"/proc/{pid}/exe")
    except (OSError, IndexError):
        return None
    value = f"{pid}:{start_ticks}:{executable}".encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _process_group_id(pid: int | None) -> int | None:
    if sys.platform != "linux" or not pid:
        return None
    try:
        return os.getpgid(pid)
    except OSError:
        # The child may exit between Popen returning and journal metadata being
        # captured.  That race must not turn an otherwise valid run into a
        # Trusted session failure.
        return None


def _orphan_identity_matches(metadata: Mapping[str, Any]) -> bool:
    if sys.platform != "linux":
        return False
    pid = metadata.get("pid")
    pgid = metadata.get("pgid")
    fingerprint = metadata.get("process_start_fingerprint")
    if type(pid) is not int or type(pgid) is not int or not fingerprint:
        return False
    try:
        return os.getpgid(pid) == pgid and _process_start_fingerprint(pid) == fingerprint
    except OSError:
        return False


def _minimal_child_env(source: Mapping[str, str], session_store_dir: str, target_ssh: Mapping[str, Any] | None = None) -> dict[str, str]:
    # These are the only model-provider credentials/configuration forwarded to
    # Claude.  They support an API-compatible third-party gateway without
    # exposing Runner callback, administration or transcript secrets.
    allow = {
        "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
        "TERM", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "WINDIR", "COMSPEC",
        "SSH_AUTH_SOCK",
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
    }
    env = {key: value for key, value in source.items() if key.upper() in allow}
    # Do not let Claude's shell snapshot import the Runner account's user
    # profile.  The dedicated 0700 session store is also the child HOME.
    env["HOME"] = session_store_dir
    if sys.platform == "linux":
        env["SHELL"] = "/bin/bash"
        env["CLAUDE_CODE_SHELL"] = "/bin/bash"
    else:
        # Trusted sessions are Linux-only.  Retaining a deterministic fallback
        # makes the process adapter unit-testable without importing the caller's
        # shell initialization variables.
        env.setdefault("PATH", os.defpath)
    env["CLAUDE_CONFIG_DIR"] = session_store_dir
    env["CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR"] = "1"
    env["CLAUDE_CODE_DISABLE_BACKGROUND_TASKS"] = "1"
    if target_ssh is not None:
        env.update({
            "AIOPS_TARGET_SSH_USER": str(target_ssh["user"]),
            "AIOPS_TARGET_ADDRESS": str(target_ssh["address"]),
            "AIOPS_TARGET_PORT": str(target_ssh["port"]),
            "AIOPS_TARGET_SSH_KEY": str(target_ssh["key_path"]),
            "AIOPS_TARGET_KNOWN_HOSTS": str(target_ssh["known_hosts_path"]),
            "AIOPS_TARGET_COMMAND_TIMEOUT_SEC": str(target_ssh["command_timeout_sec"]),
        })
    return env


def _propagate_confirmed_project_trust(
    source: Mapping[str, str], session_store_dir: str, project_dir: str
) -> None:
    """Copy only an already-confirmed local project trust decision.

    Trusted sessions intentionally use a separate ``CLAUDE_CONFIG_DIR`` so
    runner credentials cannot bleed into Claude.  Claude stores its project
    trust decision in that directory too, though, so without this narrow copy
    it sees every automated invocation as an untrusted workspace.  We never
    create trust: a user must have accepted it in their normal Claude config
    first.
    """
    home = source.get("HOME", "")
    if not home:
        return
    source_path = Path(home) / ".claude.json"
    target_path = Path(session_store_dir) / ".claude.json"
    try:
        source_config = json.loads(source_path.read_text(encoding="utf-8"))
        source_projects = source_config.get("projects")
        if not isinstance(source_projects, dict):
            return
        candidates = (
            os.path.abspath(project_dir),
            os.path.dirname(os.path.abspath(project_dir)),
        )
        confirmed = {
            path: value
            for path in candidates
            if isinstance((value := source_projects.get(path)), dict)
            and value.get("hasTrustDialogAccepted") is True
        }
        if not confirmed:
            return
        try:
            target_config = json.loads(target_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            target_config = {}
        if not isinstance(target_config, dict):
            target_config = {}
        target_projects = target_config.setdefault("projects", {})
        if not isinstance(target_projects, dict):
            target_projects = target_config["projects"] = {}
        changed = False
        for path, value in confirmed.items():
            current = target_projects.get(path)
            if not isinstance(current, dict) or current.get("hasTrustDialogAccepted") is not True:
                target_projects[path] = {"hasTrustDialogAccepted": True}
                changed = True
        if not changed:
            return
        temporary = target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}")
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(target_config, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target_path)
        os.chmod(target_path, 0o600)
    except OSError:
        # The invocation can still run with Claude's normal trust behaviour;
        # this helper must not weaken session fail-closed protocol handling.
        return


@dataclass(frozen=True)
class ClaudeRunResult:
    events: tuple[dict[str, Any], ...]
    risk_pause: bool
    remote_command_seen: bool
    verification_outcome: str | None


class ClaudeSessionAdapter:
    """Popen adapter with explicit UUID creation and resume-only continuation."""

    def __init__(
        self,
        *,
        project_dir: str,
        session_store_dir: str,
        transcript_store: EncryptedTranscriptStore,
        registry: ProcessRegistry,
        popen_factory: Callable[..., Any] = subprocess.Popen,
        claude_bin: str = "claude",
        base_env: Mapping[str, str] | None = None,
        process_started: Callable[[str, int | None, int | None, str | None], None] | None = None,
    ):
        self.project_dir = os.path.abspath(project_dir)
        self.session_store_dir = os.path.abspath(session_store_dir)
        self.transcript_store = transcript_store
        self.registry = registry
        self.popen_factory = popen_factory
        self.base_env = dict(base_env if base_env is not None else os.environ)
        resolved_claude = shutil.which(
            claude_bin, path=self.base_env.get("PATH")
        )
        self.claude_bin = (
            os.path.abspath(resolved_claude) if resolved_claude else claude_bin
        )
        self.process_started = process_started

    def argv(
        self,
        claude_session_id: str,
        *,
        resume: bool,
        skill_name: str = "trusted-repair-session",
        output_schema: str | None = None,
        allow_tools: bool = True,
        append_skill_prompt: bool = False,
    ) -> list[str]:
        selector = ["--resume", claude_session_id] if resume else ["--session-id", claude_session_id]
        argv = [
            self.claude_bin,
            "-p",
            "--input-format",
            "text",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "dontAsk",
            "--disallowedTools",
            "mcp__*,Read,Grep,Glob,Edit,Write,WebSearch,WebFetch,Agent,Task",
            "--strict-mcp-config",
        ]
        if allow_tools:
            argv.extend([
                "--tools",
                "Skill,Bash",
                "--allowedTools",
                f"Skill({skill_name}),Bash(./bin/target-exec *)",
            ])
        else:
            argv.extend(["--tools", ""])
        if append_skill_prompt:
            skill_path = os.path.abspath(os.path.join(
                self.project_dir, ".claude", "skills", skill_name, "SKILL.md"
            ))
            argv.extend(["--append-system-prompt-file", skill_path])
        if output_schema is not None:
            argv.extend(["--json-schema", output_schema])
        elif not resume:
            argv.extend(["--json-schema", diagnosis_draft_schema_json()])
        return [*argv, *selector]

    def run(
        self,
        *,
        session_id: str,
        claude_session_id: str,
        prompt: str,
        resume: bool,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        timeout_sec: int = 1800,
        command_budget: int | None = None,
        target_ssh: Mapping[str, Any] | None = None,
        spawn_guard: Callable[[], ContextManager[Any]] | None = None,
        pre_spawn: Callable[[], None] | None = None,
        phase: str | None = None,
        skill_name: str = "trusted-repair-session",
        output_schema: str | None = None,
        allow_tools: bool = True,
        append_skill_prompt: bool = False,
    ) -> ClaudeRunResult:
        session_id = _validated_session_id(session_id)
        _validated_session_id(claude_session_id)
        env = _minimal_child_env(self.base_env, self.session_store_dir, target_ssh)
        project = Path(self.project_dir)
        if not (project / ".claude" / "settings.json").is_file() or not (
            project / ".claude" / "skills" / skill_name / "SKILL.md"
        ).is_file():
            raise TrustedSessionError(
                "TRUSTED_PROJECT_INVALID", "dedicated trusted Claude project is missing"
            )
        session_store = Path(self.session_store_dir)
        if resume and not session_store.is_dir():
            raise TrustedSessionError(
                "TRUSTED_CLAUDE_SESSION_MISSING", "Claude session store is missing; no fallback is allowed"
            )
        session_store.mkdir(parents=True, exist_ok=True)
        os.chmod(session_store, 0o700)
        _propagate_confirmed_project_trust(
            self.base_env, self.session_store_dir, self.project_dir
        )
        parser = StreamJsonParser(
            phase=phase or ("executing" if resume else "diagnosing")
        )
        process = None
        registered = False
        completed = False
        try:
            guard = spawn_guard() if spawn_guard is not None else contextlib.nullcontext()
            with guard:
                if pre_spawn is not None:
                    pre_spawn()
                try:
                    process = self.popen_factory(
                        self.argv(
                            claude_session_id,
                            resume=resume,
                            skill_name=skill_name,
                            output_schema=output_schema,
                            allow_tools=allow_tools,
                            append_skill_prompt=append_skill_prompt,
                        ),
                        cwd=self.project_dir,
                        env=env,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=False,
                        start_new_session=sys.platform == "linux",
                    )
                except OSError as exc:
                    raise TrustedSessionError("TRUSTED_PROCESS_SPAWN_FAILED", "Claude process could not start") from exc
                try:
                    self.registry.register(session_id, process)
                    registered = True
                    if self.process_started is not None:
                        pid = getattr(process, "pid", None)
                        pgid = _process_group_id(pid)
                        self.process_started(session_id, pid, pgid, _process_start_fingerprint(pid))
                except Exception:
                    _signal_process_tree(process, force=True)
                    if registered:
                        self.registry.unregister(session_id)
                    raise
            if process.stdin is None or process.stdout is None:
                raise TrustedSessionError("TRUSTED_PROCESS_IO_UNAVAILABLE", "Claude pipes unavailable")
            process.stdin.write(prompt)
            process.stdin.close()
            output_queue: queue.Queue[str | None] = queue.Queue()
            stderr_parts: list[str] = []

            def read_stdout() -> None:
                try:
                    for stream_line in process.stdout:
                        output_queue.put(stream_line)
                finally:
                    output_queue.put(None)

            def read_stderr() -> None:
                if process.stderr is not None:
                    stderr_parts.extend(process.stderr)

            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            deadline = time.monotonic() + timeout_sec
            command_count = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.registry.cancel(session_id)
                    raise TrustedSessionError("TRUSTED_PROCESS_TIMEOUT", "Claude execution TTL expired")
                try:
                    line = output_queue.get(timeout=min(remaining, 0.25))
                except queue.Empty:
                    continue
                if line is None:
                    break
                raw = line.rstrip("\r\n")
                self.transcript_store.append(session_id, raw)
                parsed_events = parser.parse_line(raw)
                if event_sink is not None:
                    for event in parsed_events:
                        if event.get("event_type") == "command_started":
                            command_count += 1
                            if command_budget is not None and command_count > command_budget:
                                self.registry.cancel(session_id)
                                raise TrustedSessionError("TRUSTED_DIAGNOSIS_COMMAND_BUDGET_EXHAUSTED", "Claude diagnosis command budget exhausted")
                        event_sink(event)
                if parser.state.early_failure is not None:
                    raise TrustedSessionError(
                        "TRUSTED_CLAUDE_PROVIDER_RETRY_LIMIT",
                        "Claude provider retry limit reached",
                        failure_code=parser.state.early_failure.code,
                        http_status=parser.state.early_failure.http_status,
                    )
            remaining = max(0.001, deadline - time.monotonic())
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                self.registry.cancel(session_id)
                raise TrustedSessionError("TRUSTED_PROCESS_TIMEOUT", "Claude execution TTL expired") from exc
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            stderr = "".join(stderr_parts)
            if stderr:
                self.transcript_store.append(session_id, json.dumps({"stderr": stderr}))
            parser.finalize(returncode=returncode)
            completed = True
            return ClaudeRunResult(
                tuple(parser.state.events),
                parser.state.risk_pause_seen,
                parser.state.remote_command_seen,
                parser.state.verification_outcome,
            )
        finally:
            if process is not None and not completed and getattr(process, "poll", lambda: None)() is None:
                if registered:
                    self.registry.cancel(session_id)
                else:
                    _signal_process_tree(process, force=True)
            self.registry.unregister(session_id)


def _trusted_project_fingerprint(project_dir: str) -> str:
    """Digest the complete trusted Claude project without following links."""
    root = os.path.abspath(project_dir)
    digest = hashlib.sha256()

    def add_record(kind: bytes, relative_path: str, mode: int, content: bytes = b"") -> None:
        encoded_path = relative_path.replace(os.sep, "/").encode("utf-8")
        digest.update(kind)
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update((mode & 0o777).to_bytes(2, "big"))
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)

    try:
        root_stat = os.lstat(root)
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
            raise OSError("trusted project root is not a real directory")
        add_record(b"D", ".", root_stat.st_mode)

        def walk(directory: str, relative_parent: str = "") -> None:
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda item: item.name)
            for entry in ordered:
                relative = (
                    f"{relative_parent}/{entry.name}"
                    if relative_parent
                    else entry.name
                )
                entry_stat = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(entry_stat.st_mode):
                    raise OSError("trusted project contains a symbolic link")
                if stat.S_ISDIR(entry_stat.st_mode):
                    add_record(b"D", relative, entry_stat.st_mode)
                    walk(entry.path, relative)
                    continue
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise OSError("trusted project contains a special file")
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(entry.path, flags)
                try:
                    opened_stat = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened_stat.st_mode)
                        or (
                            sys.platform == "linux"
                            and (
                                opened_stat.st_dev != entry_stat.st_dev
                                or opened_stat.st_ino != entry_stat.st_ino
                            )
                        )
                    ):
                        raise OSError("trusted project file changed during digest")
                    file_digest = hashlib.sha256()
                    content_size = 0
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        file_digest.update(chunk)
                        content_size += len(chunk)
                    final_stat = os.fstat(descriptor)
                    if (
                        final_stat.st_size != opened_stat.st_size
                        or final_stat.st_mtime_ns != opened_stat.st_mtime_ns
                    ):
                        raise OSError("trusted project file changed during digest")
                finally:
                    os.close(descriptor)
                add_record(
                    b"F",
                    relative,
                    opened_stat.st_mode,
                    content_size.to_bytes(8, "big") + file_digest.digest(),
                )

        walk(root)
    except (OSError, UnicodeError) as exc:
        raise TrustedSessionError(
            "TRUSTED_PROJECT_FINGERPRINT_FAILED",
            "trusted Claude project cannot be fingerprinted safely",
        ) from exc
    return "sha256:" + digest.hexdigest()


def config_fingerprint(config: TrustedSessionConfig) -> str:
    safe = {
        "project_dir": os.path.abspath(config.project_dir),
        "project_content_fingerprint": _trusted_project_fingerprint(
            config.project_dir
        ),
        "journal_dir": os.path.abspath(config.journal_dir),
        "transcript_dir": os.path.abspath(config.transcript_dir),
        "session_store_dir": os.path.abspath(config.session_store_dir),
        "key_id": config.encryption_key_id,
        "inventory_dir": os.path.abspath(config.inventory_dir),
        "runner_instance_id": config.runner_instance_id,
        "runner_config_path": os.path.abspath(config.runner_config_path) if config.runner_config_path else "",
        "runner_config_version": config.runner_config_version,
    }
    encoded = json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class TrustedSessionOrchestrator:
    """Pure local orchestration; no callback retry and no cross-session fallback."""

    def __init__(
        self,
        config: TrustedSessionConfig,
        *,
        journal: SessionJournal,
        adapter: ClaudeSessionAdapter,
        locks: LockBackend,
        registry: ProcessRegistry,
        proposal_validator: Callable[[Mapping[str, Any]], Any],
        os_user: str | None = None,
        clock: Callable[[], datetime] | None = None,
        identity_verify: Callable[[], None] | None = None,
        target_authorizer: Callable[[str], None] | None = None,
        target_profile_resolver: Callable[[str], Mapping[str, Any]] | None = None,
    ):
        self.config = config
        self.journal = journal
        self.adapter = adapter
        self.locks = locks
        self.registry = registry
        self.proposal_validator = proposal_validator
        self.os_user = os_user or getpass.getuser()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._identity_verify = identity_verify
        self._target_authorizer = target_authorizer
        self._target_profile_resolver = target_profile_resolver
        self._lifecycle_gate = threading.RLock()
        self.kill_switch = False
        kill_switch_path = self.journal.directory / "_kill_switch.json"
        if kill_switch_path.is_file():
            try:
                self.kill_switch = bool(json.loads(kill_switch_path.read_text(encoding="utf-8")).get("active"))
            except (OSError, ValueError):
                self.kill_switch = True
        previous_process_started = self.adapter.process_started

        def record_process(
            session_id: str,
            pid: int | None,
            pgid: int | None,
            process_start_fingerprint: str | None,
        ) -> None:
            if previous_process_started is not None:
                previous_process_started(session_id, pid, pgid, process_start_fingerprint)
            self.journal.update(
                session_id,
                pid=pid,
                pgid=pgid,
                process_start_fingerprint=process_start_fingerprint,
            )
            current = self.journal.load(session_id)
            if (
                self.kill_switch
                or current.get("cancel_requested_at")
                or current.get("status") not in {
                    "DIAGNOSING", "EXECUTING", "PROPOSAL_GENERATING"
                }
            ):
                raise TrustedSessionError(
                    "TRUSTED_LAUNCH_CANCELLED", "session was cancelled before process registration completed"
                )

        self.adapter.process_started = record_process

    def _enabled_for(self, logical_target_id: str) -> None:
        self.verify_identity()
        if self.kill_switch:
            raise TrustedSessionError("TRUSTED_KILL_SWITCH_ACTIVE", "trusted session kill switch is active")
        if not self.config.enabled:
            raise TrustedSessionError("TRUSTED_SESSION_DISABLED", "trusted session is disabled for target")
        # Production construction always supplies the local inventory resolver.
        # Retaining this optional makes the orchestration core independently testable;
        # it must not be used to construct the HTTP Runner service.
        if self._target_authorizer is not None:
            self._target_authorizer(logical_target_id)

    def verify_identity(self) -> None:
        """Check the persistent runner identity before every trusted action."""
        if self._identity_verify is None:
            return
        try:
            self._identity_verify()
        except Exception as exc:
            raise TrustedSessionError(
                "TRUSTED_RUNNER_IDENTITY_INVALID",
                "persistent runner identity cannot be proven",
            ) from exc

    def authorize_target(self, logical_target_id: str) -> None:
        """Ingress-only target gate; it never creates a journal or starts Claude."""
        self._enabled_for(logical_target_id)

    def _target_ssh_profile(self, logical_target_id: str) -> Mapping[str, Any] | None:
        return self._target_profile_resolver(logical_target_id) if self._target_profile_resolver else None

    def _pre_spawn(
        self,
        session_id: str,
        expected_status: str,
        binding_validator: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        # Called while the global lifecycle gate is held.  Acquire in the one
        # permitted order (global -> session) and re-read every launch fact.
        with self.locks.acquire(session_id):
            current = self.journal.load(session_id)
            self._enabled_for(str(current["logical_target_id"]))
            self._validate_binding(current)
            if current.get("status") != expected_status or current.get("cancel_requested_at"):
                raise TrustedSessionError(
                    "TRUSTED_LAUNCH_CANCELLED", "session changed before process spawn"
                )
            if binding_validator is not None:
                binding_validator(current)

    def _validate_initial_launch(
        self, session_id: str, current: Mapping[str, Any], approved: tuple[Any, Any, Any]
    ) -> None:
        if approved != (
            current.get("proposal_revision"),
            current.get("proposal_hash_algorithm_id"),
            current.get("proposal_hash"),
        ):
            raise TrustedSessionError("TRUSTED_PROPOSAL_BINDING_MISMATCH", "proposal binding changed")
        now = self.clock()
        try:
            expires = datetime.fromisoformat(
                str(current.get("approval_expires_at", "")).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise TrustedSessionError("TRUSTED_APPROVAL_TIME_INVALID", "approval expiry is invalid") from exc
        if not isinstance(now, datetime) or now.tzinfo is None or expires.tzinfo is None:
            raise TrustedSessionError("TRUSTED_APPROVAL_TIME_INVALID", "approval time must be aware")
        if now >= expires:
            self.journal.update_if(
                session_id,
                lambda value: value.get("status") == "EXECUTING",
                status="EXPIRED",
                terminal_reason="TRUSTED_APPROVAL_EXPIRED",
            )
            raise TrustedSessionError("TRUSTED_APPROVAL_EXPIRED", "initial approval expired before spawn")
        proposal = self.journal.load_proposal(session_id)
        computed = self.proposal_validator(proposal)
        if not isinstance(computed, str):
            computed = proposal.get("proposal_hash")
        if (
            proposal.get("proposal_revision"), proposal.get("proposal_hash_algorithm_id"),
            computed, _record_fingerprint(proposal)
        ) != (*approved, current.get("proposal_content_fingerprint")):
            raise TrustedSessionError("TRUSTED_PROPOSAL_CORRUPT", "proposal changed before spawn")

    def _bind_generated_proposal(
        self,
        proposal_draft: Mapping[str, Any],
        metadata: Mapping[str, Any],
        *,
        command_timeout_seconds: int,
    ) -> dict[str, Any]:
        """Expand only model-owned draft fields into the immutable public v1."""
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise TrustedSessionError(
                "TRUSTED_PROPOSAL_TIME_INVALID",
                "runner proposal clock must be timezone-aware",
            )
        return expand_diagnosis_draft_to_v1(
            proposal_draft,
            runner_provider_id=str(metadata["runner_provider_id"]),
            logical_target_id=str(metadata["logical_target_id"]),
            observed_at=now,
            command_timeout_seconds=command_timeout_seconds,
        )

    def _validate_risk_launch(
        self,
        session_id: str,
        current: Mapping[str, Any],
        risk_confirmation_id: str,
        command_fingerprint_value: str,
        proposal_binding: tuple[Any, Any, Any],
    ) -> None:
        if (
            current.get("risk_confirmation_id") != risk_confirmation_id
            or current.get("risk_command_fingerprint") != command_fingerprint_value
            or (
                current.get("proposal_revision"), current.get("proposal_hash_algorithm_id"),
                current.get("proposal_hash")
            ) != proposal_binding
        ):
            raise TrustedSessionError("TRUSTED_RISK_BINDING_MISMATCH", "risk binding changed")
        now = self.clock()
        try:
            expires = datetime.fromisoformat(
                str(current.get("risk_expires_at", "")).replace("Z", "+00:00")
            )
            risk = self.journal.load_risk(session_id, risk_confirmation_id)
        except (ValueError, TrustedSessionError) as exc:
            raise TrustedSessionError("TRUSTED_RISK_BINDING_CORRUPT", "risk record is invalid") from exc
        if not isinstance(now, datetime) or now.tzinfo is None or expires.tzinfo is None:
            raise TrustedSessionError("TRUSTED_RISK_BINDING_CORRUPT", "risk time must be aware")
        if now >= expires:
            self.journal.update_if(
                session_id,
                lambda value: value.get("status") == "EXECUTING",
                status="EXPIRED",
                terminal_reason="TRUSTED_RISK_CONFIRMATION_EXPIRED",
            )
            raise TrustedSessionError("TRUSTED_RISK_CONFIRMATION_EXPIRED", "risk grant expired before spawn")
        if (
            risk.get("risk_confirmation_id") != risk_confirmation_id
            or risk.get("command_fingerprint") != command_fingerprint_value
            or risk.get("runner_expires_at") != current.get("risk_expires_at")
            or _record_fingerprint(risk) != current.get("risk_content_fingerprint")
        ):
            raise TrustedSessionError("TRUSTED_RISK_BINDING_CORRUPT", "risk record changed before spawn")

    def create_and_diagnose(
        self,
        *,
        session_id: str,
        logical_target_id: str,
        prompt: str,
        bindings: Mapping[str, Any] | None = None,
        accepted_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> ClaudeRunResult:
        session_id = _validated_session_id(session_id)
        self._enabled_for(logical_target_id)
        target_ssh = self._target_ssh_profile(logical_target_id)
        claude_session_id = str(uuid.uuid4())
        metadata = {
            "session_id": session_id,
            "claude_session_id": claude_session_id,
            "logical_target_id": logical_target_id,
            "status": "DIAGNOSING",
            "os_user": self.os_user,
            "cwd": os.path.abspath(self.config.project_dir),
            "session_store_dir": os.path.abspath(self.config.session_store_dir),
            "config_fingerprint": config_fingerprint(self.config),
            "runner_config_version": self.config.runner_config_version or None,
            "runner_instance_id": self.config.runner_instance_id,
            "config_path": os.path.abspath(self.config.runner_config_path)
            if self.config.runner_config_path else "",
            "pid": None,
            "remote_command_seen": False,
        }
        if bindings is not None:
            allowed_bindings = {
                "tenant_id", "run_id", "repair_id", "runner_provider_id", "alert_sha256",
            }
            if set(bindings) != allowed_bindings:
                raise TrustedSessionError(
                    "TRUSTED_SESSION_BINDING_MISMATCH", "dispatch bindings are incomplete or unknown"
                )
            metadata.update({key: bindings[key] for key in allowed_bindings})
        with self.locks.acquire(session_id):
            self._enabled_for(logical_target_id)
            created = self.journal.create(metadata)
            self.journal.append_event(
                session_id,
                {"event_type": "session_created", "actor": {"type": "runner", "id": "runner"}},
            )
            if accepted_sink is not None:
                accepted_sink(dict(created))
        try:
            result = self.adapter.run(
                session_id=session_id,
                claude_session_id=claude_session_id,
                prompt=prompt,
                resume=False,
                event_sink=lambda event: self._persist_live_event(session_id, event),
                timeout_sec=self.config.diagnosis_timeout_sec,
                command_budget=self.config.diagnosis_command_budget,
                target_ssh=target_ssh,
                spawn_guard=lambda: self._lifecycle_gate,
                pre_spawn=lambda: self._pre_spawn(session_id, "DIAGNOSING"),
            )
            proposals = [
                event["proposal_draft"]
                for event in result.events
                if event.get("event_type") == "proposal_draft_created"
            ]
            if len(proposals) != 1:
                raise TrustedSessionError(
                    "TRUSTED_PROPOSAL_MISSING", "diagnosis must produce exactly one repair proposal"
                )
            command_timeout = (
                int(target_ssh["command_timeout_sec"])
                if target_ssh is not None
                else 30
            )
            proposal = self._bind_generated_proposal(
                proposals[0],
                self.journal.load(session_id),
                command_timeout_seconds=command_timeout,
            )
            proposal_hash = self.proposal_validator(proposal)
            if not isinstance(proposal_hash, str):
                proposal_hash = proposal.get("proposal_hash")
            content_fingerprint = self.journal.save_proposal(session_id, proposal)
            approval_now = self.clock()
            if not isinstance(approval_now, datetime) or approval_now.tzinfo is None:
                raise TrustedSessionError(
                    "TRUSTED_APPROVAL_TIME_INVALID", "runner approval clock must be timezone-aware"
                )
            approval_expires_at = approval_now + timedelta(
                seconds=min(self.config.approval_ttl_sec, 1800)
            )
            self.journal.update(
                session_id,
                proposal_revision=proposal.get("proposal_revision"),
                proposal_hash_algorithm_id=proposal.get("proposal_hash_algorithm_id"),
                proposal_hash=proposal_hash or proposal.get("proposal_hash"),
                proposal_content_fingerprint=content_fingerprint,
                approval_expires_at=approval_expires_at.isoformat().replace("+00:00", "Z"),
            )
            self.journal.append_event(
                session_id,
                {"event_type": "proposal_created", "actor": {"type": "claude", "id": "claude"}},
            )
            self._persist_result(session_id, result, resumed=False)
            return result
        except Exception as exc:
            error = self._record_uncertain(session_id, exc)
            if error is exc:
                raise
            raise error from exc

    @staticmethod
    def _execution_completion_contract() -> dict[str, Any]:
        """Return the non-negotiable terminal protocol for every resumed repair."""
        return {
            "required": True,
            "instruction": (
                "不可省略的终态协议：完成修复并逐项验证后，最后一条 assistant content.text "
                "必须且只能是一个 verification JSON 对象；不得在其前后输出自由文本、Markdown、"
                "代码块、第二个 JSON 或任何其他字段。"
            ),
            "source": "single assistant content text JSON object",
            "verification_marker": {
                "kind": "verification",
                "status": "succeeded|failed",
                "result": "non-empty verification summary",
            },
            "valid_examples": [
                '{"kind":"verification","status":"succeeded","result":"简体中文验证结果"}',
                '{"kind":"verification","status":"failed","result":"简体中文失败证据"}',
            ],
            "failure_rule": (
                "验证无法完成、证据不足或任一命令失败时，仍必须输出 status=failed 的 verification "
                "marker；不得直接结束会话。"
            ),
            "forbidden_forms": [
                "free text instead of verification marker",
                "Markdown code fence",
                "additional fields or multiple JSON objects",
                "tool stdout or plan_delta marker",
            ],
            "tool_stdout_is_never_a_control_marker": True,
        }

    def resume(
        self,
        *,
        session_id: str,
        proposal_revision: int,
        proposal_hash_algorithm_id: str,
        proposal_hash: str,
    ) -> ClaudeRunResult:
        session_id = _validated_session_id(session_id)
        metadata = self.journal.load(session_id)
        self._enabled_for(str(metadata["logical_target_id"]))
        target_ssh = self._target_ssh_profile(str(metadata["logical_target_id"]))
        self._validate_binding(metadata)
        approved = (proposal_revision, proposal_hash_algorithm_id, proposal_hash)

        def build_prompt(current: Mapping[str, Any]) -> str:
            bound = (
                current.get("proposal_revision"),
                current.get("proposal_hash_algorithm_id"),
                current.get("proposal_hash"),
            )
            if approved != bound:
                raise TrustedSessionError(
                    "TRUSTED_PROPOSAL_BINDING_MISMATCH", "approval does not match the immutable proposal"
                )
            try:
                current_time = self.clock()
                expires = datetime.fromisoformat(
                    str(current.get("approval_expires_at", "")).replace("Z", "+00:00")
                )
                if (
                    not isinstance(current_time, datetime)
                    or current_time.tzinfo is None
                    or expires.tzinfo is None
                ):
                    raise ValueError("approval times must be timezone-aware")
                if current_time >= expires:
                    self.journal.update_if(
                        session_id,
                        lambda value: value.get("status") == "PENDING_APPROVAL",
                        status="EXPIRED",
                        terminal_reason="TRUSTED_APPROVAL_EXPIRED",
                    )
                    raise TrustedSessionError("TRUSTED_APPROVAL_EXPIRED", "initial approval expired")
                proposal = self.journal.load_proposal(session_id)
                recomputed_hash = self.proposal_validator(proposal)
                if not isinstance(recomputed_hash, str):
                    recomputed_hash = proposal.get("proposal_hash")
                stored_binding = (
                    proposal.get("proposal_revision"),
                    proposal.get("proposal_hash_algorithm_id"),
                    recomputed_hash,
                    _record_fingerprint(proposal),
                )
                metadata_binding = (*bound, current.get("proposal_content_fingerprint"))
                if stored_binding != metadata_binding:
                    raise ValueError("proposal content binding mismatch")
            except TrustedSessionError:
                raise
            except Exception as exc:
                error = TrustedSessionError("TRUSTED_PROPOSAL_CORRUPT", "proposal revalidation failed")
                self._record_uncertain(session_id, error)
                raise error from exc
            return json.dumps(
                {
                    "action": "execute_approved_proposal",
                    "session_id": session_id,
                    "proposal_revision": proposal_revision,
                    "proposal_hash_algorithm_id": proposal_hash_algorithm_id,
                    "proposal_hash": proposal_hash,
                    "approved_proposal": proposal,
                    "completion_contract": self._execution_completion_contract(),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

        return self._resume_bound(
            metadata,
            source_status="PENDING_APPROVAL",
            prompt_builder=build_prompt,
            pre_spawn_validator=lambda current: self._validate_initial_launch(
                session_id, current, approved
            ),
        )

    def resume_after_risk_grant(
        self,
        *,
        session_id: str,
        risk_confirmation_id: str,
        command_fingerprint: str,
    ) -> ClaudeRunResult:
        session_id = _validated_session_id(session_id)
        metadata = self.journal.load(session_id)
        self._enabled_for(str(metadata["logical_target_id"]))
        self._validate_binding(metadata)
        def build_prompt(current: Mapping[str, Any]) -> str:
            if (
                risk_confirmation_id != current.get("risk_confirmation_id")
                or command_fingerprint != current.get("risk_command_fingerprint")
                or (
                    current.get("proposal_revision"),
                    current.get("proposal_hash_algorithm_id"),
                    current.get("proposal_hash"),
                )
                != (
                    metadata.get("proposal_revision"),
                    metadata.get("proposal_hash_algorithm_id"),
                    metadata.get("proposal_hash"),
                )
            ):
                raise TrustedSessionError(
                    "TRUSTED_RISK_BINDING_MISMATCH", "risk decision does not match the pending command"
                )
            try:
                current_time = self.clock()
                expires = datetime.fromisoformat(
                    str(current.get("risk_expires_at", "")).replace("Z", "+00:00")
                )
                risk = self.journal.load_risk(session_id, risk_confirmation_id)
                if (
                    not isinstance(current_time, datetime)
                    or current_time.tzinfo is None
                    or expires.tzinfo is None
                ):
                    raise ValueError("risk times must be timezone-aware")
                if (
                    risk.get("risk_confirmation_id") != risk_confirmation_id
                    or risk.get("command_fingerprint") != command_fingerprint
                    or risk.get("runner_expires_at") != current.get("risk_expires_at")
                    or _record_fingerprint(risk) != current.get("risk_content_fingerprint")
                ):
                    raise ValueError("risk record binding mismatch")
                if current_time >= expires:
                    self.journal.update_if(
                        session_id,
                        lambda value: value.get("status") == "AWAITING_RISK_CONFIRMATION",
                        status="EXPIRED",
                        terminal_reason="TRUSTED_RISK_CONFIRMATION_EXPIRED",
                    )
                    raise TrustedSessionError(
                        "TRUSTED_RISK_CONFIRMATION_EXPIRED", "risk confirmation expired"
                    )
            except TrustedSessionError:
                raise
            except Exception as exc:
                error = TrustedSessionError("TRUSTED_RISK_BINDING_CORRUPT", "risk binding is unavailable")
                self._record_uncertain(session_id, error)
                raise error from exc
            return json.dumps(
                {
                    "action": "execute_confirmed_high_risk_command",
                    "session_id": session_id,
                    "risk_confirmation_id": risk_confirmation_id,
                    "command_fingerprint": command_fingerprint,
                    "approved_risk_summary": {
                        key: risk.get(key)
                        for key in (
                            "reason", "affected_scope", "rollback_instructions",
                            "consequence_if_not_executed", "runner_expires_at",
                        )
                    },
                    "completion_contract": self._execution_completion_contract(),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )

        return self._resume_bound(
            metadata,
            source_status="AWAITING_RISK_CONFIRMATION",
            prompt_builder=build_prompt,
            pre_spawn_validator=lambda current: self._validate_risk_launch(
                session_id,
                current,
                risk_confirmation_id,
                command_fingerprint,
                (
                    metadata.get("proposal_revision"),
                    metadata.get("proposal_hash_algorithm_id"),
                    metadata.get("proposal_hash"),
                ),
            ),
        )

    def _resume_bound(
        self,
        metadata: Mapping[str, Any],
        *,
        source_status: str,
        prompt_builder: Callable[[Mapping[str, Any]], str],
        pre_spawn_validator: Callable[[Mapping[str, Any]], None],
    ) -> ClaudeRunResult:
        session_id = str(metadata["session_id"])
        target_ssh = self._target_ssh_profile(str(metadata["logical_target_id"]))
        with self.locks.acquire(session_id):
            self._enabled_for(str(metadata["logical_target_id"]))
            current = self.journal.load(session_id)
            self._validate_binding(current)
            if (
                current.get("status") != source_status
                or current.get("cancel_requested_at")
                or current.get("claude_session_id") != metadata.get("claude_session_id")
            ):
                raise TrustedSessionError(
                    "TRUSTED_RESUME_STATE_CHANGED", "session changed before Claude could resume"
                )
            prompt = prompt_builder(current)
            claimed, current = self.journal.compare_and_update(
                session_id,
                lambda value: value.get("status") == source_status
                and not value.get("cancel_requested_at")
                and value.get("claude_session_id") == metadata.get("claude_session_id"),
                status="EXECUTING",
                launching=True,
            )
            if not claimed:
                raise TrustedSessionError(
                    "TRUSTED_RESUME_STATE_CHANGED", "session changed before Claude could resume"
                )
            self.journal.append_event(
                session_id,
                {"event_type": "execution_resumed", "actor": {"type": "runner", "id": "runner"}},
            )
        try:
            result = self.adapter.run(
                session_id=session_id,
                claude_session_id=str(metadata["claude_session_id"]),
                prompt=prompt,
                resume=True,
                event_sink=lambda event: self._persist_live_event(session_id, event),
                timeout_sec=self.config.execution_ttl_sec,
                target_ssh=target_ssh,
                spawn_guard=lambda: self._lifecycle_gate,
                pre_spawn=lambda: self._pre_spawn(
                    session_id, "EXECUTING", pre_spawn_validator
                ),
            )
            self.journal.update_if(
                session_id,
                lambda value: value.get("status") == "EXECUTING",
                launching=False,
            )
            self._persist_result(session_id, result, resumed=True)
            return result
        except Exception as exc:
            error = self._record_uncertain(session_id, exc)
            if error is exc:
                raise
            raise error from exc

    def _record_uncertain(self, session_id: str, exc: Exception) -> TrustedSessionError:
        error = exc if isinstance(exc, TrustedSessionError) else TrustedSessionError(
            "TRUSTED_SESSION_INTERNAL_UNCERTAIN", "trusted session failed outside its declared protocol"
        )
        try:
            current = self.journal.load(session_id)
            if current.get("status") not in LOCAL_TERMINAL_STATUSES:
                if (
                    current.get("status") == "DIAGNOSING"
                    and error.code == "TRUSTED_PROCESS_SPAWN_FAILED"
                ):
                    self.journal.update(
                        session_id,
                        status="DIAGNOSIS_FAILED",
                        terminal_reason="TRUSTED_DIAGNOSIS_PROCESS_NOT_STARTED",
                    )
                else:
                    reason = error.code
                    if current.get("status") == "DIAGNOSING":
                        reason = _diagnosis_uncertain_reason(error.code)
                    self.journal.update(
                        session_id, status="MANUAL_INTERVENTION", terminal_reason=reason
                    )
        except Exception:
            pass
        return error

    def _validate_binding(self, metadata: Mapping[str, Any]) -> None:
        expected = {
            "os_user": self.os_user,
            "cwd": os.path.abspath(self.config.project_dir),
            "session_store_dir": os.path.abspath(self.config.session_store_dir),
            "config_fingerprint": config_fingerprint(self.config),
            "runner_instance_id": self.config.runner_instance_id,
            "config_path": os.path.abspath(self.config.runner_config_path)
            if self.config.runner_config_path else "",
        }
        if not metadata.get("claude_session_id") or any(metadata.get(key) != value for key, value in expected.items()):
            raise TrustedSessionError(
                "TRUSTED_SESSION_BINDING_MISMATCH", "resume binding differs from diagnosis binding"
            )

    def _persist_live_event(self, session_id: str, event: Mapping[str, Any]) -> None:
        sanitized = _sanitize_event(json.loads(json.dumps(event)))
        sanitized.pop("proposal", None)
        actor = sanitized.get("actor")
        if not isinstance(actor, Mapping):
            actor_type = actor if actor in {"claude", "runner", "system"} else "claude"
            sanitized["actor"] = {"type": actor_type, "id": str(actor_type)}
        if sanitized.get("event_type") not in {
            "proposal_created",
            "proposal_draft_created",
        }:
            self.journal.append_event(session_id, sanitized)
        if event.get("event_type") == "risk_confirmation_requested":
            raw_risk = event.get("risk_confirmation")
            if not isinstance(raw_risk, Mapping):
                raise TrustedSessionError("TRUSTED_RISK_RECORD_CORRUPT", "risk marker must be an object")
            risk = _sanitize_event(dict(raw_risk))
            now = self.clock()
            if now.tzinfo is None:
                raise TrustedSessionError("TRUSTED_RISK_TIME_INVALID", "runner clock must be timezone-aware")
            requested = datetime.fromisoformat(str(risk.get("requested_at", "")).replace("Z", "+00:00"))
            marker_expires = datetime.fromisoformat(str(risk.get("expires_at", "")).replace("Z", "+00:00"))
            runner_limit = now + timedelta(seconds=self.config.risk_ttl_sec)
            if requested > now or marker_expires <= now or marker_expires > runner_limit:
                raise TrustedSessionError(
                    "TRUSTED_RISK_TTL_INVALID", "risk marker exceeds the runner-controlled TTL"
                )
            risk_record = dict(risk)
            risk_record.update(
                command_fingerprint=event.get("command_fingerprint"),
                runner_received_at=now.isoformat().replace("+00:00", "Z"),
                runner_expires_at=marker_expires.isoformat().replace("+00:00", "Z"),
            )
            risk_content_fingerprint = self.journal.save_risk(
                session_id, str(risk.get("risk_confirmation_id")), risk_record
            )
            self.journal.update(
                session_id,
                risk_confirmation_id=risk.get("risk_confirmation_id"),
                risk_command_fingerprint=event.get("command_fingerprint"),
                risk_expires_at=risk_record["runner_expires_at"],
                risk_content_fingerprint=risk_content_fingerprint,
            )
        command = event.get("command_redacted")
        if command and _may_start_remote_process(str(command)):
            self.journal.update(session_id, remote_command_seen=True)

    def _persist_result(
        self, session_id: str, result: ClaudeRunResult, *, resumed: bool
    ) -> None:
        terminal_reason: str | None = None
        if not resumed:
            status = "PENDING_APPROVAL"
        elif result.risk_pause:
            status = "AWAITING_RISK_CONFIRMATION"
        elif result.verification_outcome == "success":
            status = "SUCCEEDED"
            terminal_reason = "TRUSTED_VERIFICATION_SUCCEEDED"
        elif result.verification_outcome == "failed":
            status = "FAILED"
            terminal_reason = "TRUSTED_VERIFICATION_FAILED"
        else:
            status = "MANUAL_INTERVENTION"
            terminal_reason = "TRUSTED_VERIFICATION_MISSING_OR_UNKNOWN"
        changes: dict[str, Any] = {
            "status": status,
            "remote_command_seen": result.remote_command_seen,
        }
        if terminal_reason is not None:
            changes["terminal_reason"] = terminal_reason
        self.journal.update_if(
            session_id,
            lambda current: not current.get("cancel_requested_at")
            and current.get("status") == ("EXECUTING" if resumed else "DIAGNOSING"),
            **changes,
        )

    def recover_active_as_uncertain(self) -> list[str]:
        affected = []
        for metadata in self.journal.iter_metadata():
            # A completed Claude process is expected while a session waits for
            # initial approval or a risk decision.  Restarting the runner must
            # not turn either safe waiting state into an execution failure.
            # Only a session that was actively diagnosing/executing has an
            # outcome which cannot be proven after process ownership is lost.
            if metadata.get("status") in {
                "DIAGNOSING", "PROPOSAL_GENERATING", "EXECUTING"
            }:
                session_id = str(metadata["session_id"])
                source_status = str(metadata["status"])
                orphan_terminated = False
                if _orphan_identity_matches(metadata):
                    try:
                        os.killpg(int(metadata["pgid"]), signal.SIGTERM)
                        time.sleep(0.1)
                        if _orphan_identity_matches(metadata):
                            os.killpg(int(metadata["pgid"]), signal.SIGKILL)
                        orphan_terminated = not _orphan_identity_matches(metadata)
                    except OSError:
                        orphan_terminated = not _orphan_identity_matches(metadata)
                self.journal.append_event(
                    session_id,
                    {
                        "event_type": "session_interrupted",
                        "stderr_summary": "runner restarted; no automatic resume",
                        "metadata": {"orphan_process_group_terminated": orphan_terminated},
                    },
                )
                self.journal.update(
                    session_id,
                    status="MANUAL_INTERVENTION",
                    terminal_reason=(
                        "TRUSTED_RUNNER_RECOVERED_INCOMPLETE_DIAGNOSIS"
                        if source_status == "DIAGNOSING"
                        else (
                            "TRUSTED_RUNNER_RECOVERED_INCOMPLETE_PROPOSAL"
                            if source_status == "PROPOSAL_GENERATING"
                            else "TRUSTED_EXECUTION_RESULT_UNKNOWN_AFTER_RESTART"
                        )
                    ),
                )
                affected.append(session_id)
        return affected

    def cancel(self, session_id: str) -> str:
        session_id = _validated_session_id(session_id)
        cancel_time = self._runner_clock_iso()
        with self.locks.acquire(session_id):
            metadata = self.journal.update_if(
                session_id,
                lambda current: current.get("status") in ACTIVE_STATUSES,
                cancel_requested_at=cancel_time,
            )
        if metadata.get("status") not in ACTIVE_STATUSES or not metadata.get("cancel_requested_at"):
            return str(metadata.get("status"))
        with self._lifecycle_gate:
            had_process = self.registry.contains(session_id)
            stopped = self.registry.cancel(session_id)
        if metadata.get("status") in {"PENDING_APPROVAL", "AWAITING_RISK_CONFIRMATION"} and not had_process:
            status = "CANCELLED"
            reason = "TRUSTED_NO_ACTIVE_PROCESS"
        elif metadata.get("remote_command_seen") or not stopped:
            status = "MANUAL_INTERVENTION"
            reason = "TRUSTED_REMOTE_PROCESS_UNCERTAIN" if metadata.get("remote_command_seen") else "TRUSTED_LOCAL_PROCESS_UNCONFIRMED"
        else:
            status = "CANCELLED"
            reason = "TRUSTED_LOCAL_PROCESS_STOPPED"
        with self.locks.acquire(session_id):
            final = self.journal.update_if(
                session_id,
                lambda current: current.get("status") in ACTIVE_STATUSES
                and bool(current.get("cancel_requested_at")),
                status=status,
                terminal_reason=reason,
            )
        return str(final.get("status"))

    def apply_control_action(
        self,
        session_id: str,
        *,
        command_id: str,
        action: str,
        desired_terminal: str,
    ) -> tuple[str, bool, str]:
        """Apply a validated AIOps control intent without emitting business events.

        The returned tuple is ``(receipt_outcome, command_result_certain,
        local_status)``.  The caller persists the immutable ControlIntent and
        this result before it sends a ControlReceipt.  ExecutionEvent and
        terminal callbacks are deliberately outside this path: AIOps already
        owns the business decision.
        """
        self.verify_identity()
        session_id = _validated_session_id(session_id)
        initial = self.journal.load(session_id)
        if (
            initial.get("last_control_command_id") == command_id
            and initial.get("last_control_outcome") in {
                "CLOSED", "STOPPED_CONFIRMED", "STOP_UNCERTAIN", "INVALID_INTENT"
            }
            and type(initial.get("last_control_result_certain")) is bool
        ):
            return (
                "ALREADY_APPLIED",
                bool(initial["last_control_result_certain"]),
                str(initial.get("status")),
            )
        if action == "CLOSE_WAITING_SESSION":
            with self._lifecycle_gate:
                with self.locks.acquire(session_id):
                    current = self.journal.load(session_id)
                    status = str(current.get("status"))
                    if status == desired_terminal:
                        return "ALREADY_APPLIED", True, status
                    if status not in {"PENDING_APPROVAL", "AWAITING_RISK_CONFIRMATION"}:
                        return "INVALID_INTENT", False, status
                    # A waiting state is safe only when Claude has exited.  An
                    # unexpected registered process is not silently treated as
                    # closed even though the AIOps terminal remains immutable.
                    if self.registry.contains(session_id):
                        return "STOP_UNCERTAIN", False, status
                    sealed = self.journal.update_if(
                        session_id,
                        lambda value: value.get("status") == status,
                        status=desired_terminal,
                        locally_sealed=True,
                        last_control_command_id=command_id,
                        last_control_outcome="CLOSED",
                        last_control_result_certain=True,
                    )
                    if sealed.get("status") != desired_terminal:
                        return "INVALID_INTENT", False, str(sealed.get("status"))
                    return "CLOSED", True, desired_terminal

        if action != "STOP_ACTIVE_SESSION":
            current = self.journal.load(session_id)
            return "INVALID_INTENT", False, str(current.get("status"))

        cancel_time = self._runner_clock_iso()
        with self.locks.acquire(session_id):
            claimed, metadata = self.journal.compare_and_update(
                session_id,
                lambda current: current.get("status") in {"DIAGNOSING", "EXECUTING"}
                and (
                    not current.get("cancel_requested_at")
                    or current.get("last_control_command_id") == command_id
                ),
                cancel_requested_at=cancel_time,
                last_control_command_id=command_id,
            )
        if not claimed:
            status = str(metadata.get("status"))
            if status == desired_terminal and metadata.get("control_stop_confirmed"):
                return "ALREADY_APPLIED", True, status
            return "INVALID_INTENT", False, status

        with self._lifecycle_gate:
            had_process = self.registry.contains(session_id)
            stopped = self.registry.cancel(session_id)
        result_certain = bool(
            had_process and stopped and not metadata.get("remote_command_seen")
        )
        outcome = "STOPPED_CONFIRMED" if result_certain else "STOP_UNCERTAIN"
        local_status = desired_terminal if result_certain else "MANUAL_INTERVENTION"
        reason = (
            "TRUSTED_CONTROL_STOP_CONFIRMED"
            if result_certain
            else "TRUSTED_CONTROL_STOP_RESULT_UNCERTAIN"
        )
        with self.locks.acquire(session_id):
            updated = self.journal.update_if(
                session_id,
                lambda current: current.get("status") in {"DIAGNOSING", "EXECUTING"}
                and bool(current.get("cancel_requested_at")),
                status=local_status,
                terminal_reason=reason,
                control_stop_confirmed=result_certain,
                last_control_command_id=command_id,
                last_control_outcome=outcome,
                last_control_result_certain=result_certain,
            )
        if updated.get("status") != local_status:
            return "STOP_UNCERTAIN", False, str(updated.get("status"))
        return outcome, result_certain, local_status

    def activate_kill_switch(self) -> dict[str, bool]:
        self.verify_identity()
        cancel_time = self._runner_clock_iso()
        with self._lifecycle_gate:
            self.kill_switch = True
            _atomic_json(
                self.journal.directory / "_kill_switch.json",
                {"active": True, "updated_at": cancel_time},
            )
            # Process termination is unconditional and precedes all fallible
            # journal record tracking. One corrupt session cannot protect another.
            results = self.registry.cancel_all()
            claimed_sessions: dict[str, dict[str, Any]] = {}
            record_tracking_errors: list[str] = []
            for metadata in list(self.journal.iter_metadata()):
                session_id = str(metadata.get("session_id"))
                try:
                    with self.locks.acquire(session_id):
                        claimed = self.journal.update_if(
                            session_id,
                            lambda current: current.get("status") in ACTIVE_STATUSES,
                            cancel_requested_at=cancel_time,
                        )
                except Exception:
                    record_tracking_errors.append(command_fingerprint(session_id))
                    continue
                if claimed.get("status") in ACTIVE_STATUSES and claimed.get("cancel_requested_at"):
                    claimed_sessions[session_id] = claimed
            for session_id, claimed in claimed_sessions.items():
                stopped = results.get(session_id, False)
                if claimed.get("status") in {"PENDING_APPROVAL", "AWAITING_RISK_CONFIRMATION"}:
                    status, reason = "CANCELLED", "TRUSTED_KILL_SWITCH_NO_ACTIVE_PROCESS"
                elif stopped and not claimed.get("remote_command_seen"):
                    status, reason = "CANCELLED", "TRUSTED_KILL_SWITCH_LOCAL_PROCESS_STOPPED"
                else:
                    status, reason = "MANUAL_INTERVENTION", "TRUSTED_KILL_SWITCH_PROCESS_UNCERTAIN"
                try:
                    with self.locks.acquire(session_id):
                        self.journal.update_if(
                            session_id,
                            lambda current: current.get("status") in ACTIVE_STATUSES
                            and bool(current.get("cancel_requested_at")),
                            status=status,
                            terminal_reason=reason,
                        )
                except Exception:
                    record_tracking_errors.append(command_fingerprint(session_id))
            if record_tracking_errors:
                _atomic_json(
                    self.journal.directory / "_kill_switch.json",
                    {
                        "active": True,
                        "updated_at": cancel_time,
                        "record_tracking_error_session_fingerprints": sorted(set(record_tracking_errors)),
                    },
                )
        return results

    def deactivate_kill_switch(self) -> None:
        """Explicit administrator action; never resumes or creates a session."""
        self.verify_identity()
        with self._lifecycle_gate:
            _atomic_json(
                self.journal.directory / "_kill_switch.json",
                {"active": False, "updated_at": self._runner_clock_iso()},
            )
            self.kill_switch = False

    def _runner_clock_iso(self) -> str:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise TrustedSessionError("TRUSTED_RUNNER_CLOCK_INVALID", "runner clock must be timezone-aware")
        return value.isoformat().replace("+00:00", "Z")

    def cleanup_transcripts(self) -> list[Path]:
        active = [
            str(metadata["session_id"])
            for metadata in self.journal.iter_metadata()
            if metadata.get("status") in ACTIVE_STATUSES
        ]
        return self.adapter.transcript_store.cleanup(
            retention_days=self.config.transcript_retention_days,
            active_session_ids=active,
        )


def _sanitize_event(value: Any, *, key: str = "") -> Any:
    if isinstance(value, str):
        if key in {"event_type", "command_fingerprint"} or key.endswith("_id"):
            return value
        return redact_sensitive(value, limit=16384)
    if isinstance(value, list):
        return [_sanitize_event(item) for item in value]
    if isinstance(value, dict):
        return {item_key: _sanitize_event(item, key=item_key) for item_key, item in value.items()}
    return value


def _contains_detectable_secret(value: Any) -> bool:
    if isinstance(value, str):
        normalized = " ".join(value.split())
        return redact_sensitive(value, limit=max(4096, len(normalized) + 1)) != normalized
    if isinstance(value, list):
        return any(_contains_detectable_secret(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_detectable_secret(item) for item in value.values())
    return False


__all__ = [
    "TrustedSessionError",
    "redact_sensitive",
    "command_fingerprint",
    "FcntlLockBackend",
    "SessionJournal",
    "EncryptedTranscriptStore",
    "StreamJsonParser",
    "ProcessRegistry",
    "ClaudeRunResult",
    "ClaudeSessionAdapter",
    "config_fingerprint",
    "TrustedSessionOrchestrator",
]
