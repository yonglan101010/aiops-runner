"""Runner HTTP 薄壳：trusted Claude 修复会话与健康检查。"""

from __future__ import annotations

import json
import os
import sys
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import Auditor
from .auth import Authenticator
from .callback import UrllibSender
from .config import RunnerConfig, load_config
from .deadletter import Deadletter
from .monitor import SelfMonitor
from .trusted_api import (
    TrustedCallbackClient,
    TrustedSessionController,
    load_contract_schema,
)
from .trusted_repair_contract import validate_and_hash_proposal
from .trusted_session import (
    ClaudeSessionAdapter,
    EncryptedTranscriptStore,
    FcntlLockBackend,
    ProcessRegistry,
    SessionJournal,
    TrustedSessionOrchestrator,
)
from .trusted_inventory import ManagedInventory
from .instance_identity import IdentityGuard, InstanceIdentityError, RunnerInstanceLock
from .inspection import InspectionManager
from .host_context import HostContextStore, host_fingerprint
from .kubernetes import KubernetesService

# 冻结契约工件的默认相对位置（runner/ 的上一级节点根 → Trusted 项目）。
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ALERT_SCHEMA = os.path.join(
    _REPO_ROOT, "agent-project-trusted", "references", "trusted-alert-schema.json"
)
_TRUSTED_SCHEMA = os.path.join(
    _REPO_ROOT, "agent-project-trusted", "references", "trusted-repair-contract-v1.schema.json"
)
class Runner:
    """把 config 装配成 trusted 控制面与健康检查。"""

    def __init__(self, cfg: RunnerConfig, *, skill_runner=None, callback=None, sender=None,
                 trusted_orchestrator=None,
                 trusted_callback=None, kubernetes_service=None):
        self.cfg = cfg
        self.authenticator = Authenticator(
            shared_token_env=cfg.webhook.shared_token_env,
            hmac_secret_env=cfg.webhook.hmac_secret_env,
            ip_allowlist=cfg.webhook.ip_allowlist,
        )
        self.deadletter = Deadletter(cfg.deadletter_dir)
        self.monitor = SelfMonitor()
        self.auditor = Auditor(os.path.join(cfg.deadletter_dir, "..", "runner-audit.jsonl")
                               if cfg.deadletter_dir else None)
        # ── Claude 单会话修复：唯一修复链 ────────────────────────────────
        self.trusted = None
        self.inspection = None
        self.kubernetes = None
        self._trusted_instance_lock = None
        self._identity_guard = None
        self.runner_instance_id = ""
        recovered_trusted_sessions = []
        context_for_target = lambda _target_id: ""
        tc = cfg.trusted_session
        # Installation identity belongs to the Runner, rather than a single
        # feature.  It lets AIOps safely restore a replacement connection to
        # the same persisted Runner object.
        # Every production Runner needs this installation identity so a new
        # AIOps connection can be bound back to its existing history.  Local
        # non-Linux unit tests may still construct a minimal Runner without a
        # filesystem identity.
        identity_required = sys.platform == "linux" or tc.enabled or cfg.kubernetes.enabled or kubernetes_service is not None
        if identity_required:
            if trusted_orchestrator is not None and tc.runner_instance_id:
                self.runner_instance_id = tc.runner_instance_id
            else:
                try:
                    self._identity_guard = IdentityGuard(
                        tc.runner_instance_id_file,
                        expected=tc.expected_runner_instance_id,
                    )
                    self.runner_instance_id = self._identity_guard.instance_id
                    tc.runner_instance_id = self.runner_instance_id
                    self._trusted_instance_lock = RunnerInstanceLock(
                        os.path.join(os.path.dirname(tc.runner_instance_id_file), "runner-instance.lock")
                    )
                    self._trusted_instance_lock.acquire()
                except InstanceIdentityError as exc:
                    raise ValueError("runner instance identity is invalid") from exc
        if tc.enabled or trusted_orchestrator is not None:
            schema = load_contract_schema(_TRUSTED_SCHEMA)
            with open(_ALERT_SCHEMA, "r", encoding="utf-8") as stream:
                trusted_alert_schema = json.load(stream)
            if trusted_orchestrator is None:
                journal = SessionJournal(tc.journal_dir)
                registry = ProcessRegistry()
                transcript = EncryptedTranscriptStore.from_config(tc)
                adapter = ClaudeSessionAdapter(
                    project_dir=tc.project_dir,
                    session_store_dir=tc.session_store_dir,
                    transcript_store=transcript,
                    registry=registry,
                )
                # 可信会话始终以 Runner 本地 inventory 作为唯一资产来源；
                # AIOps 不维护或下发第二份主机白名单。
                inventory = ManagedInventory(tc.inventory_dir)
                host_context = HostContextStore(
                    os.path.join(os.path.dirname(tc.journal_dir), "host-context")
                )
                def context_for_target(target_id: str) -> str:
                    host = inventory.resolve_unique_target(target_id)
                    return host_context.prompt_context(
                        str(host["id"]), host_fingerprint(host, inventory.ssh_profile(target_id)),
                        inventory.ssh_profile(target_id),
                    )
                trusted_orchestrator = TrustedSessionOrchestrator(
                    tc,
                    journal=journal,
                    adapter=adapter,
                    locks=FcntlLockBackend(os.path.join(tc.journal_dir, ".locks")),
                    registry=registry,
                    proposal_validator=lambda proposal: validate_and_hash_proposal(proposal, schema),
                    identity_verify=self._identity_guard.verify,
                    target_authorizer=inventory.require_unique_target,
                    target_profile_resolver=inventory.ssh_profile,
                )
                recovered_trusted_sessions = (
                    trusted_orchestrator.recover_active_as_uncertain()
                )
            if trusted_callback is None and tc.aiops_url:
                diagnosis_token = os.environ.get(tc.token_env, "")
                admin_token = os.environ.get(tc.admin_token_env, "")
                if not diagnosis_token:
                    raise ValueError(
                        "trusted session requires the normal runner callback API key"
                    )
                if not admin_token:
                    raise ValueError(
                        "trusted admin credential must be configured"
                    )
                trusted_callback = TrustedCallbackClient(
                    events_url=tc.aiops_url,
                    token_env=tc.token_env,
                    sender=sender or UrllibSender(),
                    schema=schema,
                    identity_verify=trusted_orchestrator.verify_identity,
                )
            self.trusted = TrustedSessionController(
                trusted_orchestrator, callback=trusted_callback, schema=schema,
                alert_schema=trusted_alert_schema, context_provider=context_for_target,
            )
            for recovered_session_id in recovered_trusted_sessions:
                recovered = trusted_orchestrator.journal.load(
                    recovered_session_id
                )
                if (
                    recovered.get("session_kind") != "inspection"
                    or recovered.get("terminal_reason")
                    == "TRUSTED_RUNNER_RECOVERED_INCOMPLETE_PROPOSAL"
                ):
                    self.trusted._deliver(recovered_session_id)
            self._trusted_admin_token = os.environ.get(tc.admin_token_env, "")
            if cfg.kubernetes.enabled or kubernetes_service is not None:
                self.kubernetes = kubernetes_service or KubernetesService(
                    cfg.kubernetes, tc.runner_instance_id
                )
            ic = cfg.trusted_inspection
            if ic.enabled:
                if trusted_orchestrator is None:
                    raise ValueError("trusted inspection requires trusted session orchestration")
                self.inspection = InspectionManager(
                    ic,
                    inventory=ManagedInventory(tc.inventory_dir),
                    orchestrator=trusted_orchestrator,
                    sender=sender or UrllibSender(),
                    token_env=tc.token_env,
                    proposal_ready=self.trusted._deliver,
                    context_provider=context_for_target,
                    kubernetes=self.kubernetes,
                    callback_failure=self.monitor.note_callback_failure,
                )
                self.inspection.start_callback_retries()
        if self.kubernetes is None and (cfg.kubernetes.enabled or kubernetes_service is not None):
            self.kubernetes = kubernetes_service or KubernetesService(
                cfg.kubernetes, self.runner_instance_id
            )

    def close(self) -> None:
        if self.inspection is not None:
            self.inspection.stop_callback_retries()
        if self.kubernetes is not None and hasattr(self.kubernetes, "close"):
            self.kubernetes.close()
        if self._trusted_instance_lock is not None:
            self._trusted_instance_lock.close()
            self._trusted_instance_lock = None

    def trusted_request(self, *, client_ip: str, headers: dict, method: str,
                        path: str, body: bytes = b""):
        """Authenticate and route the private AIOps→runner trusted control API."""
        auth = self.authenticator.authenticate(client_ip=client_ip, headers=headers, body=body)
        if not auth.ok:
            return 401, {
                "error_code": "TRUSTED_REPAIR_AUTHENTICATION_REQUIRED",
                "message": "runner control authentication failed",
                "retriable": False,
                "details": {},
            }
        if self.trusted is None:
            return 503, {
                "error_code": "TRUSTED_REPAIR_FEATURE_DISABLED",
                "message": "trusted session is disabled",
                "retriable": True,
                "details": {},
            }
        prefix = "/trusted-repair-sessions"
        suffix = path[len(prefix):] if path.startswith(prefix) else ""
        parts = [part for part in suffix.split("/") if part]
        if method == "POST" and not parts:
            return self.trusted.create(body)
        if parts and parts[0] == "kill-switch":
            presented_admin = next(
                (value for key, value in headers.items() if key.lower() == "x-trusted-admin-key"), ""
            )
            if not getattr(self, "_trusted_admin_token", "") or not hmac.compare_digest(
                presented_admin, self._trusted_admin_token
            ):
                return 403, {
                    "error_code": "TRUSTED_REPAIR_AUTHORIZATION_DENIED",
                    "message": "trusted administrator credential required",
                    "retriable": False,
                    "details": {},
                }
            if method == "GET" and parts == ["kill-switch"]:
                return self.trusted.kill_switch_status()
            if method == "POST" and parts == ["kill-switch", "activate"]:
                return self.trusted.activate_kill_switch(body)
            if method == "POST" and parts == ["kill-switch", "deactivate"]:
                return self.trusted.deactivate_kill_switch(body)
            return 404, {"error_code": "not_found"}
        if not parts:
            return 404, {"error_code": "not_found"}
        session_id = parts[0]
        if method == "GET" and len(parts) == 1:
            return self.trusted.get(session_id)
        if method == "POST" and parts[1:] == ["resume"]:
            return self.trusted.approve(session_id, body)
        if method == "POST" and parts[1:] == ["stop"]:
            return self.trusted.cancel(session_id, body)
        if method == "POST" and len(parts) == 4 and parts[1] == "risk-confirmations" \
                and parts[3] in {"grant", "reject"}:
            return self.trusted.risk_decision(
                session_id, parts[2], body, grant=parts[3] == "grant"
            )
        return 404, {"error_code": "not_found"}

    def inspection_request(self, *, client_ip: str, headers: dict, method: str,
                           path: str, body: bytes = b""):
        auth = self.authenticator.authenticate(
            client_ip=client_ip, headers=headers, body=body
        )
        if not auth.ok:
            return 401, {"error_code": "TRUSTED_INSPECTION_AUTHENTICATION_REQUIRED"}
        if self.inspection is None:
            return 503, {"error_code": "TRUSTED_INSPECTION_DISABLED"}
        prefix = "/trusted-inspection"
        parts = [part for part in path[len(prefix):].split("/") if part]
        if method == "GET" and parts == ["targets"]:
            return self.inspection.targets()
        if method == "POST" and parts == ["batches"]:
            return self.inspection.create(body)
        if len(parts) >= 2 and parts[0] == "batches":
            batch_id = parts[1]
            if method == "GET" and len(parts) == 2:
                return self.inspection.get(batch_id)
            if method == "POST" and parts[2:] == ["cancel"]:
                return self.inspection.cancel(batch_id)
        if (
            method == "POST"
            and len(parts) == 3
            and parts[0] == "sessions"
            and parts[2] == "generate-proposal"
        ):
            return self.inspection.generate_proposal(parts[1])
        return 404, {"error_code": "not_found"}

    def kubernetes_request(self, *, client_ip: str, headers: dict, method: str,
                           path: str, body: bytes = b""):
        auth = self.authenticator.authenticate(
            client_ip=client_ip, headers=headers, body=body
        )
        if not auth.ok:
            return 401, {"error_code": "KUBERNETES_AUTHENTICATION_REQUIRED"}
        if self.kubernetes is None:
            return 503, {"error_code": "KUBERNETES_FEATURE_DISABLED"}
        return self.kubernetes.handle(method, path, body)

    def identity_request(self, *, client_ip: str, headers: dict):
        """Return the non-secret installation identity to an authenticated control plane."""
        auth = self.authenticator.authenticate(client_ip=client_ip, headers=headers, body=b"")
        if not auth.ok:
            return 401, {"error_code": "RUNNER_IDENTITY_AUTHENTICATION_REQUIRED"}
        if not self.runner_instance_id:
            return 503, {"error_code": "RUNNER_IDENTITY_UNAVAILABLE"}
        try:
            if self._identity_guard is not None:
                self._identity_guard.verify()
        except InstanceIdentityError:
            return 503, {"error_code": "RUNNER_IDENTITY_INVALID"}
        capabilities = []
        if self.trusted is not None:
            capabilities.append("trusted_session")
        if self.inspection is not None:
            capabilities.append("trusted_inspection")
        if self.kubernetes is not None:
            capabilities.append("kubernetes")
        return 200, {
            "schema_version": "1.0",
            "runner_instance_id": self.runner_instance_id,
            "capabilities": capabilities,
        }

    def health(self) -> dict:
        snap = self.monitor.health.snapshot()
        snap["deadletter_pending"] = len(self.deadletter.list_ids())
        snap["pages"] = len(self.monitor.pages)
        if self.inspection is not None:
            snap.update(self.inspection.health())
        else:
            snap.update({
                "inspection_active_batch_id": None,
                "inspection_active": 0,
                "inspection_queued": 0,
                "inspection_requested_concurrency": 0,
                "inspection_effective_concurrency": 0,
            })
        return snap

    def deadletters(self) -> dict:
        return {"deadletter": self.deadletter.list_ids()}


def make_handler(runner: Runner):
    class AlertHandler(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict):
            payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, runner.health())
            elif self.path == "/control-plane/identity":
                client_ip = self.client_address[0] if self.client_address else ""
                code, obj = runner.identity_request(
                    client_ip=client_ip, headers=dict(self.headers.items())
                )
                self._send(code, obj)
            elif self.path == "/deadletter":
                self._send(200, runner.deadletters())
            elif self.path.startswith("/trusted-repair-sessions"):
                client_ip = self.client_address[0] if self.client_address else ""
                code, obj = runner.trusted_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="GET", path=self.path,
                )
                self._send(code, obj)
            elif self.path.startswith("/trusted-inspection"):
                client_ip = self.client_address[0] if self.client_address else ""
                code, obj = runner.inspection_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="GET", path=self.path,
                )
                self._send(code, obj)
            elif self.path.startswith("/kubernetes"):
                client_ip = self.client_address[0] if self.client_address else ""
                code, obj = runner.kubernetes_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="GET", path=self.path,
                )
                self._send(code, obj)
            else:
                self._send(404, {"error": {"code": "not_found", "message": self.path}})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            client_ip = self.client_address[0] if self.client_address else ""
            if self.path.startswith("/trusted-repair-sessions"):
                code, obj = runner.trusted_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="POST", path=self.path, body=body,
                )
                self._send(code, obj)
            elif self.path.startswith("/trusted-inspection"):
                code, obj = runner.inspection_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="POST", path=self.path, body=body,
                )
                self._send(code, obj)
            elif self.path.startswith("/kubernetes"):
                code, obj = runner.kubernetes_request(
                    client_ip=client_ip, headers=dict(self.headers.items()),
                    method="POST", path=self.path, body=body,
                )
                self._send(code, obj)
            else:
                self._send(404, {"error": {"code": "not_found", "message": self.path}})

        def log_message(self, fmt, *args):  # 静默默认访问日志；安全事件走专用审计通道。
            pass

    return AlertHandler


def main(argv: list[str] | None = None) -> int:
    cfg = load_config()
    runner = Runner(cfg)
    if not runner.authenticator.configured:
        # 裸奔保护：没有任何凭据就不开 webhook。
        print("ERROR: runner auth not configured (set shared token or HMAC secret env).")
        return 2
    server = ThreadingHTTPServer((cfg.webhook.host, cfg.webhook.port), make_handler(runner))
    print(f"aiops-runner listening on {cfg.webhook.host}:{cfg.webhook.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        runner.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
