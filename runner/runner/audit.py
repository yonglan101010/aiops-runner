"""Runner 审计：append-only，并可发送到外部审计通道。

记诊断派发与回调事件：who(runner)/when/run_id/alert_id/outcome/token_id/stage。
红线：token / 凭据绝不入审计正文；只记 token_id（sha256 前 8）。
特权用户能删除本机日志，因此同时支持 append-only 文件与外部审计通道。
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

# 兜底：万一 detail 里混入 bearer/token，写盘前遮掉（审计正文绝不留 token）。
_TOKEN_GUARD = re.compile(r"(?i)(bearer\s+)\S+|((?:api[_-]?key|token|secret|password)\s*[=:]\s*)\S+")


def _scrub(text: str) -> str:
    return _TOKEN_GUARD.sub(lambda m: (m.group(1) or m.group(2) or "") + "«redacted»", text or "")


@dataclass
class AuditEvent:
    ts: str
    actor: str
    event: str          # alert_received | dispatched | callback_ok | callback_failed | deadletter | ...
    run_id: str = ""
    alert_id: str = ""
    outcome: str = ""
    token_id: str = ""  # sha256 前 8；绝不记原 token
    stage: str = ""
    detail: str = ""


class Auditor:
    def __init__(
        self,
        path: str | None = None,
        *,
        actor: str = "aiops-runner",
        emit: Callable[[str], None] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.path = path
        self.actor = actor
        self._emit = emit
        self._clock = clock
        self.events: list[AuditEvent] = []  # 内存镜像，便于自监控/测试断言

    def record(self, event: str, **fields) -> AuditEvent:
        fields.pop("actor", None)
        detail = _scrub(str(fields.pop("detail", "")))[:1000]
        ev = AuditEvent(
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock())),
            actor=self.actor,
            event=event,
            detail=detail,
            **{k: fields.get(k, "") for k in ("run_id", "alert_id", "outcome", "token_id", "stage")},
        )
        self.events.append(ev)
        line = json.dumps(asdict(ev), ensure_ascii=False)
        if self.path:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        if self._emit:
            self._emit(line)
        return ev
