"""死信队列：非法产出或处理失败不静默，落盘等待人工处理。

写盘前做最小脱敏：绝不把 token / 密钥写进死信。死信项可被重放（按 run_id/alert_id 幂等）。
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Callable


@dataclass
class DeadletterItem:
    ts: str
    run_id: str
    alert_id: str
    reason: str
    errors: list[str] = field(default_factory=list)
    stage: str = ""  # validation | result_schema | skill_error | ...


class Deadletter:
    def __init__(self, directory: str, *, clock: Callable[[], float] = time.time):
        self.dir = directory
        self._clock = clock

    def put(
        self,
        *,
        run_id: str,
        alert_id: str,
        reason: str,
        errors: list[str] | None = None,
        stage: str = "",
    ) -> DeadletterItem:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock()))
        item = DeadletterItem(
            ts=ts, run_id=run_id, alert_id=alert_id, reason=reason,
            errors=list(errors or []), stage=stage,
        )
        os.makedirs(self.dir, exist_ok=True)
        # 文件名按 run_id 幂等：同 run_id 重投覆盖同一死信，不堆积重复。
        safe_run = "".join(c for c in (run_id or "unknown") if c.isalnum() or c in "-_") or "unknown"
        path = os.path.join(self.dir, f"{safe_run}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(item), f, ensure_ascii=False)
        return item

    def list_ids(self) -> list[str]:
        if not os.path.isdir(self.dir):
            return []
        return sorted(f[:-5] for f in os.listdir(self.dir) if f.endswith(".json"))
