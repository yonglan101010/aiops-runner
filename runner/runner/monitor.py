"""自监控：聚合健康状态，并报告死信、回调失败与 Runner 不可用。

"runner down 必 page"：runner 真挂了无法自报，由外部 watchdog 探 /healthz；
本模块提供 check_liveness（watchdog 调用）与显式 mark_runner_down，并把 page 事件
落到可注入 page_sink，测试可断言。死信堆积 / 回调连续失败超阈值同样 page。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class HealthState:
    alerts_received: int = 0
    completed: int = 0
    needs_human: int = 0
    failed: int = 0
    rejected: int = 0
    duplicate: int = 0
    rate_limited: int = 0
    budget_exhausted: int = 0
    callback_failures: int = 0
    deadletter_count: int = 0
    last_alert_ts: float = 0.0
    last_heartbeat: float = 0.0

    def snapshot(self) -> dict:
        return {
            "status": "ok",
            "alerts_received": self.alerts_received,
            "completed": self.completed,
            "needs_human": self.needs_human,
            "failed": self.failed,
            "rejected": self.rejected,
            "duplicate": self.duplicate,
            "rate_limited": self.rate_limited,
            "budget_exhausted": self.budget_exhausted,
            "callback_failures": self.callback_failures,
            "deadletter_count": self.deadletter_count,
            "last_alert_ts": self.last_alert_ts,
            "last_heartbeat": self.last_heartbeat,
        }


@dataclass
class PageEvent:
    reason: str
    detail: str = ""
    ts: float = 0.0


class SelfMonitor:
    def __init__(
        self,
        *,
        page_sink: Callable[[PageEvent], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
        deadletter_page_threshold: int = 5,
        callback_failure_page_threshold: int = 3,
        liveness_max_silence_sec: int = 120,
    ):
        self.health = HealthState()
        self._page_sink = page_sink
        self._clock = clock
        self.deadletter_page_threshold = deadletter_page_threshold
        self.callback_failure_page_threshold = callback_failure_page_threshold
        self.liveness_max_silence_sec = liveness_max_silence_sec
        self.pages: list[PageEvent] = []
        self.health.last_heartbeat = clock()

    # ── 事件计数 ────────────────────────────────────────────────────
    def note_alert(self) -> None:
        self.health.alerts_received += 1
        self.health.last_alert_ts = self._clock()

    def note_outcome(self, outcome: str) -> None:
        if hasattr(self.health, outcome):
            setattr(self.health, outcome, getattr(self.health, outcome) + 1)

    def note_deadletter(self) -> None:
        self.health.deadletter_count += 1
        if self.health.deadletter_count >= self.deadletter_page_threshold:
            self._page("deadletter_threshold", f"deadletter_count={self.health.deadletter_count}")

    def note_callback_failure(self) -> None:
        self.health.callback_failures += 1
        if self.health.callback_failures >= self.callback_failure_page_threshold:
            self._page("callback_failures", f"callback_failures={self.health.callback_failures}")

    # ── liveness ────────────────────────────────────────────────────
    def heartbeat(self) -> None:
        self.health.last_heartbeat = self._clock()

    def check_liveness(self) -> bool:
        """watchdog 调用。心跳过期 → page 并返回 False。"""
        silent = self._clock() - self.health.last_heartbeat
        if silent > self.liveness_max_silence_sec:
            self._page("runner_down", f"no heartbeat for {silent:.0f}s")
            return False
        return True

    def mark_runner_down(self, reason: str = "explicit") -> None:
        self._page("runner_down", reason)

    def _page(self, reason: str, detail: str = "") -> None:
        ev = PageEvent(reason=reason, detail=detail, ts=self._clock())
        self.pages.append(ev)
        if self._page_sink:
            self._page_sink(ev)
