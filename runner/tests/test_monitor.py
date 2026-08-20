"""自监控测试：健康计数、死信、回调失败与 Runner 不可用。"""

from runner.monitor import SelfMonitor

from .conftest import FakeClock


def _mon(**kw):
    pages = []
    clk = FakeClock()
    m = SelfMonitor(page_sink=pages.append, clock=clk, **kw)
    return m, pages, clk


def test_outcome_counters():
    m, _, _ = _mon()
    m.note_alert()
    m.note_outcome("completed")
    m.note_outcome("needs_human")
    snap = m.health.snapshot()
    assert snap["alerts_received"] == 1
    assert snap["completed"] == 1
    assert snap["needs_human"] == 1


def test_deadletter_threshold_pages():
    m, pages, _ = _mon(deadletter_page_threshold=3)
    for _ in range(2):
        m.note_deadletter()
    assert not pages
    m.note_deadletter()  # 第 3 个触发 page
    assert len(pages) == 1
    assert pages[0].reason == "deadletter_threshold"


def test_callback_failure_threshold_pages():
    m, pages, _ = _mon(callback_failure_page_threshold=2)
    m.note_callback_failure()
    assert not pages
    m.note_callback_failure()
    assert pages and pages[0].reason == "callback_failures"


def test_runner_down_via_liveness():
    m, pages, clk = _mon(liveness_max_silence_sec=120)
    m.heartbeat()
    assert m.check_liveness()  # 刚心跳，存活
    clk.advance(121)
    assert not m.check_liveness()  # 超过静默上限 → runner_down page
    assert pages[-1].reason == "runner_down"


def test_explicit_mark_runner_down_pages():
    m, pages, _ = _mon()
    m.mark_runner_down("watchdog detected crash")
    assert pages[-1].reason == "runner_down"
    assert "watchdog" in pages[-1].detail
