"""审计安全测试：append-only，Token 不入正文，只记录 token_id。"""

import json

from runner.audit import Auditor


def test_append_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = Auditor(str(path), clock=lambda: 0.0)
    a.record("dispatched", run_id="r1", alert_id="a1", outcome="completed")
    a.record("callback_ok", run_id="r1", alert_id="a1", token_id="abc12345")
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "dispatched"


def test_token_scrubbed_from_detail(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = Auditor(str(path), clock=lambda: 0.0)
    a.record("callback_failed", run_id="r1",
             detail="Authorization: Bearer super-secret-abc and token=leakme123")
    body = path.read_text()
    assert "super-secret-abc" not in body
    assert "leakme123" not in body
    assert "redacted" in body


def test_token_id_recorded_not_token(tmp_path):
    a = Auditor(clock=lambda: 0.0)
    ev = a.record("callback_ok", run_id="r1", token_id="deadbeef")
    assert ev.token_id == "deadbeef"
    # 整条审计 JSON 里不应出现 'Bearer <token>' 形态
    assert "Bearer" not in json.dumps(ev.__dict__)


def test_emit_sink_called():
    seen = []
    a = Auditor(emit=seen.append, clock=lambda: 0.0)
    a.record("dispatched", run_id="r1")
    assert len(seen) == 1
    assert "dispatched" in seen[0]
