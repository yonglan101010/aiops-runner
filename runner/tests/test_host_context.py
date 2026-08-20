from __future__ import annotations

import subprocess

from runner.host_context import MARKER, HostContextStore, host_fingerprint, render, write_remote


def test_render_marks_context_as_managed_and_is_readable():
    value = render("web-1", {"summary": "反向代理", "services": [{"name": "nginx", "kind": "systemd", "state": "active", "evidence": "unit active"}], "runtime_notes": ["未检查健康状态"]})
    assert value.startswith(MARKER)
    assert "nginx" in value


def test_context_requires_current_index_and_managed_marker(tmp_path, monkeypatch):
    store = HostContextStore(str(tmp_path))
    profile = {"user": "ops", "address": "host", "port": 22, "key_path": "key", "known_hosts_path": "known"}
    fingerprint = host_fingerprint({"id": "web-1", "addr": "host", "logical_target_ids": ["web"]}, profile)
    store.mark("web-1", fingerprint, status="initialized")
    monkeypatch.setattr("runner.host_context._ssh", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, MARKER + "\n# context\n", ""))
    assert "<untrusted-host-context>" in store.prompt_context("web-1", fingerprint, profile)
    assert not store.prompt_context("web-1", "sha256:different", profile)


def test_unmanaged_remote_file_is_not_overwritten(monkeypatch):
    calls = []
    def fake_ssh(_profile, command, **kwargs):
        calls.append((command, kwargs)); raise subprocess.CalledProcessError(73, "ssh")
    monkeypatch.setattr("runner.host_context._ssh", fake_ssh)
    try:
        write_remote({"user": "ops"}, "data")
    except subprocess.CalledProcessError:
        pass
    assert len(calls) == 1
