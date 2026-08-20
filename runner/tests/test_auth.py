"""鉴权安全测试：shared token、HMAC、IP 白名单与 Token 脱敏。"""

import hashlib
import hmac as hmaclib

from runner.auth import Authenticator, ip_allowed, token_id, verify_hmac


def _auth(token=None, hmac_secret=None, ip_allowlist=("10.0.0.0/24",)):
    env = {}
    if token:
        env["RUNNER_SHARED_TOKEN"] = token
    if hmac_secret:
        env["RUNNER_HMAC"] = hmac_secret
    return Authenticator(
        shared_token_env="RUNNER_SHARED_TOKEN",
        hmac_secret_env="RUNNER_HMAC" if hmac_secret else None,
        ip_allowlist=ip_allowlist,
        env=env,
    )


def test_ip_allowlist():
    assert ip_allowed("10.0.0.5", ("10.0.0.0/24",))
    assert not ip_allowed("192.168.1.1", ("10.0.0.0/24",))
    assert not ip_allowed("garbage", ("10.0.0.0/24",))


def test_shared_token_ok():
    a = _auth(token="s3cr3t-token")
    r = a.authenticate(client_ip="10.0.0.5", headers={"Authorization": "Bearer s3cr3t-token"}, body=b"{}")
    assert r.ok
    assert r.token_id == token_id("s3cr3t-token")


def test_wrong_token_rejected():
    a = _auth(token="s3cr3t-token")
    r = a.authenticate(client_ip="10.0.0.5", headers={"Authorization": "Bearer wrong"}, body=b"{}")
    assert not r.ok
    assert r.reason == "bad_token"


def test_missing_token_rejected():
    a = _auth(token="s3cr3t-token")
    r = a.authenticate(client_ip="10.0.0.5", headers={}, body=b"{}")
    assert not r.ok


def test_ip_blocked_even_with_token():
    a = _auth(token="s3cr3t-token")
    r = a.authenticate(client_ip="192.168.1.1", headers={"Authorization": "Bearer s3cr3t-token"}, body=b"{}")
    assert not r.ok
    assert r.reason == "ip_not_allowed"


def test_hmac_ok():
    secret = "hmac-secret"
    body = b'{"alert_id":"x"}'
    sig = "sha256=" + hmaclib.new(secret.encode(), body, hashlib.sha256).hexdigest()
    a = _auth(hmac_secret=secret)
    r = a.authenticate(client_ip="10.0.0.5", headers={"X-Signature": sig}, body=body)
    assert r.ok


def test_hmac_bad_signature_rejected():
    a = _auth(hmac_secret="hmac-secret")
    r = a.authenticate(client_ip="10.0.0.5", headers={"X-Signature": "sha256=deadbeef"}, body=b"{}")
    assert not r.ok
    assert r.reason == "bad_hmac"


def test_unconfigured_runner_rejects_all():
    a = _auth()  # 无 token 无 hmac
    assert not a.configured
    r = a.authenticate(client_ip="10.0.0.5", headers={}, body=b"{}")
    assert not r.ok


def test_token_id_is_not_token():
    tid = token_id("my-secret-token")
    assert tid != "my-secret-token"
    assert len(tid) == 8
