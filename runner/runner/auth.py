"""Runner 鉴权：内网监听 + shared token 或 HMAC，并支持 IP 白名单。

红线：token / 密钥绝不入日志、审计正文、prompt。审计只记 token_id（sha256 前 8 字符）。
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from dataclasses import dataclass


@dataclass
class AuthResult:
    ok: bool
    reason: str = ""
    token_id: str = ""  # sha256(token)[:8]，可入审计；绝不记原 token


def token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8] if token else ""


def ip_allowed(client_ip: str, allowlist: tuple[str, ...]) -> bool:
    if not allowlist:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in allowlist:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def verify_hmac(secret: str, body: bytes, signature: str) -> bool:
    """signature 形如 'sha256=<hex>'。常量时间比较。"""
    if not signature:
        return False
    algo, _, sig = signature.partition("=")
    if algo != "sha256" or not sig:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


class Authenticator:
    """从 env 读 token / hmac secret（按 config 的变量名）；请求级校验。"""

    def __init__(
        self,
        *,
        shared_token_env: str,
        hmac_secret_env: str | None,
        ip_allowlist: tuple[str, ...],
        env: dict | None = None,
    ):
        env = env if env is not None else os.environ
        self._token = env.get(shared_token_env) or ""
        self._hmac_secret = env.get(hmac_secret_env) if hmac_secret_env else None
        self.ip_allowlist = ip_allowlist
        # 至少要有一种凭据，否则 runner 是裸奔的——拒绝启动语义由调用方决定。
        self.configured = bool(self._token or self._hmac_secret)

    def authenticate(
        self,
        *,
        client_ip: str,
        headers: dict,
        body: bytes,
    ) -> AuthResult:
        if not ip_allowed(client_ip, self.ip_allowlist):
            return AuthResult(False, reason="ip_not_allowed")

        # header 名大小写不敏感
        h = {k.lower(): v for k, v in headers.items()}

        if self._hmac_secret:
            sig = h.get("x-signature", "")
            if not verify_hmac(self._hmac_secret, body, sig):
                return AuthResult(False, reason="bad_hmac")
            return AuthResult(True, token_id="hmac")

        if self._token:
            presented = _extract_token(h)
            if not presented or not hmac.compare_digest(presented, self._token):
                return AuthResult(False, reason="bad_token", token_id=token_id(presented))
            return AuthResult(True, token_id=token_id(presented))

        return AuthResult(False, reason="runner_auth_not_configured")


def _extract_token(headers_lower: dict) -> str:
    auth = headers_lower.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return headers_lower.get("x-ops-token", "").strip()
