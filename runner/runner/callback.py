"""Minimal HTTP transport shared by trusted-session callbacks."""

from __future__ import annotations

import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SendResult:
    ok: bool
    status_code: int = 0
    attempts: int = 0
    error: str = ""
    deadlettered: bool = False


class Sender(ABC):
    @abstractmethod
    def post(self, url: str, body: bytes, headers: dict, *, timeout: int) -> tuple[int, str]:
        """Return ``(status_code, error)``; a non-empty error is a transport failure."""


class UrllibSender(Sender):
    def post(self, url: str, body: bytes, headers: dict, *, timeout: int) -> tuple[int, str]:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, ""
        except urllib.error.HTTPError as exc:
            return exc.code, f"http_{exc.code}"
        except urllib.error.URLError as exc:
            return 0, f"urlerror:{exc.reason}"
        except OSError as exc:
            return 0, f"oserror:{exc}"
