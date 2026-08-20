"""Trusted-repair view of the runner-local asset inventory.

AIOps never receives this inventory. It is deliberately limited to proving that
a logical target resolves to exactly one managed host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import ipaddress
import os
import re

import yaml

from .trusted_session import TrustedSessionError


class ManagedInventory:
    def __init__(self, inventory_dir: str):
        self.inventory_dir = Path(inventory_dir)

    def _load_hosts(self) -> list[dict[str, Any]]:
        base_path = self.inventory_dir / "inventory.yaml"
        local_path = self.inventory_dir / "inventory.local.yaml"
        try:
            base = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise TrustedSessionError(
                "TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory is unavailable"
            ) from exc
        if not isinstance(base, dict):
            raise TrustedSessionError("TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory is invalid")
        value = base
        if local_path.exists():
            try:
                local = yaml.safe_load(local_path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise TrustedSessionError(
                    "TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory overlay is unavailable"
                ) from exc
            if not isinstance(local, dict) or set(local) - {"hosts"}:
                raise TrustedSessionError("TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory overlay is invalid")
            if "hosts" in local:
                value = {**base, "hosts": local["hosts"]}
        hosts = value.get("hosts")
        if not isinstance(hosts, list):
            raise TrustedSessionError("TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory has no host list")
        seen: set[str] = set()
        for host in hosts:
            if not isinstance(host, dict):
                raise TrustedSessionError("TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory contains an invalid host")
            host_id, address, targets = host.get("id"), host.get("addr"), host.get("logical_target_ids", [])
            if (
                not isinstance(host_id, str) or not host_id or host_id in seen
                or not isinstance(address, str) or not address
                or not isinstance(targets, list)
                or any(not isinstance(item, str) or not item for item in targets)
            ):
                raise TrustedSessionError("TRUSTED_INVENTORY_UNAVAILABLE", "runner managed inventory is invalid")
            seen.add(host_id)
        return hosts

    def validate(self) -> None:
        self._load_hosts()

    def require_unique_target(self, logical_target_id: str) -> None:
        self.resolve_unique_target(logical_target_id)

    def public_targets(self) -> list[dict[str, str]]:
        """Return the minimal target catalogue exposed to AIOps.

        A literal IP is useful for identifying a host in the operator UI.  It
        is deliberately optional: hostnames are not resolved and no SSH
        connection material (user, port, or paths) crosses the boundary.
        """
        rows: list[dict[str, str]] = []
        for host in self._load_hosts():
            try:
                ip_address = str(ipaddress.ip_address(str(host["addr"])))
            except ValueError:
                ip_address = ""
            for logical_target_id in host.get("logical_target_ids", []):
                row = {
                    "logical_target_id": logical_target_id,
                    "display_name": str(host["id"]),
                    "environment": str(host.get("env") or ""),
                }
                if ip_address:
                    row["ip_address"] = ip_address
                rows.append(row)
        return sorted(rows, key=lambda item: item["logical_target_id"])

    def resolve_unique_target(self, logical_target_id: str) -> dict[str, Any]:
        matches = [
            host for host in self._load_hosts()
            if logical_target_id in host.get("logical_target_ids", [])
        ]
        if not matches:
            raise TrustedSessionError(
                "TRUSTED_TARGET_NOT_MANAGED", "logical target is not in the runner managed inventory"
            )
        if len(matches) != 1:
            raise TrustedSessionError(
                "TRUSTED_TARGET_NOT_UNIQUELY_RESOLVED",
                "logical target resolves to more than one managed host"
            )
        return dict(matches[0])

    def ssh_profile(self, logical_target_id: str) -> dict[str, str | int]:
        """Return the local-only SSH profile for a uniquely resolved asset.

        This is deliberately never sent to AIOps or written into model events.
        Connection material is runner-local and is never sent to AIOps.
        """
        host = self.resolve_unique_target(logical_target_id)
        config = self._load_connection_config()
        user = str(host.get("ssh_user") or config.get("ssh_user") or "").strip()
        address = str(host["addr"]).strip()
        port = host.get("ssh_port", 22)
        key = str(config.get("ssh_key_path") or "").strip()
        known_hosts = str(config.get("known_hosts_path") or "").strip()
        timeout = config.get("command_timeout_sec", 30)
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", address)
                or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                or not key or not known_hosts or not os.path.isfile(key) or not os.path.isfile(known_hosts)
                or isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1):
            raise TrustedSessionError("TRUSTED_TARGET_CONNECTION_UNAVAILABLE", "target SSH connection is unavailable")
        return {"user": user, "address": address, "port": port, "key_path": key,
                "known_hosts_path": known_hosts, "command_timeout_sec": timeout}

    def _load_connection_config(self) -> dict[str, Any]:
        def load(name: str) -> dict[str, Any]:
            path = self.inventory_dir / name
            if not path.exists():
                return {}
            try:
                value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise TrustedSessionError("TRUSTED_TARGET_CONNECTION_UNAVAILABLE", "target SSH configuration is unreadable") from exc
            if not isinstance(value, dict):
                raise TrustedSessionError("TRUSTED_TARGET_CONNECTION_UNAVAILABLE", "target SSH configuration is invalid")
            return value
        base, local = load("connection.yaml"), load("connection.local.yaml")
        allowed = {"ssh_user", "ssh_key_path", "known_hosts_path", "strict_host_key_checking", "connect_timeout_sec", "command_timeout_sec"}
        if set(base) - allowed or set(local) - {"ssh_user", "ssh_key_path", "known_hosts_path", "strict_host_key_checking"}:
            raise TrustedSessionError("TRUSTED_TARGET_CONNECTION_UNAVAILABLE", "target SSH configuration is invalid")
        merged = {**base, **local}
        for field in ("ssh_key_path", "known_hosts_path"):
            value = merged.get(field)
            if value and not os.path.isabs(str(value)):
                merged[field] = str((self.inventory_dir / str(value)).resolve())
        return merged

    def summary(self) -> dict[str, int]:
        hosts = self._load_hosts()
        targets = {target for host in hosts for target in host.get("logical_target_ids", [])}
        return {"managed_host_count": len(hosts), "logical_target_count": len(targets)}
