#!/usr/bin/env python3
"""Runner 分文件配置向导：全程暂存，最终确认后才替换本地文件。"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import socket
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# 在脚本模式下，Python 不一定会自动加载 readline。
# 显式导入后，input() 才支持左右方向键、Home/End、Delete 等行编辑能力。
if os.name != "nt":
    try:
        import readline  # noqa: F401

        readline.parse_and_bind("set editing-mode emacs")
    except ImportError:
        readline = None
else:
    readline = None

try:
    import yaml
except ImportError as exc:  # 向导本身不安装依赖。
    raise SystemExit("缺少 PyYAML。请先运行 scripts/install.sh。") from exc

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HOST_ADDR = re.compile(r"^[A-Za-z0-9._:-]+$")
SSH_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
SSH_PORT = re.compile(r"^\d{1,5}$")
TRUSTED_REPAIR_CALLBACK_PATH = "/aiops/repair-sessions/callbacks/events"
TRUSTED_INSPECTION_CALLBACK_PATH = "/aiops/inspection-batches/callbacks/events"
KUBERNETES_INVENTORY_PATH = CONFIG / "kubernetes.local.yaml"
KUBERNETES_KEYS_DIR = CONFIG / "keys"
KUBERNETES_MAX_KUBECONFIG_BYTES = 2 * 1024 * 1024
KUBERNETES_CLUSTER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
KUBERNETES_NAMESPACE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$"
)
VOLCENGINE_ENV_NAMES = (
    "VOLCENGINE_ACCESS_KEY_ID",
    "VOLCENGINE_ACCESS_KEY_SECRET",
)
KUBERNETES_PARAMETER_FIELDS = (
    "current_metrics_cache_sec",
    "sync_timeout_sec",
    "continuous_collection_enabled",
    "collection_interval_sec",
    "collection_memory_limit_mb",
    "log_collection_concurrency",
    "log_all_namespaces",
    "log_request_timeout_sec",
    "reconcile_interval_sec",
)


class Cancelled(Exception):
    pass


class SSHVerificationError(ValueError):
    """可判定处理方式的 SSH 公钥验证错误。"""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class TrustedEnvSetup:
    """Secrets prepared by the simplified trusted-session setup.

    Values exist only in the wizard transaction and are written by
    ``configure_env``.  They must never be added to runner.yaml or printed.
    """

    values: dict[str, str]


@dataclass(frozen=True)
class KubernetesEnvSetup:
    """Volcengine credentials staged only for the Runner-local env file."""

    values: dict[str, str]



@dataclass
class PendingSSHCredential:
    host_id: str
    addr: str
    user: str
    port: int
    password: str
    os_type: str
    scanned_host_keys: bytes


@dataclass
class RemoteKeyChange:
    host_id: str
    addr: str
    user: str
    port: int
    password: str
    os_type: str
    public_key: str
    remote_path: str
    file_existed: bool
    dir_existed: bool
    original_acl_sddl: str = ""
    original_file_data: bytes = b""
    key_added: bool = True
    acl_changed: bool = False
    permissions_changed: bool = False
    original_file_mode: str = ""
    original_dir_mode: str = ""
    original_had_final_newline: bool = True
    installed_file_sha256: str = ""
    installed_file_mode: str = ""
    installed_dir_mode: str = ""
    installed_acl_sddl: str = ""
    scanned_host_keys: bytes = b""


class WizardState:
    """仅在当前向导进程内保存密码和远程回滚信息。"""

    def __init__(self) -> None:
        self.credentials: dict[str, PendingSSHCredential] = {}
        self.pending_setups: list[str] = []
        self.remote_changes: list[RemoteKeyChange] = []
        self.key_source: Path | None = None
        self.key_source_sha256 = ""
        self.key_target: Path | None = None
        self.known_hosts_data: bytes = b""
        self.public_key: str = ""
        self.ssh_inventory_changed = False
        self.remote_operation_inflight = False
        self.old_remote_key_requires_manual_removal = False
        self.initialize_host_ids: list[str] = []

    def remove_host(self, host_id: str) -> None:
        credential = self.credentials.pop(host_id, None)
        if credential is not None:
            credential.password = ""

    def clear_secrets(self) -> None:
        for credential in self.credentials.values():
            credential.password = ""
        for change in self.remote_changes:
            change.password = ""
        self.credentials.clear()
        self.pending_setups.clear()
        self.remote_changes.clear()
        self.key_source = None
        self.key_source_sha256 = ""
        self.key_target = None
        self.known_hosts_data = b""
        self.public_key = ""
        self.ssh_inventory_changed = False
        self.remote_operation_inflight = False
        self.old_remote_key_requires_manual_removal = False
        self.initialize_host_ids.clear()


class Transaction:
    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix=".configure-tmp-", dir=ROOT))
        try:
            _secure_work_directory(self.dir)
        except BaseException:
            shutil.rmtree(self.dir, ignore_errors=True)
            raise
        self.files: dict[Path, bytes] = {}
        self.modes: dict[Path, int] = {}
        self.private_keys: set[Path] = set()
        self.owner: tuple[int, int] | None = None
        if os.name == "posix":
            import pwd

            owner_uid = _trusted_identity_owner_uid()
            owner_entry = pwd.getpwuid(owner_uid)
            self.owner = (owner_uid, owner_entry.pw_gid)
        self.deletes: set[Path] = set()
        self.prepared: dict[Path, Path] = {}
        self.backups: dict[Path, Path | None] = {}
        self.original_snapshots: dict[
            Path, tuple[int, int, int, int, str] | None
        ] = {}
        self.staged_baselines: dict[
            Path, tuple[int, int, int, int, str] | None
        ] = {}
        self.observed_snapshots: dict[
            Path, tuple[int, int, int, int, str] | None
        ] = {}
        self.watched_snapshots: dict[
            Path, tuple[int, int, int, int, str] | None
        ] = {}
        self.candidate_snapshots: dict[
            Path, tuple[int, int, int, int, str]
        ] = {}
        self.created_dirs: list[tuple[Path, tuple[int, int]]] = []
        self.external_probes: list[Path] = []
        self.prepare_state = "new"
        self.preserve_recovery = False
        self.committed = False
        self.cleanup_error = ""

    def read(self, path: Path) -> bytes | None:
        if path in self.deletes:
            return None
        if path in self.files:
            return self.files[path]
        try:
            data, snapshot = self._read_snapshot(path)
        except FileNotFoundError:
            data = None
            snapshot = None
        if path in self.observed_snapshots:
            if self.observed_snapshots[path] != snapshot:
                raise OSError(
                    f"配置文件在读取期间被其它进程修改：{path}"
                )
        else:
            self.observed_snapshots[path] = snapshot
        return data

    def stage_text(self, path: Path, text: str, mode: int = 0o600) -> None:
        self.stage_bytes(path, text.encode("utf-8"), mode)

    def stage_bytes(self, path: Path, data: bytes, mode: int = 0o600) -> None:
        if self.prepare_state != "new":
            raise RuntimeError("事务候选文件已准备，不能继续修改草稿")
        self._capture_staged_baseline(path)
        baseline = self.staged_baselines[path]
        if baseline is not None and baseline[-1] == hashlib.sha256(data).hexdigest():
            self.files.pop(path, None)
            self.modes.pop(path, None)
            self.private_keys.discard(path)
            self.deletes.discard(path)
            self.staged_baselines.pop(path, None)
            return
        self.files[path] = data
        self.modes[path] = mode
        self.private_keys.discard(path)
        self.deletes.discard(path)

    def stage_private_key(self, path: Path, data: bytes) -> None:
        if self.prepare_state != "new":
            raise RuntimeError("事务候选文件已准备，不能继续修改草稿")
        self._capture_staged_baseline(path)
        # 即使字节未变化也重新落盘，以修复可能过宽的 Windows DACL。
        self.files[path] = data
        self.modes[path] = 0o600
        self.deletes.discard(path)
        self.private_keys.add(path)

    def delete(self, path: Path) -> None:
        if self.prepare_state != "new":
            raise RuntimeError("事务候选文件已准备，不能继续修改草稿")
        self.files.pop(path, None)
        self.modes.pop(path, None)
        self.private_keys.discard(path)
        self._capture_staged_baseline(path)
        if self.staged_baselines[path] is not None:
            self.deletes.add(path)
        else:
            self.staged_baselines.pop(path, None)

    def changed(self) -> bool:
        return bool(self.files or self.deletes)

    def _capture_staged_baseline(self, path: Path) -> None:
        if path in self.staged_baselines:
            return
        if path in self.observed_snapshots:
            self.staged_baselines[path] = self.observed_snapshots[path]
        else:
            self.staged_baselines[path] = (
                self._snapshot(path) if os.path.lexists(path) else None
            )

    def watch(self, path: Path) -> None:
        """记录参与验证但未暂存的文件，防止验证后配置漂移。"""
        if path in self.files or path in self.deletes:
            return
        if path not in self.watched_snapshots:
            if path in self.observed_snapshots:
                snapshot = self.observed_snapshots[path]
            else:
                snapshot = (
                    self._snapshot(path) if os.path.lexists(path) else None
                )
            self.watched_snapshots[path] = snapshot

    def _assert_unchanged(
        self,
        snapshots: dict[
            Path, tuple[int, int, int, int, str] | None
        ],
        phase: str,
    ) -> None:
        for path, expected in snapshots.items():
            current = (
                self._snapshot(path) if os.path.lexists(path) else None
            )
            if current != expected:
                raise OSError(
                    f"配置文件在{phase}被其它进程修改：{path}"
                )

    @staticmethod
    def _read_snapshot(
        path: Path,
    ) -> tuple[bytes, tuple[int, int, int, int, str]]:
        try:
            initial = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            raise
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError(f"配置目标必须是普通文件：{path}")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"配置目标必须是普通文件：{path}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        final = path.stat(follow_symlinks=False)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            stable_before != stable_after
            or not stat.S_ISREG(final.st_mode)
            or (final.st_dev, final.st_ino)
            != (after.st_dev, after.st_ino)
            or len(data) != after.st_size
        ):
            raise OSError(
                f"配置文件在读取期间被其它进程修改：{path}"
            )
        digest = hashlib.sha256(data).hexdigest()
        return data, (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            digest,
        )

    @staticmethod
    def _snapshot(path: Path) -> tuple[int, int, int, int, str]:
        return Transaction._read_snapshot(path)[1]

    def _prepare_parent(self, parent: Path) -> None:
        missing: list[Path] = []
        cursor = parent
        while not cursor.exists():
            missing.append(cursor)
            if cursor == cursor.parent:
                raise OSError(f"无法找到配置目标的现有父目录：{parent}")
            cursor = cursor.parent
        if not cursor.is_dir():
            raise OSError(f"配置目标父路径不是目录：{cursor}")
        for directory in reversed(missing):
            created = False
            try:
                directory.mkdir()
                created = True
                stat = directory.stat()
                self.created_dirs.append(
                    (directory, (stat.st_dev, stat.st_ino))
                )
            except FileExistsError:
                # 其它进程抢先创建时，它不属于本事务，绝不能在 cleanup
                # 中删除；重新核对类型后按现有目录继续。
                if not directory.is_dir():
                    raise
            except BaseException:
                # mkdir 成功后到达的异步中断仍要登记本事务创建的目录。
                if created and not any(
                    item[0] == directory for item in self.created_dirs
                ):
                    stat = directory.stat()
                    self.created_dirs.append(
                        (directory, (stat.st_dev, stat.st_ino))
                    )
                raise

        if parent.stat().st_dev != self.dir.stat().st_dev:
            raise OSError(
                f"配置目标与事务目录不在同一文件系统，无法原子提交：{parent}"
            )
        probe = parent / (
            f".configure-write-test-{secrets.token_hex(8)}"
        )
        self.external_probes.append(probe)
        with probe.open("xb"):
            pass
        probe.unlink()
        self.external_probes.remove(probe)

        # 新目标使用 hard-link no-clobber 提交；在任何远程副作用前
        # 预检跨目录硬链接能力，避免最后一步才发现文件系统不支持。
        link_token = secrets.token_hex(8)
        link_source = self.dir / f"link-test-source-{link_token}"
        link_probe = parent / f".configure-link-test-{link_token}"
        with link_source.open("xb"):
            pass
        self.external_probes.append(link_probe)
        probe_is_ours = False
        try:
            os.link(link_source, link_probe, follow_symlinks=False)
        finally:
            try:
                if os.path.lexists(link_probe):
                    source_stat = link_source.stat()
                    probe_stat = link_probe.stat(follow_symlinks=False)
                    probe_is_ours = (
                        source_stat.st_dev,
                        source_stat.st_ino,
                    ) == (
                        probe_stat.st_dev,
                        probe_stat.st_ino,
                    )
                if probe_is_ours:
                    link_probe.unlink()
            finally:
                if not os.path.lexists(link_probe) or not probe_is_ours:
                    self.external_probes.remove(link_probe)
                link_source.unlink(missing_ok=True)

    def prepare(self) -> None:
        """在真实配置不变的前提下，完整落盘并加固所有候选文件。"""
        if self.prepare_state == "ready":
            return
        if self.prepare_state != "new":
            raise RuntimeError("事务候选文件准备失败，不能继续提交")
        self.prepare_state = "preparing"
        try:
            for index, path in enumerate(sorted(self.files, key=str)):
                data = self.files[path]
                temp_path = self.dir / f"staged-{index}"
                with temp_path.open("xb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                if path in self.private_keys:
                    _secure_private_key_file(temp_path)
                    if self.owner is not None:
                        os.chown(temp_path, *self.owner)
                        _secure_private_key_file(temp_path)
                    # 用最终候选文件本身做 OpenSSH 预检，Windows DACL 问题会在
                    # 任何远程副作用之前失败。
                    _derive_public_key(temp_path)
                else:
                    if self.owner is not None:
                        os.chown(temp_path, *self.owner)
                    os.chmod(temp_path, self.modes[path])
                self.prepared[path] = temp_path
                self.candidate_snapshots[path] = self._snapshot(temp_path)

            affected = sorted(set(self.files) | self.deletes, key=str)
            self._assert_unchanged(
                {
                    path: self.staged_baselines[path]
                    for path in affected
                },
                "交互期间",
            )
            self._assert_unchanged(
                self.watched_snapshots,
                "验证后",
            )
            for index, path in enumerate(affected):
                self._prepare_parent(path.parent)
                if os.path.lexists(path):
                    snapshot = self.staged_baselines[path]
                    if snapshot is None:
                        raise OSError(
                            f"配置目标在交互期间被创建：{path}"
                        )
                    backup = self.dir / f"backup-{index}"
                    self.backups[path] = backup
                    # 先登记 backup 路径，再调用 link；若 link 成功同时中断，
                    # 整个事务目录仍会在清理阶段被移除。
                    os.link(path, backup, follow_symlinks=False)
                    if self._snapshot(backup) != snapshot:
                        raise OSError(
                            f"配置目标在创建事务备份时被其它进程修改：{path}"
                        )
                    self.original_snapshots[path] = snapshot
                else:
                    self.backups[path] = None
                    self.original_snapshots[path] = self.staged_baselines[path]
        except BaseException:
            self.prepare_state = "failed"
            for candidate in self.prepared.values():
                candidate.unlink(missing_ok=True)
            self.prepared.clear()
            raise
        self.prepare_state = "ready"

    def commit(self) -> None:
        if self.committed:
            return
        self.prepare()
        affected = sorted(set(self.files) | self.deletes, key=str)
        changed: list[Path] = []
        try:
            # 远程副作用前已经验证父目录、同卷原子替换和硬链接备份能力。
            # 提交前再做一次并发修改检测，再开始任何本地切换。
            self._assert_unchanged(
                self.watched_snapshots,
                "最终提交前",
            )
            for path in affected:
                expected = self.original_snapshots[path]
                if expected is None:
                    if os.path.lexists(path):
                        raise OSError(
                            f"配置目标在确认后被其它进程创建：{path}"
                        )
                elif not os.path.lexists(path) or self._snapshot(path) != expected:
                    raise OSError(
                        f"配置目标在确认后被其它进程修改：{path}"
                    )

            for path in affected:
                # 全量检查与本次系统调用之间仍可能有并发写；逐文件切换前
                # 再核对一次，发现冲突就回滚已经切换的前序目标。
                expected = self.original_snapshots[path]
                if expected is None:
                    if os.path.lexists(path):
                        raise OSError(
                            f"配置目标在提交期间被其它进程创建：{path}"
                        )
                elif (
                    not os.path.lexists(path)
                    or self._snapshot(path) != expected
                ):
                    raise OSError(
                        f"配置目标在提交期间被其它进程修改：{path}"
                    )
                # 先登记恢复意图，再执行任何可能已经成功但同时收到
                # KeyboardInterrupt 的系统调用。
                changed.append(path)
                if path in self.prepared:
                    if expected is None:
                        try:
                            # hard link 的目标创建具备 no-clobber 语义；
                            # 检查后出现的并发新文件不会被 replace 覆盖。
                            os.link(
                                self.prepared[path],
                                path,
                                follow_symlinks=False,
                            )
                        except FileExistsError as link_exc:
                            changed.pop()
                            raise OSError(
                                f"配置目标在提交期间被其它进程创建：{path}"
                            ) from link_exc
                        self.prepared[path].unlink()
                    else:
                        os.replace(self.prepared[path], path)
                elif os.path.lexists(path):
                    path.unlink()
                intended = (
                    self.candidate_snapshots[path]
                    if path in self.prepared
                    else None
                )
                switched = (
                    self._snapshot(path)
                    if os.path.lexists(path)
                    else None
                )
                if switched != intended:
                    raise OSError(
                        f"配置目标在提交切换后被其它进程修改：{path}"
                    )
                backup = self.backups.get(path)
                if (
                    expected is not None
                    and backup is not None
                    and self._snapshot(backup) != expected
                ):
                    raise OSError(
                        f"配置目标在提交切换期间被其它进程修改：{path}"
                    )
            # 旧 inode 仍可能被提交前已打开的句柄写入；发布 committed
            # 状态前最后复核目标状态与全部硬链接备份。
            for path in affected:
                expected = self.original_snapshots[path]
                backup = self.backups.get(path)
                intended = (
                    self.candidate_snapshots[path]
                    if path in self.prepared
                    else None
                )
                current = (
                    self._snapshot(path)
                    if os.path.lexists(path)
                    else None
                )
                if current != intended:
                    raise OSError(
                        f"配置目标在提交完成前被其它进程修改：{path}"
                    )
                if (
                    expected is not None
                    and backup is not None
                    and self._snapshot(backup) != expected
                ):
                    raise OSError(
                        f"配置目标在提交完成前被其它进程修改：{path}"
                    )
            self.committed = True
        except BaseException as exc:
            if self.committed:
                # committed 状态已经发布；此后的中断属于收尾阶段，
                # 不得把已完成的本地事务回滚成与远端不一致的状态。
                raise
            # 恢复过程中即使再次收到 Ctrl+C，也必须保留 backup，不能由
            # finally 清掉唯一恢复材料。
            self.preserve_recovery = True
            restore_errors: list[str] = []
            for path in reversed(changed):
                try:
                    backup = self.backups.get(path)
                    original = self.original_snapshots[path]
                    current = (
                        self._snapshot(path)
                        if os.path.lexists(path)
                        else None
                    )
                    if path in self.prepared:
                        candidate = self.candidate_snapshots[path]
                        if current == original:
                            continue
                        if current != candidate:
                            if backup is None and original is None:
                                # 新目标已被并发方接管；保留它即可，本事务
                                # 没有需要恢复的旧版本。
                                continue
                            raise OSError(
                                "目标在事务恢复前又被修改，拒绝覆盖"
                            )
                        if backup is not None and backup.exists():
                            os.replace(backup, path)
                        elif backup is None:
                            path.unlink(missing_ok=True)
                        else:
                            raise OSError(
                                "事务备份不存在，无法自动恢复"
                            )
                    else:
                        if current == original:
                            continue
                        if current is not None:
                            raise OSError(
                                "已删除目标被其它进程重建，拒绝覆盖"
                            )
                        if backup is not None and backup.exists():
                            os.replace(backup, path)
                        elif original is not None:
                            raise OSError(
                                "事务备份不存在，无法自动恢复"
                            )
                except BaseException as restore_exc:
                    restore_errors.append(f"{path}: {restore_exc}")
            if restore_errors:
                detail = "；".join(restore_errors)
                raise RuntimeError(
                    f"本地配置提交失败且自动恢复不完整：{detail}；"
                    f"恢复文件保留在 {self.dir}"
                ) from exc
            self.preserve_recovery = False
            raise
        finally:
            if not self.preserve_recovery:
                self.cleanup()

    def cleanup(self) -> None:
        if self.preserve_recovery:
            return
        cleanup_errors: list[str] = []
        try:
            shutil.rmtree(self.dir)
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup_errors.append(f"{self.dir}: {exc}")
        remaining_probes: list[Path] = []
        for probe in self.external_probes:
            try:
                probe.unlink(missing_ok=True)
            except OSError as exc:
                cleanup_errors.append(f"{probe}: {exc}")
                remaining_probes.append(probe)
        self.external_probes = remaining_probes
        if not self.committed:
            remaining_dirs: list[tuple[Path, tuple[int, int]]] = []
            for directory, identity in reversed(self.created_dirs):
                try:
                    stat = directory.stat()
                    if (stat.st_dev, stat.st_ino) != identity:
                        continue
                    directory.rmdir()
                except OSError:
                    # 非空表示期间出现了其它文件，不能为追求“清理”而误删。
                    if directory.exists():
                        remaining_dirs.append((directory, identity))
            self.created_dirs = list(reversed(remaining_dirs))
        else:
            self.created_dirs.clear()
        if self.dir.exists() and not cleanup_errors:
            cleanup_errors.append(f"{self.dir}: 目录仍然存在")
        previous_error = self.cleanup_error
        self.cleanup_error = "；".join(cleanup_errors)
        if self.cleanup_error and self.cleanup_error != previous_error:
            print(
                "警告：无法完全清理配置事务目录，可能仍含敏感候选文件："
                + self.cleanup_error,
                file=sys.stderr,
            )


def load_yaml(raw: bytes | None, name: str) -> dict:
    if raw is None:
        return {}
    data = yaml.safe_load(raw.decode("utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{name} 顶层必须是 mapping")
    return data


def dump_yaml(data: dict) -> str:
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def ask(prompt: str, default: str | None = None, *, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    value = (getpass.getpass if secret else input)(f"{prompt}{suffix}: ")
    return value if value else (default or "")


def required(prompt: str, default: str | None = None, *, pattern: re.Pattern[str] | None = None) -> str:
    while True:
        value = ask(prompt, default)
        if value and (pattern is None or pattern.fullmatch(value)):
            return value
        print("输入不能为空或格式不正确。")


def secret(prompt: str, current: str | None = None) -> str:
    while True:
        value = ask(prompt + ("（直接回车保留当前值）" if current else ""), secret=True)
        value = value or (current or "")
        if value and not value.startswith("change-me-"):
            return value
        print("Token 不能为空或示例值。")


def choose(prompt: str, choices: str) -> str:
    options = choices.replace("/", "")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        # 保留非交互回退，方便自动化验收和管道输入。
        return _choose_text(prompt, options)

    labels = {
        "a": "新增", "b": "启用（简易）", "c": "配置", "d": "删除", "e": "编辑", "f": "完成", "i": "初始化服务上下文",
        "h": "高级设置", "x": "关闭",
        "k": "改用新私钥", "m": "修改", "o": "覆盖重建", "p": "参数配置", "q": "取消",
        "r": "复用现有", "s": "跳过", "v": "查看",
    }
    index = 0
    # 提示语可能因窄终端换行，不能纳入需要按固定行数回退的菜单区域。
    # 只让短选项列表原地重绘，避免中文长提示造成光标错位。
    print(prompt)
    print("使用 ↑↓ 选择，按 Enter 确认。")
    renderer = _MenuRenderer("选择:", options, labels)
    with _raw_terminal():
        renderer.render(index)
        while True:
            key = _read_key()
            if key == "up":
                index = (index - 1) % len(options)
                renderer.render(index)
            elif key == "down":
                index = (index + 1) % len(options)
                renderer.render(index)
            elif key == "enter":
                # raw 模式关闭了 ONLCR，必须显式 CRLF 才能回到下一行行首。
                sys.stdout.write("\n" if os.name == "nt" else "\r\n")
                return options[index]
            elif key == "escape" and "q" in options:
                sys.stdout.write("\n" if os.name == "nt" else "\r\n")
                return "q"


class _MenuRenderer:
    """原地重绘菜单；Windows 使用 Console API，避免终端不支持 ANSI 时重复输出。"""

    def __init__(self, prompt: str, options: str, labels: dict[str, str]) -> None:
        self.prompt = prompt
        self.options = options
        self.labels = labels
        self.rows = len(options) + 1
        self.drawn = False
        self.windows = os.name == "nt"
        # Windows Console API 不可用时也要能退回 ANSI 相对光标移动。
        self._init_posix_terminal()
        if self.windows:
            self._init_windows_console()

    def _init_posix_terminal(self) -> None:
        """POSIX 终端使用相对移动重绘，不依赖兼容性较差的光标保存/恢复。"""
        # 每次输出结束后，光标位于菜单下一行的行首。
        # 重绘时向上移动固定行数，再清除到屏幕末尾。
        self.redraw_sequence = f"\x1b[{self.rows}A\r\x1b[J".encode("ascii")

    def _write_control(self, sequence: bytes) -> None:
        sys.stdout.flush()
        os.write(sys.stdout.fileno(), sequence)

    def _init_windows_console(self) -> None:
        import ctypes
        from ctypes import wintypes

        class COORD(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", wintypes.SHORT), ("Top", wintypes.SHORT), ("Right", wintypes.SHORT), ("Bottom", wintypes.SHORT)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD), ("dwCursorPosition", COORD), ("wAttributes", wintypes.WORD),
                ("srWindow", SMALL_RECT), ("dwMaximumWindowSize", COORD),
            ]

        self.ctypes = ctypes
        self.COORD = COORD
        self.CSBI = CONSOLE_SCREEN_BUFFER_INFO
        self.DWORD = wintypes.DWORD
        self.WCHAR = wintypes.WCHAR
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        self.kernel32.GetStdHandle.restype = wintypes.HANDLE
        self.kernel32.GetConsoleScreenBufferInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO),
        ]
        self.kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
        self.kernel32.FillConsoleOutputCharacterW.argtypes = [
            wintypes.HANDLE,
            wintypes.WCHAR,
            wintypes.DWORD,
            COORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.FillConsoleOutputCharacterW.restype = wintypes.BOOL
        self.kernel32.SetConsoleCursorPosition.argtypes = [
            wintypes.HANDLE,
            COORD,
        ]
        self.kernel32.SetConsoleCursorPosition.restype = wintypes.BOOL

        # STD_OUTPUT_HANDLE = (DWORD)-11。
        self.handle = self.kernel32.GetStdHandle(
            wintypes.DWORD(-11 & 0xFFFFFFFF)
        )
        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not self.kernel32.GetConsoleScreenBufferInfo(
            self.handle, ctypes.byref(info)
        ):
            # 非 Windows Console（例如某些 IDE 终端）退回 ANSI。
            self.windows = False
            return

    def _lines(self, index: int) -> str:
        lines = [self.prompt]
        for i, key in enumerate(self.options):
            marker = ">" if i == index else " "
            lines.append(f" {marker} {self.labels.get(key, key)}")
        # POSIX raw 模式下 '\n' 不会自动转换为 CRLF；Windows 则由控制台文本层处理换行。
        newline = "\n" if os.name == "nt" else "\r\n"
        return newline.join(lines) + newline

    def _clear_windows(self) -> bool:
        info = self.CSBI()
        if not self.kernel32.GetConsoleScreenBufferInfo(
            self.handle, self.ctypes.byref(info)
        ):
            return False

        # 上次绘制结束后光标位于菜单下一行。终端靠近底部时输出会滚屏，
        # 因此不能复用初始化时保存的绝对 Y 坐标，必须从当前光标反推。
        origin_y = max(0, info.dwCursorPosition.Y - self.rows)
        clear_rows = min(self.rows, info.dwSize.Y - origin_y)
        written = self.DWORD()
        for offset in range(clear_rows):
            coord = self.COORD(0, origin_y + offset)
            if not self.kernel32.FillConsoleOutputCharacterW(
                self.handle,
                self.WCHAR(" "),
                info.dwSize.X,
                coord,
                self.ctypes.byref(written),
            ):
                return False
        return bool(
            self.kernel32.SetConsoleCursorPosition(
                self.handle, self.COORD(0, origin_y)
            )
        )

    def render(self, index: int) -> None:
        if self.drawn:
            if self.windows:
                sys.stdout.flush()
                if not self._clear_windows():
                    self.windows = False
                    self._write_control(self.redraw_sequence)
            else:
                self._write_control(self.redraw_sequence)
        sys.stdout.write(self._lines(index))
        sys.stdout.flush()
        self.drawn = True


def _choose_text(prompt: str, options: str) -> str:
    while True:
        value = input(f"{prompt} [{'/'.join(options)}]: ").lower().strip()
        if value in options:
            return value
        print("无效选择。")


class _raw_terminal:
    """跨平台的短暂原始终端模式；仅由交互菜单使用。"""

    def __enter__(self):
        if os.name == "nt":
            return self
        import termios
        import tty

        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        return self

    def __exit__(self, *_exc):
        if os.name != "nt":
            import termios

            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def _read_key() -> str:
    if os.name == "nt":
        import msvcrt

        key = msvcrt.getwch()
        if key in ("\x00", "\xe0"):
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "other")
        return {"\r": "enter", "\x1b": "escape"}.get(key, "other")

    fd = sys.stdin.fileno()
    key = os.read(fd, 1)
    if key == b"\x03":
        # tty.setraw() 会关闭 ISIG；显式恢复 Ctrl+C 的取消语义。
        raise KeyboardInterrupt
    if key == b"\x1b":
        import select

        def continuation() -> bytes:
            try:
                ready, _, _ = select.select([fd], [], [], 0.1)
            except (OSError, TypeError, ValueError):
                return b""
            return os.read(fd, 1) if ready else b""

        if continuation() == b"[":
            return {b"A": "up", b"B": "down"}.get(
                continuation(), "escape"
            )
        return "escape"
    return {b"\r": "enter", b"\n": "enter"}.get(key, "other")


def action(name: str, exists: bool) -> str:
    if not exists:
        return choose(f"{name} 尚不存在：配置、跳过或取消", "c/s/q")
    return choose(f"{name}：修改、覆盖重建、跳过或取消", "m/o/s/q")


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() in {"y", "yes"}


BASE_MANAGED_ENV_NAMES = (
    "RUNNER_SHARED_TOKEN",
)
def env_values(raw: bytes | None) -> dict[str, str]:
    text = (raw or b"").decode("utf-8")
    out: dict[str, str] = {}
    pattern = r"^\s*((?:RUNNER|VOLCENGINE)_[A-Z0-9_]+)\s*=(.*)$"
    for line in text.splitlines():
        match = re.match(pattern, line)
        if match:
            try:
                parsed = shlex.split(match.group(2), posix=True)
                out[match.group(1)] = parsed[0] if parsed else ""
            except ValueError:
                continue
    return out


def _update_env_file(
    raw: bytes | None,
    values: dict[str, str],
    *,
    preserve_existing: bool,
) -> str:
    """只更新 values 中由向导管理的变量，保留其它变量与注释。"""
    managed_names = tuple(values)
    managed_alternation = "|".join(re.escape(name) for name in managed_names)
    pattern = re.compile(
        rf"^\s*({managed_alternation})\s*="
    )

    def assignment(name: str, value: str) -> str:
        escaped = "'" + value.replace("'", "'\\''") + "'"
        return f"{name}={escaped}"

    lines = (
        (raw or b"").decode("utf-8").splitlines()
        if preserve_existing
        else ["# 由配置向导生成；不提交。"]
    )
    output: list[str] = []
    written: set[str] = set()
    for line in lines:
        match = pattern.match(line)
        if not match:
            output.append(line)
            continue
        name = match.group(1)
        if name not in written:
            output.append(assignment(name, values[name]))
            written.add(name)
    for name in managed_names:
        if name not in written:
            output.append(assignment(name, values[name]))
    return "\n".join(output).rstrip("\n") + "\n"


def configure_env(tx: Transaction) -> None:
    path = ROOT / ".env"
    exists = tx.read(path) is not None
    mode = action(path.name, exists)
    if mode == "q": raise Cancelled
    if mode == "s": return
    old = env_values(tx.read(path)) if mode == "m" else {}

    def configured_secret(name: str) -> str:
        current = old.get(name)
        return secret(name, current)

    values = {
        name: configured_secret(name)
        for name in BASE_MANAGED_ENV_NAMES
    }
    runner_base = CONFIG / "runner.yaml"
    base = load_yaml(tx.read(runner_base), runner_base.name)
    trusted = (
        base.get("trusted_session", {})
        if isinstance(base.get("trusted_session"), dict)
        else {}
    )
    if trusted.get("enabled") is True:
        for name in (
            str(
                trusted.get("token_env")
                or "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN"
            ),
            str(
                trusted.get("admin_token_env")
                or "RUNNER_SHARED_TOKEN"
            ),
        ):
            if name not in values:
                values[name] = configured_secret(name)
        encryption_key_env = str(
            trusted.get("encryption_key_env") or ""
        ).strip()
        if encryption_key_env:
            if encryption_key_env not in values:
                values[encryption_key_env] = configured_secret(encryption_key_env)
    text = _update_env_file(
        tx.read(path),
        values,
        preserve_existing=mode == "m",
    )
    tx.stage_text(path, text)


def _stage_kubernetes_env(
    tx: Transaction, setup: KubernetesEnvSetup | None
) -> None:
    """将 Kubernetes 阶段新增的 VMP/TLS 凭据并入已配置的 .env。"""
    if setup is None or not setup.values:
        return
    path = ROOT / ".env"
    tx.stage_text(
        path,
        _update_env_file(
            tx.read(path), setup.values, preserve_existing=True
        ),
    )


def _trusted_int(
    prompt: str, default: int, *, maximum: int | None = None
) -> int:
    while True:
        value = required(prompt, str(default), pattern=re.compile(r"\d+"))
        parsed = int(value)
        if parsed >= 1 and (maximum is None or parsed <= maximum):
            return parsed
        suffix = f"1..{maximum}" if maximum is not None else "正整数"
        print(f"{prompt} 必须是 {suffix}。")


def _trusted_url(prompt: str, default: str) -> str:
    while True:
        value = required(prompt, default)
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError:
            parsed = None
        if (
            parsed is not None
            and parsed.scheme.lower() in {"http", "https"}
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and parsed.path.endswith(TRUSTED_REPAIR_CALLBACK_PATH)
            and not any(character.isspace() for character in value)
        ):
            return value
        print(
            "可信回调 URL 必须是绝对 http(s) URL，且以 "
            f"{TRUSTED_REPAIR_CALLBACK_PATH} 结尾。"
        )


def _canonical_uuid(
    value: str, *, allow_empty: bool = False, require_v4: bool = False
) -> str:
    value = value.strip()
    if allow_empty and not value:
        return ""
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ValueError("必须是小写、带连字符的 canonical UUID") from exc
    if str(parsed) != value or (require_v4 and parsed.version != 4):
        raise ValueError("必须是小写、带连字符的 canonical UUID")
    return value


def _trusted_uuid(
    prompt: str,
    default: str = "",
    *,
    allow_empty: bool = False,
    require_v4: bool = False,
) -> str:
    while True:
        value = ask(prompt, default)
        try:
            return _canonical_uuid(
                value, allow_empty=allow_empty, require_v4=require_v4
            )
        except ValueError as exc:
            print(str(exc))


def _configure_trusted_session_advanced(tx: Transaction) -> None:
    """高级模式仅调整本机路径、回调和保留策略，不再配置 AIOps 绑定。"""
    path = CONFIG / "runner.yaml"
    current = load_yaml(tx.read(path), path.name)
    old = (
        current.get("trusted_session", {})
        if isinstance(current.get("trusted_session"), dict)
        else {}
    )
    instance_file = required(
        "Runner 本机身份文件",
        str(old.get("runner_instance_id_file") or "state/runner-instance-id"),
    )
    aiops_url = _trusted_url(
        "可信事件回调 URL",
        _derive_trusted_callback_url(tx)
        or "http://aiops-backend:8080/aiops/repair-sessions/callbacks/events",
    )
    # 这些字段曾要求用户在 AIOps 与 Runner 间重复登记。现在 AIOps 直接
    # 派发给已启用的 Runner，资产解析只以本机 inventory 为准。
    retained = dict(old)
    for key in ("target_scope", "target_allowlist", "runner_provider_id",
                "expected_runner_instance_id", "token_env", "aiops_url"):
        retained.pop(key, None)
    trusted = {
        **retained,
        "enabled": True,
        "project_dir": required(
            "Trusted Claude project 目录",
            str(old.get("project_dir") or "agent-project-trusted"),
        ),
        "journal_dir": required(
            "可信 session journal 目录",
            str(old.get("journal_dir") or "state/trusted-sessions"),
        ),
        "transcript_dir": required(
            "加密 transcript 目录",
            str(
                old.get("transcript_dir") or "state/trusted-transcripts"
            ),
        ),
        "session_store_dir": required(
            "Claude session store 目录",
            str(
                old.get("session_store_dir")
                or "state/trusted-claude-config"
            ),
        ),
        "runner_instance_id_file": instance_file,
        "runner_config_version": required(
            "Runner 配置版本",
            str(old.get("runner_config_version") or "v1"),
        ),
        "token_env": "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN",
        "admin_token_env": "RUNNER_SHARED_TOKEN",
        "approval_ttl_sec": _trusted_int(
            "首次审批 TTL（秒）",
            int(old.get("approval_ttl_sec") or 1800),
            maximum=1800,
        ),
        "execution_ttl_sec": _trusted_int(
            "修复执行 TTL（秒）",
            int(old.get("execution_ttl_sec") or 1800),
            maximum=1800,
        ),
        "risk_ttl_sec": _trusted_int(
            "高风险确认 TTL（秒）",
            int(old.get("risk_ttl_sec") or 600),
            maximum=600,
        ),
        "transcript_retention_days": _trusted_int(
            "加密 transcript 保留天数",
            int(old.get("transcript_retention_days") or 30),
        ),
        "encryption_key_env": "",
        "encryption_key_file": "state/trusted-transcript.key",
        "encryption_key_id": required(
            "Transcript 密钥 ID",
            str(old.get("encryption_key_id") or "v1"),
        ),
    }
    updated = _without_trusted_callback_urls(
        {**current, "trusted_session": trusted}
    )
    tx.stage_text(path, dump_yaml(updated))
    _stage_local_trusted_callback_urls(tx, aiops_url)
    print(
        "可信模式不会自动创建 Runner 身份。身份文件必须已由 "
        "`python -m runner.instance_identity init` 显式初始化。"
    )


def _valid_trusted_callback_url(value: str) -> str:
    """Return a canonical trusted callback URL, or an empty string."""
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(TRUSTED_REPAIR_CALLBACK_PATH)
    ):
        return ""
    return value


def _inspection_callback_url(trusted_callback_url: str) -> str:
    """Derive the inspection endpoint without losing a reverse-proxy prefix."""
    if not _valid_trusted_callback_url(trusted_callback_url):
        raise ValueError("可信事件回调 URL 无效")
    parsed = urlsplit(trusted_callback_url)
    prefix = parsed.path[: -len(TRUSTED_REPAIR_CALLBACK_PATH)]
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            prefix + TRUSTED_INSPECTION_CALLBACK_PATH,
            "",
            "",
        )
    )


def _with_local_trusted_callback_urls(
    current: dict, trusted_callback_url: str
) -> dict:
    """Store deployment-specific callback destinations in local config."""
    trusted = (
        current.get("trusted_session", {})
        if isinstance(current.get("trusted_session"), dict)
        else {}
    )
    inspection = (
        current.get("trusted_inspection", {})
        if isinstance(current.get("trusted_inspection"), dict)
        else {}
    )
    return {
        **current,
        "trusted_session": {**trusted, "aiops_url": trusted_callback_url},
        "trusted_inspection": {
            **inspection,
            "aiops_url": _inspection_callback_url(trusted_callback_url),
        },
    }


def _without_trusted_callback_urls(current: dict) -> dict:
    """Remove deployment-specific callback destinations from base config."""
    updated = dict(current)
    for section_name in ("trusted_session", "trusted_inspection"):
        section = updated.get(section_name)
        if isinstance(section, dict):
            section = dict(section)
            section.pop("aiops_url", None)
            updated[section_name] = section
    return updated


def _stage_local_trusted_callback_urls(
    tx: Transaction, trusted_callback_url: str
) -> None:
    local_path = CONFIG / "runner.local.yaml"
    local = load_yaml(tx.read(local_path), local_path.name)
    tx.stage_text(
        local_path,
        dump_yaml(
            _with_local_trusted_callback_urls(local, trusted_callback_url)
        ),
    )


def _repair_callback_url(inspection_callback_url: str) -> str:
    """Derive the repair endpoint from a legacy inspection-only setting."""
    try:
        parsed = urlsplit(inspection_callback_url)
        _ = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(TRUSTED_INSPECTION_CALLBACK_PATH)
    ):
        return ""
    prefix = parsed.path[: -len(TRUSTED_INSPECTION_CALLBACK_PATH)]
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            prefix + TRUSTED_REPAIR_CALLBACK_PATH,
            "",
            "",
        )
    )


def _derive_trusted_callback_url(tx: Transaction) -> str:
    """Read the effective callback, preferring ignored local configuration."""
    runner_path = CONFIG / "runner.yaml"
    base = load_yaml(tx.read(runner_path), runner_path.name)
    local_path = CONFIG / "runner.local.yaml"
    local = load_yaml(tx.read(local_path), local_path.name)
    for data in (local, base):
        trusted = (
            data.get("trusted_session", {})
            if isinstance(data.get("trusted_session"), dict)
            else {}
        )
        value = _valid_trusted_callback_url(
            str(trusted.get("aiops_url") or "").strip()
        )
        if value:
            return value
    for data in (local, base):
        inspection = (
            data.get("trusted_inspection", {})
            if isinstance(data.get("trusted_inspection"), dict)
            else {}
        )
        value = _repair_callback_url(
            str(inspection.get("aiops_url") or "").strip()
        )
        if value:
            return value
    # Retain migration support for the retired callback section.
    callback: dict = {}
    for data in (base, local):
        legacy = data.get("callback", {}) if isinstance(data, dict) else {}
        if isinstance(legacy, dict):
            callback.update(legacy)
    value = str(callback.get("aiops_url", "") or "").strip()
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return ""
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return ""
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            TRUSTED_REPAIR_CALLBACK_PATH,
            "",
            "",
        )
    )


def _usable_secret(value: str | None) -> bool:
    return bool(value and not value.startswith("change-me-"))


def _trusted_identity_path(identity_file: str) -> Path:
    path = Path(identity_file)
    return path if path.is_absolute() else ROOT / path


def _trusted_identity_owner_uid() -> int:
    """Validate identity ownership against the installed runner account.

    The wizard is often intentionally launched by root, while the runner
    systemd service runs as an unprivileged account.  ``load_identity``
    otherwise compares against root and rejects a correctly secured state
    directory before the transaction can be committed.
    """
    if os.name != "posix":
        return os.geteuid() if hasattr(os, "geteuid") else 0
    configured_user = os.environ.get("RUNNER_SERVICE_USER", "").strip()
    if configured_user:
        if not SSH_USER.fullmatch(configured_user):
            raise ValueError("RUNNER_SERVICE_USER 格式无效")
        try:
            import pwd

            return pwd.getpwnam(configured_user).pw_uid
        except KeyError as exc:
            raise ValueError(
                f"RUNNER_SERVICE_USER 不存在：{configured_user}"
            ) from exc
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=User", "--value", "aiops-trusted-runner.service"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=5,
        )
        user = result.stdout.strip()
        if result.returncode == 0 and SSH_USER.fullmatch(user):
            import pwd
            return pwd.getpwnam(user).pw_uid
    except (OSError, subprocess.TimeoutExpired, KeyError):
        pass
    return os.geteuid()


def _load_simple_trusted_identity(identity_file: str) -> str:
    from runner.instance_identity import InstanceIdentityError, load_identity

    # configure.sh is commonly invoked from scripts/, while the configured
    # relative path is intentionally relative to the Runner repository root.
    # Never make identity validity depend on the caller's current directory.
    resolved_identity_file = _trusted_identity_path(identity_file)
    try:
        return load_identity(
            resolved_identity_file, owner_uid=_trusted_identity_owner_uid()
        ).instance_id
    except InstanceIdentityError as exc:
        raise ValueError(
            "Runner 实例身份无效；请先显式初始化且不要覆盖已有身份："
            " python -m runner.instance_identity init --file "
            + shlex.quote(str(resolved_identity_file))
        ) from exc


def _configure_trusted_session_simple(tx: Transaction) -> TrustedEnvSetup:
    """The normal Linux setup: no separate trusted identity or callback setup."""
    path = CONFIG / "runner.yaml"
    current = load_yaml(tx.read(path), path.name)
    old = (
        current.get("trusted_session", {})
        if isinstance(current.get("trusted_session"), dict)
        else {}
    )
    retained = dict(old)
    for key in ("target_scope", "target_allowlist", "runner_provider_id",
                "expected_runner_instance_id", "token_env", "aiops_url"):
        retained.pop(key, None)
    print("可信修复将授权该 Runner 资产清单中的全部已登记资产；组目标仅可诊断，不能批量修复。")
    identity_file = str(
        old.get("runner_instance_id_file") or "state/runner-instance-id"
    )
    aiops_url = _derive_trusted_callback_url(tx)
    if not aiops_url:
        aiops_url = _trusted_url(
            "可信事件回调 URL",
            "http://aiops-backend:8080/aiops/repair-sessions/callbacks/events",
        )

    env_path = ROOT / ".env"
    setup_values: dict[str, str] = {}

    trusted = {
        **retained,
        "enabled": True,
        "inventory_dir": str(old.get("inventory_dir") or "config"),
        "project_dir": str(old.get("project_dir") or "agent-project-trusted"),
        "journal_dir": str(old.get("journal_dir") or "state/trusted-sessions"),
        "transcript_dir": str(old.get("transcript_dir") or "state/trusted-transcripts"),
        "session_store_dir": str(old.get("session_store_dir") or "state/trusted-claude-config"),
        "runner_instance_id_file": identity_file,
        "runner_config_version": str(old.get("runner_config_version") or "v1"),
        "token_env": "RUNNER_TRUSTED_AIOPS_CALLBACK_TOKEN",
        "admin_token_env": "RUNNER_SHARED_TOKEN",
        "approval_ttl_sec": int(old.get("approval_ttl_sec") or 1800),
        "execution_ttl_sec": int(old.get("execution_ttl_sec") or 1800),
        "risk_ttl_sec": int(old.get("risk_ttl_sec") or 600),
        "transcript_retention_days": int(old.get("transcript_retention_days") or 30),
        "encryption_key_env": "",
        "encryption_key_file": "state/trusted-transcript.key",
        "encryption_key_id": str(old.get("encryption_key_id") or "v1"),
    }
    updated = _without_trusted_callback_urls(
        {**current, "trusted_session": trusted}
    )
    tx.stage_text(path, dump_yaml(updated))
    _stage_local_trusted_callback_urls(tx, aiops_url)
    print(
        "可信修复简易配置已准备（密钥不会显示）："
        f"目标范围=全部已登记资产，回调={aiops_url}。"
    )
    return TrustedEnvSetup(setup_values)


def configure_trusted_session(tx: Transaction) -> TrustedEnvSetup | None:
    """Configure Linux-only trusted session with a concise normal path."""
    mode = choose(
        "可信 Claude 修复：启用（简易）、高级设置、跳过或取消",
        "b/h/s/q",
    )
    if mode == "q":
        raise Cancelled
    if mode == "s":
        return None
    if mode == "h":
        _configure_trusted_session_advanced(tx)
        return None
    return _configure_trusted_session_simple(tx)


def configure_runner(tx: Transaction) -> None:
    path = CONFIG / "runner.local.yaml"
    mode = action(path.name, tx.read(path) is not None)
    if mode == "q": raise Cancelled
    if mode == "s": return
    old = load_yaml(tx.read(path), path.name) if mode == "m" else {}
    webhook = old.get("webhook", {}) if isinstance(old.get("webhook"), dict) else {}
    while True:
        listen = required(
            "Runner 监听地址",
            webhook.get("listen", "0.0.0.0:8002"),
        )
        try:
            parsed_listen = urlsplit("//" + listen)
            listen_port = parsed_listen.port
        except ValueError:
            parsed_listen = None
            listen_port = None
        if (
            parsed_listen is not None
            and parsed_listen.hostname
            and ":" not in parsed_listen.hostname
            and listen_port is not None
            and 1 <= listen_port <= 65535
            and parsed_listen.username is None
            and parsed_listen.password is None
            and not parsed_listen.path
            and not parsed_listen.query
            and not parsed_listen.fragment
            and not any(character.isspace() for character in listen)
        ):
            break
        print(
            "监听地址必须为 IPv4/DNS host:port，"
            "端口范围 1..65535。"
        )
    runner_path = CONFIG / "runner.yaml"
    runner_data = load_yaml(tx.read(runner_path), runner_path.name)
    trusted_callback_url = _trusted_url(
        "可信事件回调 URL",
        _derive_trusted_callback_url(tx)
        or "http://aiops-backend:8080/aiops/repair-sessions/callbacks/events",
    )
    # 固定诊断/修复回调已退役。可信会话与巡检共用同一个 AIOps 地址，
    # 由这一项派生各自的固定回调路径，避免后端地址发生漂移。
    local = _with_local_trusted_callback_urls(
        {**old, "webhook": {**webhook, "listen": listen}},
        trusted_callback_url,
    )
    tx.stage_text(path, dump_yaml(local))
    tx.stage_text(
        runner_path,
        dump_yaml(_without_trusted_callback_urls(runner_data)),
    )


def _ask_bool(prompt: str, default: bool = False) -> bool:
    default_text = "y" if default else "n"
    while True:
        value = ask(prompt + " [y/n]", default_text).strip().lower()
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("请输入 y 或 n。")


def _kubeconfig_document(data: bytes) -> tuple[dict, list[str], str]:
    if not data:
        raise ValueError("kubeconfig 不能为空")
    if len(data) > KUBERNETES_MAX_KUBECONFIG_BYTES:
        raise ValueError("kubeconfig 不能超过 2 MiB")
    try:
        document = yaml.safe_load(data.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("kubeconfig 不是有效的 UTF-8 YAML") from exc
    if not isinstance(document, dict):
        raise ValueError("kubeconfig 顶层必须是对象")
    contexts = []
    for item in document.get("contexts") or []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("kubeconfig contexts 包含无效记录")
        name = item["name"].strip()
        if name and name not in contexts:
            contexts.append(name)
    if not contexts:
        raise ValueError("kubeconfig 不包含可用 context")
    for item in document.get("users") or []:
        user = item.get("user") if isinstance(item, dict) else None
        if isinstance(user, dict) and user.get("exec") is not None:
            raise ValueError(
                "kubeconfig 使用 exec 认证插件，Runner 为避免执行本地命令拒绝导入"
            )
    current = str(document.get("current-context") or "").strip()
    return document, contexts, current


def _kubeconfig_source(tx: Transaction, value: str) -> tuple[Path, bytes]:
    source = Path(value).expanduser()
    if not source.is_absolute():
        source = ROOT / source
    source = Path(os.path.abspath(source))
    if os.path.islink(source):
        raise ValueError("kubeconfig 来源不能是符号链接")
    staged = getattr(tx, "files", {}).get(source)
    if staged is not None:
        _kubeconfig_document(staged)
        return source, staged
    try:
        size = source.stat(follow_symlinks=False).st_size
    except FileNotFoundError as exc:
        raise ValueError(f"kubeconfig 来源不存在：{source}") from exc
    if size > KUBERNETES_MAX_KUBECONFIG_BYTES:
        raise ValueError("kubeconfig 不能超过 2 MiB")
    data = tx.read(source)
    if data is None:
        raise ValueError(f"kubeconfig 来源不存在：{source}")
    _kubeconfig_document(data)
    tx.watch(source)
    return source, data


def _namespace_allowlist(value: str) -> list[str]:
    namespaces: list[str] = []
    for raw in value.split(","):
        namespace = raw.strip()
        if not namespace:
            continue
        if len(namespace) > 253 or not KUBERNETES_NAMESPACE.fullmatch(namespace):
            raise ValueError(f"Namespace 格式无效：{namespace}")
        if namespace not in namespaces:
            namespaces.append(namespace)
    return namespaces


def _managed_kubeconfig_path(value: str) -> Path | None:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    path = Path(os.path.abspath(path))
    try:
        path.relative_to(KUBERNETES_KEYS_DIR.resolve())
    except ValueError:
        return None
    return path


def _kubernetes_cluster_form(
    tx: Transaction,
    old: dict | None = None,
) -> tuple[dict, Path, bytes]:
    old = old or {}
    if old:
        cluster_id = str(old["id"])
        print(f"编辑集群 {cluster_id}；集群 ID 为稳定绑定标识，不能在编辑中修改。")
    else:
        cluster_id = required(
            "Runner 集群 ID",
            pattern=KUBERNETES_CLUSTER_ID,
        )
    display_name = required(
        "集群显示名称",
        str(old.get("display_name") or cluster_id),
    )
    environment = required(
        "环境标识",
        str(old.get("environment") or "prod"),
        pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    )
    old_kubeconfig = str(old.get("kubeconfig_path") or "")
    source_default = ""
    if old_kubeconfig:
        old_source = Path(old_kubeconfig)
        source_default = str(old_source if old_source.is_absolute() else ROOT / old_source)
    source_value = required("kubeconfig 来源文件", source_default or None)
    _, kubeconfig_data = _kubeconfig_source(tx, source_value)
    _, contexts, current_context = _kubeconfig_document(kubeconfig_data)
    print("可用 context：" + "、".join(contexts))
    context_default = str(old.get("context") or current_context or contexts[0])
    while True:
        context = required("使用的 context", context_default)
        if context in contexts:
            break
        print("所选 context 不在 kubeconfig 中。")

    old_namespaces = old.get("namespace_allowlist") or []
    while True:
        try:
            namespaces = _namespace_allowlist(
                ask(
                    "Namespace 白名单（逗号分隔，留空表示全集群）",
                    ",".join(str(item) for item in old_namespaces) or None,
                )
            )
            break
        except ValueError as exc:
            print(exc)

    old_vmp = old.get("vmp") if isinstance(old.get("vmp"), dict) else {}
    vmp: dict[str, str] = {}
    if _ask_bool("配置 VMP 历史指标", bool(old_vmp)):
        vmp = {
            "region": required("VMP Region", str(old_vmp.get("region") or "cn-beijing")),
            "workspace_id": required("VMP Workspace ID", str(old_vmp.get("workspace_id") or "") or None),
        }

    old_tls = old.get("tls") if isinstance(old.get("tls"), dict) else {}
    tls: dict[str, str] = {}
    if _ask_bool("配置 TLS 历史日志/事件", bool(old_tls)):
        tls = {
            "region": required("TLS Region", str(old_tls.get("region") or "cn-beijing")),
            "log_topic_id": required("TLS 日志 Topic ID", str(old_tls.get("log_topic_id") or "") or None),
            "event_topic_id": required("TLS 事件 Topic ID", str(old_tls.get("event_topic_id") or "") or None),
        }

    target = KUBERNETES_KEYS_DIR / f"{cluster_id}.kubeconfig"
    entry = {
        "id": cluster_id,
        "display_name": display_name,
        "environment": environment,
        "kubeconfig_path": target.relative_to(ROOT).as_posix(),
        "context": context,
        "namespace_allowlist": namespaces,
        "vmp": vmp,
        "tls": tls,
    }
    return entry, target, kubeconfig_data


def _select_cluster(clusters: list[dict], prompt: str) -> int:
    ids = [str(item.get("id")) for item in clusters]
    while True:
        selected = required(prompt, ids[0] if len(ids) == 1 else None)
        if selected in ids:
            return ids.index(selected)
        print("集群 ID 不存在；当前集群：" + "、".join(ids))


def _configure_volcengine_env(
    tx: Transaction,
    clusters: list[dict],
) -> KubernetesEnvSetup | None:
    history_enabled = any(item.get("vmp") or item.get("tls") for item in clusters)
    if not history_enabled:
        return None
    mode = choose(
        "VMP/TLS 需要受限火山云子账号 AK/SK：由向导写入本地环境文件，或复用进程已有环境变量",
        "c/r/q",
    )
    if mode == "q":
        raise Cancelled
    if mode == "r":
        missing = [name for name in VOLCENGINE_ENV_NAMES if not os.environ.get(name)]
        if missing:
            raise ValueError(
                "当前向导进程缺少外部环境变量：" + "、".join(missing)
            )
        return None
    env_path = ROOT / ".env"
    existing = env_values(tx.read(env_path))
    values = {
        name: secret(name, existing.get(name) or os.environ.get(name))
        for name in VOLCENGINE_ENV_NAMES
    }
    return KubernetesEnvSetup(values=values)


def _configure_kubernetes_parameters(current: dict) -> dict:
    """Prompt for optional local overrides of the base Kubernetes defaults."""
    return {
        "current_metrics_cache_sec": _trusted_int(
            "当前指标缓存秒数",
            int(current.get("current_metrics_cache_sec") or 15),
            maximum=60,
        ),
        "sync_timeout_sec": _trusted_int(
            "资产同步超时秒数",
            int(current.get("sync_timeout_sec") or 300),
            maximum=1800,
        ),
        "continuous_collection_enabled": _ask_bool(
            "启用 Kubernetes 持续采集",
            bool(current.get("continuous_collection_enabled", True)),
        ),
        "collection_interval_sec": _trusted_int(
            "持续采集间隔秒数",
            int(current.get("collection_interval_sec") or 15),
            maximum=300,
        ),
        "collection_memory_limit_mb": _trusted_int(
            "采集内存队列上限 MiB",
            int(current.get("collection_memory_limit_mb") or 128),
            maximum=2048,
        ),
        "log_collection_concurrency": _trusted_int(
            "日志采集并发数",
            int(current.get("log_collection_concurrency") or 16),
            maximum=64,
        ),
        "log_all_namespaces": _ask_bool(
            "采集全部命名空间的容器日志",
            bool(current.get("log_all_namespaces", True)),
        ),
        "log_request_timeout_sec": _trusted_int(
            "单次日志请求超时秒数",
            int(current.get("log_request_timeout_sec") or 10),
            maximum=60,
        ),
        "reconcile_interval_sec": _trusted_int(
            "资源全量校准间隔秒数",
            int(current.get("reconcile_interval_sec") or 21600),
            maximum=86400,
        ),
    }


def configure_kubernetes(
    tx: Transaction,
) -> KubernetesEnvSetup | None:
    runner_local_path = CONFIG / "runner.local.yaml"
    runner_local = load_yaml(tx.read(runner_local_path), runner_local_path.name)
    current = runner_local.get("kubernetes")
    current = current if isinstance(current, dict) else {}
    choice = choose(
        "Kubernetes/VKE：启用并配置集群、参数配置、跳过或取消",
        "b/p/s/q",
    )
    if choice == "q":
        raise Cancelled
    if choice == "s":
        return None
    inventory_raw = tx.read(KUBERNETES_INVENTORY_PATH)
    inventory = load_yaml(inventory_raw, KUBERNETES_INVENTORY_PATH.name)
    clusters = inventory.get("clusters", []) if inventory_raw else []
    if not isinstance(clusters, list) or any(not isinstance(item, dict) for item in clusters):
        raise ValueError("kubernetes.local.yaml 的 clusters 必须是列表")
    clusters = [dict(item) for item in clusters]
    original_paths = {
        path
        for item in clusters
        if (path := _managed_kubeconfig_path(str(item.get("kubeconfig_path") or "")))
    }
    touched_paths = set(original_paths)

    if choice == "b":
        while True:
            if clusters:
                print(
                    "当前 Kubernetes 集群："
                    + "、".join(str(item.get("id")) for item in clusters)
                    + "\n"
                )
                operation = choose("集群配置：新增、编辑、删除或完成", "a/e/d/f")
            else:
                operation = choose("尚未配置集群：新增或取消", "a/q")
            if operation == "q":
                raise Cancelled
            if operation == "f":
                break
            if operation == "a":
                entry, target, data = _kubernetes_cluster_form(tx)
                if any(item.get("id") == entry["id"] for item in clusters):
                    raise ValueError(f"集群 ID 已存在：{entry['id']}")
                tx.stage_bytes(target, data, 0o600)
                touched_paths.add(target)
                clusters.append(entry)
                continue
            index = _select_cluster(clusters, "集群 ID")
            old = clusters[index]
            if operation == "d":
                if not confirm(f"确认删除集群 {old.get('id')} 的本地配置"):
                    continue
                clusters.pop(index)
                continue
            entry, target, data = _kubernetes_cluster_form(tx, old)
            tx.stage_bytes(target, data, 0o600)
            touched_paths.add(target)
            clusters[index] = entry

    if not clusters:
        raise ValueError("启用 Kubernetes 或调整参数时至少需要配置一个集群")
    referenced_paths = {
        path
        for item in clusters
        if (path := _managed_kubeconfig_path(str(item.get("kubeconfig_path") or "")))
    }
    if choice == "b":
        for path in touched_paths - referenced_paths:
            tx.delete(path)
        tx.stage_text(
            KUBERNETES_INVENTORY_PATH,
            dump_yaml({"clusters": clusters}),
            0o600,
        )
    runner_local["kubernetes"] = {
        **current,
        "enabled": True,
        "inventory_file": KUBERNETES_INVENTORY_PATH.relative_to(ROOT).as_posix(),
        "state_dir": "state/kubernetes",
        # New wizard-managed clusters opt in to the v2 report. Existing nodes
        # that have not run the wizard remain on the config default (v1).
        "inspection_report_version": str(
            current.get("inspection_report_version") or "v2"
        ),
    }
    if choice == "p":
        runner_local["kubernetes"].update(
            _configure_kubernetes_parameters(current)
        )
    tx.stage_text(runner_local_path, dump_yaml(runner_local))
    if choice == "p":
        return None
    return _configure_volcengine_env(tx, clusters)


def _parse_known_hosts(raw: bytes | None) -> tuple[list[dict[str, object]], list[str]]:
    """把 known_hosts 按主机字段分组，便于逐目标查看和删除。

    ssh-keyscan 通常会为同一主机返回多种算法，因此一个目标可能对应多行。
    无法识别的注释或非标准行会原样保留。
    """
    groups: dict[str, list[str]] = {}
    order: list[str] = []
    extras: list[str] = []
    text = (raw or b"").decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            extras.append(line)
            continue
        parts = stripped.split()
        if parts[0].startswith("@"):
            if (
                len(parts) < 4
                or parts[0] not in {"@cert-authority", "@revoked"}
            ):
                extras.append(line)
                continue
            host_field = parts[1]
        elif len(parts) >= 3:
            host_field = parts[0]
        else:
            extras.append(line)
            continue
        if host_field not in groups:
            groups[host_field] = []
            order.append(host_field)
        groups[host_field].append(line)
    return ([{"host_field": host, "lines": groups[host]} for host in order], extras)


def _known_host_label(host_field: str) -> str:
    if host_field.startswith("|1|"):
        return "历史哈希主机记录（无法显示原地址）"
    return host_field


def _known_hosts_bytes(entries: list[dict[str, object]], extras: list[str]) -> bytes:
    lines = [line for line in extras if line.strip()]
    for entry in entries:
        lines.extend(str(line) for line in entry["lines"])
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def _show_host_fingerprints(data: bytes) -> None:
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", "-"],
            input=data,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("计算 SSH host key 指纹超时") from exc
    if result.stdout:
        sys.stdout.write(result.stdout.decode("utf-8", errors="replace"))
    if result.returncode and result.stderr:
        sys.stdout.write(result.stderr.decode("utf-8", errors="replace"))


def _scan_host_key(host: str, port: int) -> bytes:
    # ssh-keyscan can successfully return no keys on a network failure. Probe
    # TCP first so an operator gets an actionable firewall/security-group hint.
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except socket.timeout as exc:
        raise ValueError(
            f"无法连接 {host}:{port}：TCP 连接超时。请检查目标安全组/防火墙是否允许 "
            "runner 节点访问 SSH 端口。"
        ) from exc
    except OSError as exc:
        detail = str(exc).strip() or exc.__class__.__name__
        raise ValueError(f"无法连接 {host}:{port}：{detail}") from exc

    command = ["ssh-keyscan", "-T", "5"]
    if port != 22:
        command.extend(["-p", str(port)])
    command.append(host)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"获取 {host}:{port} 的 SSH host key 超时") from exc
    scanned = b"\n".join(
        line for line in result.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith(b"#")
    )
    if scanned:
        scanned += b"\n"
    if not scanned:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"无法获取 {host}:{port} 的 SSH host key" + (f"：{detail}" if detail else ""))
    return scanned



def _decode_process_output(data: bytes) -> str:
    """兼容 Linux UTF-8 和中文 Windows 常见的 GB18030 输出。"""
    if not data:
        return ""
    for encoding in ("utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _run_local_powershell(script: str, error_prefix: str) -> None:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError(f"{error_prefix}；PowerShell 执行超时") from exc
    if result.returncode:
        detail = (
            _decode_process_output(result.stderr).strip()
            or _decode_process_output(result.stdout).strip()
            or f"PowerShell 退出码 {result.returncode}"
        )
        raise OSError(f"{error_prefix}；{detail}")


def _secure_work_directory(path: Path) -> None:
    """事务目录先设为 owner-only，再允许任何凭据进入其中。"""
    if os.name != "nt":
        os.chmod(path, 0o700)
        return

    escaped_path = str(path).replace("'", "''")
    script = rf"""
$ErrorActionPreference = 'Stop'
$path = '{escaped_path}'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$directory = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $path
$acl = $directory.GetAccessControl()
$acl.SetAccessRuleProtection($true, $false)
foreach ($existing in @($acl.Access)) {{
    [void]$acl.RemoveAccessRuleSpecific($existing)
}}
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $currentSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)
[void]$acl.AddAccessRule($rule)
$directory.SetAccessControl($acl)
"""
    _run_local_powershell(
        script, f"无法保护配置事务目录：{path}"
    )


def _secure_private_key_file(path: Path) -> None:
    """把本地私钥限制为仅当前用户可访问。"""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return

    escaped_path = str(path).replace("'", "''")
    script = rf"""
$ErrorActionPreference = 'Stop'
$path = '{escaped_path}'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$file = New-Object -TypeName System.IO.FileInfo -ArgumentList $path
$acl = $file.GetAccessControl()
$acl.SetAccessRuleProtection($true, $false)
foreach ($existing in @($acl.Access)) {{
    [void]$acl.RemoveAccessRuleSpecific($existing)
}}
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $currentSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
)
[void]$acl.AddAccessRule($rule)
$file.SetAccessControl($acl)

$actual = $file.GetAccessControl()
$actualOwner = $actual.GetOwner(
    [System.Security.Principal.SecurityIdentifier]
)
if ($actualOwner.Value -ne $currentSid.Value) {{
    throw "private key owner is $($actualOwner.Value), expected $($currentSid.Value)"
}}
$unexpected = @(
    $actual.Access | Where-Object {{
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value -ne $currentSid.Value
    }}
)
if ($unexpected.Count -ne 0) {{
    throw 'private key ACL still grants access to another identity'
}}
"""
    _run_local_powershell(
        script, f"无法收紧 Windows 私钥权限：{path}"
    )


def _materialize_private_key_probe(
    tx: Transaction,
    key_data: bytes,
) -> tuple[Path, str]:
    """在 owner-only 事务目录中生成 SSH 预检副本并返回其公钥。"""
    probe = tx.dir / f"ssh-key-preflight-{secrets.token_hex(8)}"
    with probe.open("xb") as file:
        file.write(key_data)
        file.flush()
        os.fsync(file.fileno())
    _secure_private_key_file(probe)
    return probe, _derive_public_key(probe)


def _ssh_error_kind(stderr: str) -> str:
    detail = stderr.lower()
    if any(
        marker in detail
        for marker in (
            "unprotected private key file",
            "bad permissions",
            "permissions for ",
            "load key ",
            "identity file ",
        )
    ):
        return "local_key"
    if any(
        marker in detail
        for marker in (
            "host key verification failed",
            "remote host identification has changed",
            "no matching host key",
        )
    ):
        return "host_key"
    if re.search(
        r"(?:^|\n)[^\r\n]+:\s*permission denied "
        r"\([^)]*publickey[^)]*\)\.?(?:\r?\n|$)",
        detail,
    ):
        return "authentication"
    if any(
        marker in detail
        for marker in (
            "connection timed out",
            "connection refused",
            "connection closed",
            "no route to host",
            "could not resolve hostname",
            "name or service not known",
        )
    ):
        return "transport"
    return "unknown"


def _verify_ssh_target(
    tx: Transaction,
    key_path: Path,
    known_hosts_data: bytes,
    user: str,
    host: str,
    port: int,
) -> None:
    """验证 SSH 公钥登录；远程命令同时兼容 Linux 和 Windows。"""
    verify_dir = Path(tempfile.mkdtemp(prefix="ssh-verify-", dir=tx.dir))
    known = verify_dir / "known_hosts"
    known.write_bytes(known_hosts_data)

    marker = "AIOPS_RUNNER_SSH_OK"
    command = [
        "ssh", "-p", str(port), "-i", str(key_path),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}",
        f"{user}@{host}",
        f"echo {marker}",
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise SSHVerificationError(
            "transport",
            f"SSH 免密验证超时：{user}@{host}:{port}",
        ) from exc
    stdout = _decode_process_output(result.stdout)
    stderr = _decode_process_output(result.stderr)
    if result.returncode != 0 or marker not in stdout:
        detail = stderr.strip() or stdout.strip() or f"ssh 退出码 {result.returncode}"
        diagnostics = "\n".join(part for part in (stderr, stdout) if part)
        raise SSHVerificationError(
            _ssh_error_kind(diagnostics),
            f"SSH 免密验证失败：{user}@{host}:{port}；{detail}",
        )


def _load_paramiko():
    try:
        import paramiko
    except ImportError as exc:
        raise ValueError(
            "自动配置 SSH 免密需要 Paramiko。请先执行："
            "python3 -m pip install paramiko"
        ) from exc
    return paramiko


def _scanned_key_pairs(scanned: bytes) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for line in scanned.decode("utf-8", errors="replace").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            pairs.add((parts[1], parts[2]))
    return pairs


def _open_password_client(
    host: str,
    port: int,
    user: str,
    password: str,
    scanned_host_keys: bytes,
):
    """先校验 ssh-keyscan 已确认的主机密钥，再发送密码认证。"""
    paramiko = _load_paramiko()
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=8)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = 8
        transport.auth_timeout = 8
        transport.start_client(timeout=8)
        remote_key = transport.get_remote_server_key()
        expected = _scanned_key_pairs(scanned_host_keys)
        actual = (remote_key.get_name(), remote_key.get_base64())
        if actual not in expected:
            raise ValueError("SSH 主机密钥与已确认的 ssh-keyscan 结果不一致")
        transport.auth_password(username=user, password=password)
        if not transport.is_authenticated():
            raise ValueError(f"SSH 密码认证失败：{user}@{host}:{port}")
        client = paramiko.SSHClient()
        client._transport = transport
        return client
    except paramiko.AuthenticationException as exc:
        raise ValueError(f"SSH 密码认证失败：{user}@{host}:{port}") from exc
    except paramiko.ssh_exception.NoValidConnectionsError as exc:
        raise ValueError(f"无法连接 SSH 服务：{host}:{port}；{exc}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ValueError(f"连接 SSH 服务超时：{host}:{port}") from exc
    except paramiko.SSHException as exc:
        raise ValueError(f"SSH 协议错误：{host}:{port}；{exc}") from exc
    except Exception:
        raise
    finally:
        if transport is not None and not transport.is_authenticated():
            transport.close()
        elif sock is not None and transport is None:
            sock.close()


def _run_remote_command(
    client,
    command: str,
    timeout: int = 20,
    *,
    input_data: str | bytes | None = None,
) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if input_data is not None:
        stdin.write(input_data)
        stdin.flush()
    stdin.close()
    out = stdout.read()
    err = stderr.read()
    return (
        stdout.channel.recv_exit_status(),
        _decode_process_output(out),
        _decode_process_output(err),
    )


def _run_remote_powershell(
    client,
    script: str,
    timeout: int = 30,
) -> tuple[int, str, str]:
    """用短 bootstrap 从 stdin 读取 Base64 脚本，规避长度和代码页限制。"""
    loader = (
        "$payload=[Console]::In.ReadToEnd();"
        "$inputScript=[Text.Encoding]::UTF8.GetString("
        "[Convert]::FromBase64String($payload));"
        "&([ScriptBlock]::Create($inputScript))"
    )
    encoded_loader = base64.b64encode(
        loader.encode("utf-16le")
    ).decode("ascii")
    command = (
        "powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded_loader}"
    )
    return _run_remote_command(
        client,
        command,
        timeout=timeout,
        input_data=base64.b64encode(script.encode("utf-8")),
    )


def _detect_remote_os(client) -> str:
    """只区分当前向导支持的 Windows OpenSSH 与 Linux/Unix shell。"""
    rc, out, _ = _run_remote_command(client, "cmd.exe /d /c ver")
    if rc == 0 and "windows" in out.lower():
        return "windows"

    rc, out, _ = _run_remote_command(client, "uname -s")
    if rc == 0 and out.strip():
        return "linux"

    rc, out, _ = _run_remote_command(
        client,
        'powershell.exe -NoProfile -NonInteractive -Command '
        '"[System.Environment]::OSVersion.Platform"',
    )
    if rc == 0 and "win32nt" in out.lower():
        return "windows"

    raise ValueError("无法识别目标系统；当前仅支持 Windows OpenSSH 和 Linux")


def _verify_password_login(
    host: str,
    port: int,
    user: str,
    password: str,
    scanned_host_keys: bytes,
) -> str:
    client = _open_password_client(
        host, port, user, password, scanned_host_keys
    )
    try:
        return _detect_remote_os(client)
    finally:
        client.close()


def _derive_public_key(key_source: Path) -> str:
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key_source)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(
            f"读取私钥公钥部分超时；请确认私钥无需交互式口令：{key_source}"
        ) from exc
    if result.returncode:
        detail = _decode_process_output(result.stderr).strip()
        raise ValueError(
            f"无法从私钥生成公钥：{key_source}"
            + (f"；{detail}" if detail else "")
        )
    fields = _decode_process_output(result.stdout).strip().split()
    if len(fields) < 2:
        raise ValueError("ssh-keygen 未返回有效公钥")
    return f"{fields[0]} {fields[1]} aiops-runner"


def _public_key_identity(public_key: str) -> str:
    fields = public_key.split()
    if len(fields) < 2:
        raise ValueError("公钥格式不正确")
    return f"{fields[0]} {fields[1]}"


def _parse_aiops_markers(output: str) -> dict[str, str]:
    markers: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("AIOPS_") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in markers:
            raise ValueError(
                f"公钥安装结果包含重复的 {key} 标记；"
                "远端状态不确定，请检查 authorized_keys"
            )
        markers[key] = value
    return markers


def _required_binary_marker(
    markers: dict[str, str],
    name: str,
    platform: str,
) -> bool:
    value = markers.get(name)
    if value not in {"0", "1"}:
        raise ValueError(
            f"{platform} 公钥安装结果缺少有效的 {name} 标记；"
            "远端状态不确定，请检查 authorized_keys"
        )
    return value == "1"


def _require_install_complete(
    markers: dict[str, str],
    platform: str,
) -> None:
    if not _required_binary_marker(
        markers, "AIOPS_INSTALL_COMPLETE", platform
    ):
        raise ValueError(
            f"{platform} 公钥安装未返回成功完成状态；"
            "远端状态不确定，请检查 authorized_keys"
        )


def _b64decode_text(value: str) -> str:
    if not value:
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return ""


def _b64decode_bytes(value: str) -> bytes | None:
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return None


def _linux_install_script(public_key: str) -> str:
    identity = _public_key_identity(public_key)
    return f"""
set -eu
ssh_dir="$HOME/.ssh"
auth="$ssh_dir/authorized_keys"
dir_existed=0
file_existed=0
identity={shlex.quote(identity)}
key={shlex.quote(public_key)}
added=0
permissions_changed=0
old_dir_mode=""
old_file_mode=""
file_had_final_newline=1
backup=""
backup_ready=0

rollback_on_error() {{
    status=$?
    trap - EXIT HUP INT TERM
    rollback_failed=0
    if [ "$status" -ne 0 ]; then
        if [ "$backup_ready" -eq 1 ]; then
            if [ -f "$backup" ]; then
                mv -f "$backup" "$auth" || rollback_failed=1
            else
                rollback_failed=1
            fi
        elif [ "$file_existed" -eq 0 ] && [ -f "$auth" ]; then
            rm -f "$auth" || rollback_failed=1
        fi
        if (
            [ "$dir_existed" -eq 1 ] &&
            [ -n "$old_dir_mode" ] &&
            [ -d "$ssh_dir" ]
        ); then
            chmod "$old_dir_mode" "$ssh_dir" || rollback_failed=1
        fi
        if [ "$dir_existed" -eq 0 ] && [ -d "$ssh_dir" ]; then
            rmdir "$ssh_dir" 2>/dev/null || rollback_failed=1
        fi
        if [ -n "$backup" ] && [ -f "$backup" ]; then
            rm -f "$backup" || rollback_failed=1
        fi
        if [ "$rollback_failed" -ne 0 ]; then
            printf '%s\\n' 'remote rollback incomplete' >&2
            exit 125
        fi
    fi
    exit "$status"
}}
trap rollback_on_error EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for required_command in awk base64 chmod id mktemp od sha256sum stat tail tr truncate; do
    command -v "$required_command" >/dev/null 2>&1 || {{
        printf 'missing required command: %s\\n' "$required_command" >&2
        exit 127
    }}
done

if [ -e "$ssh_dir" ] || [ -L "$ssh_dir" ]; then
    if [ -L "$ssh_dir" ] || [ ! -d "$ssh_dir" ]; then
        printf '%s\\n' '.ssh path is not a real directory' >&2
        exit 1
    fi
    dir_existed=1
    old_dir_mode=$(stat -c '%a' -- "$ssh_dir")
    dir_owner_uid=$(stat -c '%u' -- "$ssh_dir")
    if [ "$dir_owner_uid" != "$(id -u)" ]; then
        printf '%s\\n' '.ssh directory is not owned by the login user' >&2
        exit 1
    fi
fi

if [ -e "$auth" ] || [ -L "$auth" ]; then
    if [ -L "$auth" ] || [ ! -f "$auth" ]; then
        printf '%s\\n' 'authorized_keys path is not a real file' >&2
        exit 1
    fi
    file_existed=1
    old_file_mode=$(stat -c '%a' -- "$auth")
    file_owner_uid=$(stat -c '%u' -- "$auth")
    if [ "$file_owner_uid" != "$(id -u)" ]; then
        printf '%s\\n' 'authorized_keys is not owned by the login user' >&2
        exit 1
    fi
    if [ -s "$auth" ]; then
        last_octet=$(
            tail -c 1 -- "$auth" |
                od -An -t u1 |
                tr -d '[:space:]'
        )
        [ "$last_octet" = "10" ] || file_had_final_newline=0
    fi
fi

if [ "$file_existed" -eq 1 ]; then
    umask 077
    backup=$(mktemp "${{auth}}.aiops-runner-backup.XXXXXX")
    cp -p "$auth" "$backup"
    backup_ready=1
fi

if [ ! -d "$ssh_dir" ]; then
    umask 077
    mkdir -p "$ssh_dir"
fi
chmod 700 "$ssh_dir"
if [ ! -f "$auth" ]; then
    umask 077
    : > "$auth"
fi
chmod 600 "$auth"

if (
    [ "$dir_existed" -eq 1 ] &&
    [ "$old_dir_mode" != "700" ]
); then
    permissions_changed=1
fi
if (
    [ "$file_existed" -eq 1 ] &&
    [ "$old_file_mode" != "600" ]
); then
    permissions_changed=1
fi

if awk -v wanted="$identity" '
BEGIN {{ found = 0 }}
/^[[:space:]]*#/ {{ next }}
{{
    delete parts
    part_count = 0
    token = ""
    in_quote = 0
    escaped = 0
    for (char_index = 1; char_index <= length($0); char_index++) {{
        ch = substr($0, char_index, 1)
        if (escaped) {{
            token = token ch
            escaped = 0
        }} else if (in_quote && ch == "\\\\") {{
            token = token ch
            escaped = 1
        }} else if (ch == "\\\"") {{
            token = token ch
            in_quote = !in_quote
        }} else if (!in_quote && ch ~ /[[:space:]]/) {{
            if (length(token)) {{
                parts[++part_count] = token
                token = ""
            }}
        }} else {{
            token = token ch
        }}
    }}
    if (length(token)) {{
        parts[++part_count] = token
    }}
    for (i = 1; i < part_count; i++) {{
        if (parts[i] ~ /^(ssh-|ecdsa-|sk-|rsa-sha2-)/) {{
            candidate = parts[i] " " parts[i + 1]
            if (candidate == wanted) {{
                found = 1
                exit
            }}
            break
        }}
    }}
}}
END {{ exit(found ? 0 : 1) }}
' "$auth"; then
    added=0
else
    added=1
    if [ -s "$auth" ]; then
        last_octet=$(
            tail -c 1 -- "$auth" |
                od -An -t u1 |
                tr -d '[:space:]'
        )
        [ "$last_octet" = "10" ] || printf '\\n' >> "$auth"
    fi
    printf '%s\\n' "$key" >> "$auth"
fi

installed_sha256=$(sha256sum -- "$auth" | awk '{{ print $1 }}')
installed_file_mode=$(stat -c '%a' -- "$auth")
installed_dir_mode=$(stat -c '%a' -- "$ssh_dir")
key_path_b64=$(
    printf '%s' "$auth" |
        base64 |
        tr -d '\\r\\n'
)

printf 'AIOPS_KEY_ADDED=%s\\n' "$added"
printf 'AIOPS_PERMISSIONS_CHANGED=%s\\n' "$permissions_changed"
printf 'AIOPS_FILE_EXISTED=%s\\n' "$file_existed"
printf 'AIOPS_DIR_EXISTED=%s\\n' "$dir_existed"
printf 'AIOPS_FILE_HAD_FINAL_NEWLINE=%s\\n' "$file_had_final_newline"
printf 'AIOPS_OLD_FILE_MODE=%s\\n' "$old_file_mode"
printf 'AIOPS_OLD_DIR_MODE=%s\\n' "$old_dir_mode"
printf 'AIOPS_INSTALLED_SHA256=%s\\n' "$installed_sha256"
printf 'AIOPS_INSTALLED_FILE_MODE=%s\\n' "$installed_file_mode"
printf 'AIOPS_INSTALLED_DIR_MODE=%s\\n' "$installed_dir_mode"
printf 'AIOPS_KEY_PATH_B64=%s\\n' "$key_path_b64"
printf 'AIOPS_INSTALL_COMPLETE=1\\n'
if [ "$backup_ready" -eq 1 ]; then
    rm -f "$backup"
    backup_ready=0
fi
trap - EXIT HUP INT TERM
"""


def _install_linux_public_key(
    client,
    host_id: str,
    addr: str,
    user: str,
    port: int,
    password: str,
    public_key: str,
) -> RemoteKeyChange | None:
    script = _linux_install_script(public_key)
    command = f"sh -c {shlex.quote(script)}"
    rc, out, err = _run_remote_command(client, command)
    if rc != 0:
        raise ValueError(
            f"Linux 公钥安装失败：{user}@{addr}:{port}；"
            f"{err.strip() or out.strip() or f'退出码 {rc}'}"
        )
    markers = _parse_aiops_markers(out)
    _require_install_complete(markers, "Linux")
    key_added = _required_binary_marker(
        markers, "AIOPS_KEY_ADDED", "Linux"
    )
    permissions_changed = _required_binary_marker(
        markers, "AIOPS_PERMISSIONS_CHANGED", "Linux"
    )
    file_existed = _required_binary_marker(
        markers, "AIOPS_FILE_EXISTED", "Linux"
    )
    dir_existed = _required_binary_marker(
        markers, "AIOPS_DIR_EXISTED", "Linux"
    )
    had_final_newline = _required_binary_marker(
        markers, "AIOPS_FILE_HAD_FINAL_NEWLINE", "Linux"
    )
    remote_path = _b64decode_text(
        markers.get("AIOPS_KEY_PATH_B64", "")
    )
    if not remote_path:
        raise ValueError(
            "Linux 公钥安装结果缺少有效的 authorized_keys 路径；"
            "远端状态不确定，请检查 authorized_keys"
        )
    original_file_mode = markers.get("AIOPS_OLD_FILE_MODE", "").strip()
    original_dir_mode = markers.get("AIOPS_OLD_DIR_MODE", "").strip()
    if file_existed and not re.fullmatch(
        r"[0-7]{3,4}", original_file_mode
    ):
        raise ValueError(
            "Linux 公钥安装结果缺少原 authorized_keys 权限；"
            "远端状态不确定，请检查 authorized_keys"
        )
    if dir_existed and not re.fullmatch(r"[0-7]{3,4}", original_dir_mode):
        raise ValueError(
            "Linux 公钥安装结果缺少原 .ssh 权限；"
            "远端状态不确定，请检查 authorized_keys"
        )
    installed_hash = markers.get("AIOPS_INSTALLED_SHA256", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", installed_hash):
        raise ValueError(
            "Linux 公钥安装结果缺少有效的安装后内容摘要；"
            "远端状态不确定，请检查 authorized_keys"
        )
    installed_file_mode = markers.get(
        "AIOPS_INSTALLED_FILE_MODE", ""
    ).strip()
    installed_dir_mode = markers.get(
        "AIOPS_INSTALLED_DIR_MODE", ""
    ).strip()
    if installed_file_mode != "600" or installed_dir_mode != "700":
        raise ValueError(
            "Linux 公钥安装后 SSH 权限校验失败；"
            "远端状态不确定，请检查 authorized_keys"
        )
    if not key_added and not permissions_changed:
        print(f"公钥已存在且权限正确：{user}@{addr}:{port}")
        return None
    if not key_added:
        print(f"公钥已存在，已修复权限：{user}@{addr}:{port}")
    return RemoteKeyChange(
        host_id=host_id,
        addr=addr,
        user=user,
        port=port,
        password=password,
        os_type="linux",
        public_key=public_key,
        remote_path=remote_path,
        file_existed=file_existed,
        dir_existed=dir_existed,
        key_added=key_added,
        permissions_changed=permissions_changed,
        original_file_mode=original_file_mode,
        original_dir_mode=original_dir_mode,
        original_had_final_newline=had_final_newline,
        installed_file_sha256=installed_hash,
        installed_file_mode=installed_file_mode,
        installed_dir_mode=installed_dir_mode,
    )


def _windows_authorized_key_tokenizer_script() -> str:
    """返回按 authorized_keys 引号规则拆分字段的 PowerShell 函数。"""
    return r"""
function Get-AuthorizedKeyTokens([string]$Line) {
    $tokens = New-Object 'System.Collections.Generic.List[string]'
    $token = New-Object System.Text.StringBuilder
    $inQuote = $false
    $escaped = $false
    foreach ($character in $Line.ToCharArray()) {
        if ($escaped) {
            [void]$token.Append($character)
            $escaped = $false
        } elseif ($inQuote -and [int]$character -eq 92) {
            [void]$token.Append($character)
            $escaped = $true
        } elseif ([int]$character -eq 34) {
            [void]$token.Append($character)
            $inQuote = -not $inQuote
        } elseif (-not $inQuote -and [char]::IsWhiteSpace($character)) {
            if ($token.Length -gt 0) {
                $tokens.Add($token.ToString())
                [void]$token.Clear()
            }
        } else {
            [void]$token.Append($character)
        }
    }
    if ($token.Length -gt 0) {
        $tokens.Add($token.ToString())
    }
    return $tokens.ToArray()
}
"""


def _windows_install_script(public_key: str) -> str:
    key = public_key.replace("'", "''")
    identity = _public_key_identity(public_key).replace("'", "''")
    tokenizer = _windows_authorized_key_tokenizer_script()
    return rf"""
$ErrorActionPreference = 'Stop'
$key = '{key}'
$identity = '{identity}'
{tokenizer}
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$systemSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
$adminsSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
$isAdmin = @(
    $current.Groups | Where-Object {{ $_.Value -eq $adminsSid.Value }}
).Count -ne 0

$configPath = Join-Path $env:ProgramData 'ssh\sshd_config'
$useAdminFile = $false
if ($isAdmin) {{
    if (Test-Path -LiteralPath $configPath) {{
        $configText = Get-Content -LiteralPath $configPath -Raw
        if (
            $configText -match '(?im)^\s*Match\s+Group\s+administrators\b' -and
            $configText -match '(?im)^\s*AuthorizedKeysFile\s+.*administrators_authorized_keys'
        ) {{
            $useAdminFile = $true
        }}
    }} else {{
        $useAdminFile = $true
    }}
}}
if ($useAdminFile) {{
    $path = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $ownerSid = $adminsSid
    $allowedSids = @($adminsSid, $systemSid)
}} else {{
    $path = Join-Path $env:USERPROFILE '.ssh\authorized_keys'
    $ownerSid = $current.User
    $allowedSids = @($current.User, $systemSid, $adminsSid)
}}

$dir = Split-Path -Parent $path
$dirExisted = Test-Path -LiteralPath $dir
$fileExisted = Test-Path -LiteralPath $path
$oldSddl = ''
$oldBytes = $null
if ($fileExisted) {{
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {{
        throw "authorized_keys path is not a file: $path"
    }}
    $oldBytes = [System.IO.File]::ReadAllBytes($path)
    $oldSddl = (
        New-Object -TypeName System.IO.FileInfo -ArgumentList $path
    ).GetAccessControl().Sddl
}}

$added = 0
$aclChanged = 0
try {{
    if ($dirExisted -and -not (Test-Path -LiteralPath $dir -PathType Container)) {{
        throw "SSH directory path is not a directory: $dir"
    }}
    if (-not $dirExisted) {{
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }}
    if (-not $fileExisted) {{
        New-Item -ItemType File -Path $path -Force | Out-Null
    }}

    $exists = $false
    foreach ($line in @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)) {{
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {{
            continue
        }}
        $parts = @(Get-AuthorizedKeyTokens $trimmed)
        for ($index = 0; $index -lt ($parts.Count - 1); $index++) {{
            if ($parts[$index] -match '^(ssh-|ecdsa-|sk-|rsa-sha2-)') {{
                if (
                    "$($parts[$index]) $($parts[$index + 1])" -eq
                    $identity
                ) {{
                    $exists = $true
                }}
                break
            }}
        }}
        if ($exists) {{
            break
        }}
    }}

    $acl = New-Object -TypeName System.Security.AccessControl.FileSecurity
    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $allowedSids) {{
        $rule = New-Object `
            -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList @(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        [void]$acl.AddAccessRule($rule)
    }}
    $fileInfo = New-Object -TypeName System.IO.FileInfo -ArgumentList $path
    $fileInfo.SetAccessControl($acl)

    $actual = $fileInfo.GetAccessControl()
    $actualOwner = $actual.GetOwner(
        [System.Security.Principal.SecurityIdentifier]
    )
    if ($actualOwner.Value -ne $ownerSid.Value) {{
        throw "authorized_keys owner verification failed"
    }}
    if (-not $actual.AreAccessRulesProtected) {{
        throw "authorized_keys ACL still inherits permissions"
    }}
    $allowedValues = @($allowedSids | ForEach-Object {{ $_.Value }})
    $unexpected = @(
        $actual.Access | Where-Object {{
            $_.AccessControlType -ne 'Allow' -or
            $allowedValues -notcontains $_.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }}
    )
    if ($unexpected.Count -ne 0) {{
        throw "authorized_keys ACL grants an unexpected identity"
    }}
    $aclChanged = [int]($oldSddl -ne $actual.Sddl)

    if (-not $exists) {{
        $added = 1
        $currentBytes = [System.IO.File]::ReadAllBytes($path)
        $separator = ''
        if (
            $currentBytes.Length -gt 0 -and
            $currentBytes[$currentBytes.Length - 1] -ne 10
        ) {{
            if ($currentBytes[$currentBytes.Length - 1] -eq 13) {{
                $separator = "`n"
            }} else {{
                $separator = "`r`n"
            }}
        }}
        [System.IO.File]::AppendAllText(
            $path,
            $separator + $key + "`r`n",
            [Text.Encoding]::ASCII
        )
    }}
    $installedAclSddl = $fileInfo.GetAccessControl().Sddl
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {{
        $installedHash = (
            [BitConverter]::ToString(
                $hasher.ComputeHash(
                    [System.IO.File]::ReadAllBytes($path)
                )
            )
        ).Replace('-', '').ToLowerInvariant()
    }} finally {{
        $hasher.Dispose()
    }}
}} catch {{
    $installError = $_.Exception.Message
    $restoreErrors = @()
    if ($fileExisted) {{
        try {{
            [System.IO.File]::WriteAllBytes($path, $oldBytes)
        }} catch {{
            $restoreErrors += "content: $($_.Exception.Message)"
        }}
        if ($oldSddl) {{
            try {{
                $restoreFile = New-Object -TypeName System.IO.FileInfo -ArgumentList $path
                $restoreAcl = $restoreFile.GetAccessControl()
                $restoreAcl.SetSecurityDescriptorSddlForm($oldSddl)
                $restoreFile.SetAccessControl($restoreAcl)
            }} catch {{
                $restoreErrors += "ACL: $($_.Exception.Message)"
            }}
        }}
    }} elseif (Test-Path -LiteralPath $path) {{
        try {{
            Remove-Item -LiteralPath $path -Force
        }} catch {{
            $restoreErrors += "new file: $($_.Exception.Message)"
        }}
    }}
    if (-not $dirExisted -and (Test-Path -LiteralPath $dir -PathType Container)) {{
        try {{
            if (@(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) {{
                Remove-Item -LiteralPath $dir -Force
            }}
        }} catch {{
            $restoreErrors += "new directory: $($_.Exception.Message)"
        }}
    }}
    if ($restoreErrors.Count -ne 0) {{
        throw "$installError; remote rollback incomplete: $($restoreErrors -join '; ')"
    }}
    throw
}}

function To-B64([string]$value) {{
    if ($null -eq $value) {{ return '' }}
    return [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($value)
    )
}}
function Bytes-To-B64([byte[]]$value) {{
    if ($null -eq $value) {{ return '' }}
    return [Convert]::ToBase64String($value)
}}

Write-Output "AIOPS_KEY_ADDED=$added"
Write-Output "AIOPS_ACL_CHANGED=$aclChanged"
Write-Output "AIOPS_FILE_EXISTED=$([int]$fileExisted)"
Write-Output "AIOPS_DIR_EXISTED=$([int]$dirExisted)"
Write-Output "AIOPS_KEY_PATH_B64=$(To-B64 $path)"
Write-Output "AIOPS_OLD_SDDL_B64=$(To-B64 $oldSddl)"
Write-Output "AIOPS_OLD_CONTENT_B64=$(Bytes-To-B64 $oldBytes)"
Write-Output "AIOPS_INSTALLED_SHA256=$installedHash"
Write-Output "AIOPS_INSTALLED_SDDL_B64=$(To-B64 $installedAclSddl)"
Write-Output "AIOPS_INSTALL_COMPLETE=1"
"""


def _install_windows_public_key(
    client,
    host_id: str,
    addr: str,
    user: str,
    port: int,
    password: str,
    public_key: str,
) -> RemoteKeyChange | None:
    rc, out, err = _run_remote_powershell(
        client, _windows_install_script(public_key), timeout=30
    )
    if rc != 0:
        raise ValueError(
            f"Windows 公钥安装失败：{user}@{addr}:{port}；"
            f"{err.strip() or out.strip() or f'退出码 {rc}'}"
        )
    markers = _parse_aiops_markers(out)
    _require_install_complete(markers, "Windows")
    key_added = _required_binary_marker(
        markers, "AIOPS_KEY_ADDED", "Windows"
    )
    acl_changed = _required_binary_marker(
        markers, "AIOPS_ACL_CHANGED", "Windows"
    )
    file_existed = _required_binary_marker(
        markers, "AIOPS_FILE_EXISTED", "Windows"
    )
    dir_existed = _required_binary_marker(
        markers, "AIOPS_DIR_EXISTED", "Windows"
    )
    remote_path = _b64decode_text(
        markers.get("AIOPS_KEY_PATH_B64", "")
    )
    if not remote_path:
        raise ValueError(
            "Windows 公钥安装结果缺少有效的 authorized_keys 路径；"
            "远端状态不确定，请人工检查"
        )
    original_acl = _b64decode_text(
        markers.get("AIOPS_OLD_SDDL_B64", "")
    )
    if file_existed and not original_acl:
        raise ValueError(
            "Windows 公钥已写入，但缺少原 authorized_keys ACL；"
            "远端状态不确定，请人工检查"
        )
    if "AIOPS_OLD_CONTENT_B64" not in markers:
        raise ValueError(
            "Windows 公钥安装结果缺少原 authorized_keys 内容；"
            "远端状态不确定，请人工检查"
        )
    original_content = _b64decode_bytes(
        markers["AIOPS_OLD_CONTENT_B64"]
    )
    if original_content is None:
        raise ValueError(
            "Windows 公钥安装结果中的原 authorized_keys 内容无效；"
            "远端状态不确定，请人工检查"
        )
    installed_hash = markers.get("AIOPS_INSTALLED_SHA256", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", installed_hash):
        raise ValueError(
            "Windows 公钥安装结果缺少有效的安装后内容摘要；"
            "远端状态不确定，请人工检查"
        )
    installed_acl = _b64decode_text(
        markers.get("AIOPS_INSTALLED_SDDL_B64", "")
    )
    if not installed_acl:
        raise ValueError(
            "Windows 公钥安装结果缺少安装后 ACL；"
            "远端状态不确定，请人工检查"
        )
    if not key_added and not acl_changed:
        print(f"公钥已存在且 ACL 正确：{user}@{addr}:{port}")
        return None
    if not key_added:
        print(f"公钥已存在，已修复 ACL：{user}@{addr}:{port}")
    return RemoteKeyChange(
        host_id=host_id,
        addr=addr,
        user=user,
        port=port,
        password=password,
        os_type="windows",
        public_key=public_key,
        remote_path=remote_path,
        file_existed=file_existed,
        dir_existed=dir_existed,
        original_acl_sddl=original_acl,
        original_file_data=original_content,
        key_added=key_added,
        acl_changed=acl_changed,
        installed_file_sha256=installed_hash,
        installed_acl_sddl=installed_acl,
    )


def _install_remote_public_key(
    credential: PendingSSHCredential,
    public_key: str,
    state: WizardState | None = None,
) -> RemoteKeyChange | None:
    client = _open_password_client(
        credential.addr,
        credential.port,
        credential.user,
        credential.password,
        credential.scanned_host_keys,
    )
    try:
        os_type = _detect_remote_os(client)
        if os_type == "windows":
            if state is not None:
                state.remote_operation_inflight = True
            change = _install_windows_public_key(
                client,
                credential.host_id,
                credential.addr,
                credential.user,
                credential.port,
                credential.password,
                public_key,
            )
        elif os_type == "linux":
            if state is not None:
                state.remote_operation_inflight = True
            change = _install_linux_public_key(
                client,
                credential.host_id,
                credential.addr,
                credential.user,
                credential.port,
                credential.password,
                public_key,
            )
        else:
            raise ValueError(f"不支持的目标系统：{os_type}")
        if change is not None:
            change.scanned_host_keys = credential.scanned_host_keys
            if state is not None:
                state.remote_changes.append(change)
        if state is not None:
            state.remote_operation_inflight = False
        return change
    finally:
        client.close()


def _linux_rollback_script(change: RemoteKeyChange) -> str:
    file_existed = 1 if change.file_existed else 0
    dir_existed = 1 if change.dir_existed else 0
    key_added = 1 if change.key_added else 0
    had_final_newline = 1 if change.original_had_final_newline else 0
    return f"""
set -eu
auth={shlex.quote(change.remote_path)}
key={shlex.quote(change.public_key)}
expected_sha256={shlex.quote(change.installed_file_sha256)}
installed_file_mode={shlex.quote(change.installed_file_mode)}
installed_dir_mode={shlex.quote(change.installed_dir_mode)}
old_file_mode={shlex.quote(change.original_file_mode)}
old_dir_mode={shlex.quote(change.original_dir_mode)}
file_existed={file_existed}
dir_existed={dir_existed}
key_added={key_added}
had_final_newline={had_final_newline}
dir=$(dirname "$auth")
backup=""
backup_ready=0
output=""

rollback_on_error() {{
    status=$?
    trap - EXIT HUP INT TERM
    rollback_failed=0
    if [ "$status" -ne 0 ] && [ "$backup_ready" -eq 1 ]; then
        if [ -f "$backup" ]; then
            chmod "$installed_dir_mode" "$dir" || rollback_failed=1
            cp -p "$backup" "$auth" || rollback_failed=1
            chmod "$installed_file_mode" "$auth" || rollback_failed=1
        else
            rollback_failed=1
        fi
    fi
    [ -z "$output" ] || rm -f "$output" || rollback_failed=1
    [ -z "$backup" ] || rm -f "$backup" || rollback_failed=1
    if [ "$rollback_failed" -ne 0 ]; then
        printf '%s\\n' 'remote rollback recovery incomplete' >&2
        exit 125
    fi
    exit "$status"
}}
trap rollback_on_error EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -L "$auth" ] || [ ! -f "$auth" ]; then
    printf '%s\\n' 'authorized_keys missing or no longer a real file' >&2
    exit 1
fi
if [ -L "$dir" ] || [ ! -d "$dir" ]; then
    printf '%s\\n' '.ssh directory missing or no longer a real directory' >&2
    exit 1
fi

assert_installed_state() {{
    current_sha256=$(sha256sum -- "$auth" | awk '{{ print $1 }}')
    current_file_mode=$(stat -c '%a' -- "$auth")
    current_dir_mode=$(stat -c '%a' -- "$dir")
    if (
        [ "$current_sha256" != "$expected_sha256" ] ||
        [ "$current_file_mode" != "$installed_file_mode" ] ||
        [ "$current_dir_mode" != "$installed_dir_mode" ]
    ); then
        printf '%s\\n' \
            'authorized_keys changed after installation; refusing unsafe rollback' \
            >&2
        exit 1
    fi
}}
assert_installed_state

umask 077
backup=$(mktemp "${{TMPDIR:-/tmp}}/aiops-runner-key-rollback.XXXXXX")
cp -p "$auth" "$backup"
backup_ready=1

if [ "$key_added" -eq 1 ]; then
    output=$(mktemp "${{auth}}.aiops-runner-rollback-output.XXXXXX")
    if ! awk -v key="$key" '
BEGIN {{ removed = 0 }}
$0 == key {{ removed++; next }}
{{ print }}
END {{ exit(removed == 1 ? 0 : 1) }}
' "$auth" > "$output"; then
        printf '%s\\n' 'installed public key was not found exactly once' >&2
        exit 1
    fi
    if (
        [ "$file_existed" -eq 1 ] &&
        [ "$had_final_newline" -eq 0 ] &&
        [ -s "$output" ]
    ); then
        truncate -s -1 -- "$output"
    fi
fi

# 生成恢复候选期间仍可能有并发写；实际切换前再核对一次。
assert_installed_state

if [ "$key_added" -eq 1 ]; then
    if [ "$file_existed" -eq 1 ]; then
        chmod "$old_file_mode" "$output"
        mv -f "$output" "$auth"
        output=""
    else
        if [ -s "$output" ]; then
            printf '%s\\n' 'new authorized_keys contains unexpected data' >&2
            exit 1
        fi
        rm -f "$output"
        output=""
        rm -f "$auth"
    fi
elif [ "$file_existed" -eq 1 ]; then
    chmod "$old_file_mode" "$auth"
fi

if [ "$dir_existed" -eq 1 ]; then
    chmod "$old_dir_mode" "$dir"
fi

rm -f "$backup"
backup=""
backup_ready=0
if [ "$dir_existed" -eq 0 ] && [ -d "$dir" ]; then
    # 并发进程若已在新目录中写入其它文件，保留目录而不扩大回滚范围。
    rmdir "$dir" 2>/dev/null || true
fi
trap - EXIT HUP INT TERM
"""


def _rollback_linux_key(change: RemoteKeyChange, client) -> None:
    script = _linux_rollback_script(change)
    rc, out, err = _run_remote_command(
        client, f"sh -c {shlex.quote(script)}"
    )
    if rc != 0:
        raise ValueError(err.strip() or out.strip() or f"退出码 {rc}")


def _windows_rollback_script(change: RemoteKeyChange) -> str:
    path_b64 = base64.b64encode(
        change.remote_path.encode("utf-8")
    ).decode("ascii")
    old_sddl = change.original_acl_sddl.replace("'", "''")
    installed_sddl = change.installed_acl_sddl.replace("'", "''")
    installed_hash = change.installed_file_sha256
    file_existed = "$true" if change.file_existed else "$false"
    dir_existed = "$true" if change.dir_existed else "$false"
    key_added = "$true" if change.key_added else "$false"
    old_content_b64 = base64.b64encode(
        change.original_file_data
    ).decode("ascii")
    return rf"""
$ErrorActionPreference = 'Stop'
$path = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('{path_b64}')
)
$fileExisted = {file_existed}
$dirExisted = {dir_existed}
$keyAdded = {key_added}
$oldSddl = '{old_sddl}'
$oldContentB64 = '{old_content_b64}'
$installedSddl = '{installed_sddl}'
$installedHash = '{installed_hash}'

if ($fileExisted -and -not (Test-Path -LiteralPath $path -PathType Leaf)) {{
    throw "cannot restore missing authorized_keys file: $path"
}}
if (Test-Path -LiteralPath $path) {{
    $fileInfo = New-Object -TypeName System.IO.FileInfo -ArgumentList $path
    $currentAcl = $fileInfo.GetAccessControl().Sddl
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {{
        $currentHash = (
            [BitConverter]::ToString(
                $hasher.ComputeHash(
                    [System.IO.File]::ReadAllBytes($path)
                )
            )
        ).Replace('-', '').ToLowerInvariant()
    }} finally {{
        $hasher.Dispose()
    }}
    if ($currentHash -ne $installedHash -or $currentAcl -ne $installedSddl) {{
        throw "authorized_keys changed after installation; refusing unsafe rollback"
    }}

    if ($keyAdded) {{
        if ($fileExisted) {{
            [System.IO.File]::WriteAllBytes(
                $path,
                [Convert]::FromBase64String($oldContentB64)
            )
        }} else {{
            Remove-Item -LiteralPath $path -Force
        }}
    }}

    if ($fileExisted -and $oldSddl) {{
        $acl = $fileInfo.GetAccessControl()
        $acl.SetSecurityDescriptorSddlForm($oldSddl)
        $fileInfo.SetAccessControl($acl)
    }}
}}

$dir = Split-Path -Parent $path
if (-not $dirExisted -and (Test-Path -LiteralPath $dir)) {{
    $children = @(Get-ChildItem -LiteralPath $dir -Force)
    if ($children.Count -eq 0) {{
        Remove-Item -LiteralPath $dir -Force
    }}
}}
"""


def _rollback_remote_key_change(change: RemoteKeyChange) -> None:
    client = _open_password_client(
        change.addr,
        change.port,
        change.user,
        change.password,
        change.scanned_host_keys,
    )
    try:
        if change.os_type == "windows":
            rc, out, err = _run_remote_powershell(
                client, _windows_rollback_script(change), timeout=30
            )
            if rc != 0:
                raise ValueError(
                    err.strip() or out.strip() or f"退出码 {rc}"
                )
        else:
            _rollback_linux_key(change, client)
    finally:
        client.close()


def _apply_pending_remote_setups(
    tx: Transaction,
    state: WizardState,
) -> None:
    """最终确认后安装远程公钥，并逐台执行私钥登录复验。"""
    if not state.pending_setups:
        return
    if state.key_source is None:
        raise ValueError("缺少用于 SSH 复验的本地私钥路径")
    if state.key_target is None:
        raise ValueError("缺少待提交的 runner SSH 私钥目标")
    prepared_key = tx.prepared.get(state.key_target)
    if prepared_key is None or not prepared_key.is_file():
        raise ValueError("runner SSH 私钥候选尚未完成安全预检")
    try:
        current_key_data = state.key_source.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"SSH 私钥在确认后已不可用：{state.key_source}"
        ) from exc
    if (
        not state.key_source_sha256
        or hashlib.sha256(current_key_data).hexdigest()
        != state.key_source_sha256
    ):
        raise ValueError(
            f"SSH 私钥在确认后发生变化，拒绝继续：{state.key_source}"
        )
    if _public_key_identity(_derive_public_key(prepared_key)) != (
        _public_key_identity(state.public_key)
    ):
        raise ValueError(
            f"待提交私钥与已确认的公钥不一致，拒绝继续：{prepared_key}"
        )
    print("\n正在配置远程 SSH 免密登录：")
    for host_id in state.pending_setups:
        credential = state.credentials.get(host_id)
        if credential is None:
            raise ValueError(f"缺少资产 {host_id} 的临时 SSH 凭据")
        print(
            f"  配置 {credential.user}@{credential.addr}:"
            f"{credential.port} [{credential.os_type}]"
        )
        _install_remote_public_key(
            credential, state.public_key, state
        )
        _verify_ssh_target(
            tx,
            prepared_key,
            state.known_hosts_data,
            credential.user,
            credential.addr,
            credential.port,
        )
        print(
            f"  免密登录验证成功：{credential.user}@"
            f"{credential.addr}:{credential.port}"
        )
def _rollback_remote_changes(state: WizardState) -> list[str]:
    if not state.remote_changes:
        return []
    print("正在回滚本次已安装的远程 SSH 公钥……")
    failures: list[str] = []
    unresolved: list[RemoteKeyChange] = []
    for change in reversed(state.remote_changes):
        try:
            _rollback_remote_key_change(change)
            print(
                f"  已回滚 {change.user}@{change.addr}:{change.port}"
            )
        except BaseException as exc:
            target = f"{change.user}@{change.addr}:{change.port}"
            detail = str(exc) or type(exc).__name__
            failures.append(f"{target}: {detail}")
            unresolved.append(change)
            print(
                f"  警告：无法回滚 {target}：{detail}",
                file=sys.stderr,
            )
    state.remote_changes = list(reversed(unresolved))
    return failures


def _expected_known_host_field(host: str, port: int) -> str:
    """返回 OpenSSH known_hosts 中目标对应的主机字段。"""
    return host if port == 22 else f"[{host}]:{port}"


def _credential_for_host(
    state: WizardState,
    host: dict,
) -> PendingSSHCredential | None:
    return state.credentials.get(str(host.get("id", "")))


def _prompt_password_for_host(
    host_id: str,
    addr: str,
    user: str,
    port: int,
    scanned: bytes,
) -> PendingSSHCredential:
    while True:
        password = getpass.getpass(
            "SSH 密码（仅本次使用，不写入配置） "
            f"[{user}@{addr}:{port}]: "
        )
        if not password:
            print("SSH 密码不能为空。")
            continue
        try:
            os_type = _verify_password_login(
                addr, port, user, password, scanned
            )
        except Exception as exc:
            password = ""
            print(f"密码登录验证失败：{exc}")
            if choose("重试密码登录或取消本次配置", "r/q") == "q":
                raise Cancelled
            continue
        print(
            f"密码登录验证成功：{user}@{addr}:{port}，"
            f"目标系统={os_type}"
        )
        return PendingSSHCredential(
            host_id=host_id,
            addr=addr,
            user=user,
            port=port,
            password=password,
            os_type=os_type,
            scanned_host_keys=scanned,
        )


def configure_connection(tx: Transaction, state: WizardState) -> None:
    """配置共享私钥，并为 inventory 中每台资产安装、验证 SSH 公钥。"""
    path = CONFIG / "connection.local.yaml"
    inventory_path = CONFIG / "inventory.local.yaml"
    key_target = CONFIG / "keys" / "runner_target_ed25519"
    known_target = CONFIG / "keys" / "known_hosts"

    while True:
        mode = action(path.name, tx.read(path) is not None)
        if mode == "s" and state.ssh_inventory_changed:
            print(
                "资产的 SSH 目标已变化，必须同步更新并验证 runner connection 配置；"
                "可选择修改、覆盖重建或取消。"
            )
            continue
        break
    if mode == "q":
        raise Cancelled
    if mode == "s":
        return

    old = load_yaml(tx.read(path), path.name) if mode == "m" else {}
    for command in ("ssh-keyscan", "ssh-keygen", "ssh"):
        if shutil.which(command) is None:
            raise ValueError(f"缺少 {command}")

    inventory = load_yaml(tx.read(inventory_path), inventory_path.name)
    hosts = inventory.get("hosts", [])
    if not isinstance(hosts, list):
        raise ValueError("inventory.local.yaml 的 hosts 必须是列表")
    if not hosts:
        raise ValueError("请先在资产配置中至少添加一台主机")

    seen_ids: set[str] = set()
    seen_addrs: set[str] = set()
    for host in hosts:
        if not isinstance(host, dict):
            raise ValueError("inventory.local.yaml 存在无效主机项")
        host_id = str(host.get("id", "")).strip()
        addr = str(host.get("addr", "")).strip()
        if not host_id or host_id in seen_ids:
            raise ValueError(f"资产 ID 缺失或重复：{host_id or '-'}")
        if not addr or addr in seen_addrs:
            raise ValueError(f"资产地址缺失或重复：{addr or '-'}")
        seen_ids.add(host_id)
        seen_addrs.add(addr)
        if not str(host.get("ssh_user", "")).strip():
            raise ValueError(
                f"资产 {host.get('id', '-')} 缺少 ssh_user"
            )
        port = int(host.get("ssh_port") or 22)
        if not 1 <= port <= 65535:
            raise ValueError(
                f"资产 {host.get('id', '-')} 的 SSH 端口无效"
            )

    existing_key_data = tx.read(key_target)
    if mode == "m" and existing_key_data is not None:
        key_mode = choose(
            "SSH 私钥：普通修改复用现有密钥，或显式改用新私钥",
            "r/k/q",
        )
        if key_mode == "q":
            raise Cancelled
        if key_mode == "r":
            key_source = key_target.resolve()
        else:
            key_source = Path(
                required("新的 SSH 私钥路径", "~/.ssh/id_ed25519")
            ).expanduser().resolve()
    else:
        key_source = Path(
            required("已有 SSH 私钥路径", "~/.ssh/id_ed25519")
        ).expanduser().resolve()
    if not key_source.is_file():
        raise ValueError(f"找不到 SSH 私钥：{key_source}")
    if key_source == key_target.resolve():
        key_data = tx.read(key_target)
        if key_data is None:
            raise ValueError(f"找不到 SSH 私钥：{key_target}")
    else:
        key_data = key_source.read_bytes()
    key_probe, public_key = _materialize_private_key_probe(tx, key_data)
    if existing_key_data:
        _, existing_public_key = _materialize_private_key_probe(
            tx, existing_key_data
        )
        if _public_key_identity(existing_public_key) != (
            _public_key_identity(public_key)
        ):
            print(
                "警告：本次只会改用并安装新公钥，不会自动删除各远端"
                " authorized_keys 中的旧公钥。"
            )
            if not confirm(
                "确认继续，并在成功后按安全流程人工撤销旧公钥"
            ):
                raise Cancelled
            state.old_remote_key_requires_manual_removal = True

    entries, extras = (
        _parse_known_hosts(tx.read(known_target))
        if mode == "m"
        else ([], [])
    )

    print("\n准备配置 SSH 免密的资产：")
    for index, host in enumerate(hosts, 1):
        print(
            f"  {index}. {host.get('ssh_user')}@{host.get('addr')}:"
            f"{host.get('ssh_port', 22)} [{host.get('id')}]"
        )

    for host in hosts:
        host_id = str(host.get("id", ""))
        addr = str(host.get("addr", ""))
        user = str(host.get("ssh_user", ""))
        port = int(host.get("ssh_port") or 22)
        if not HOST_ADDR.fullmatch(addr):
            raise ValueError(f"资产地址格式不正确：{addr}")

        credential = _credential_for_host(state, host)
        if credential is not None:
            scanned = credential.scanned_host_keys
        else:
            scanned = _scan_host_key(addr, port)

        scanned_entries, _ = _parse_known_hosts(scanned)
        if not scanned_entries:
            raise ValueError(
                f"ssh-keyscan 未返回可识别的 host key：{addr}:{port}"
            )

        expected = _expected_known_host_field(addr, port)
        trusted_entries = [
            entry for entry in entries
            if str(entry["host_field"]) == expected
        ]
        trusted_data = _known_hosts_bytes(trusted_entries, [])
        trusted_pairs = _scanned_key_pairs(trusted_data)
        scanned_pairs = _scanned_key_pairs(scanned)
        if trusted_pairs and trusted_pairs == scanned_pairs:
            print(
                f"\nSSH host key 与现有 known_hosts 匹配：{addr}:{port}"
            )
        elif trusted_pairs:
            print(f"\n警告：{addr}:{port} 的 SSH host key 已变化。")
            print("已信任的旧指纹：")
            _show_host_fingerprints(trusted_data)
            print("本次扫描的新指纹：")
            _show_host_fingerprints(scanned)
            if not confirm("已通过可信渠道确认此次 host key 轮换"):
                raise Cancelled
        else:
            print(f"\n首次检测到 {addr}:{port} 的 SSH host key 指纹：")
            _show_host_fingerprints(scanned)
            if not confirm("已通过可信渠道核对指纹"):
                raise Cancelled

        new_fields = {
            str(item["host_field"]) for item in scanned_entries
        }
        entries = [
            entry for entry in entries
            if str(entry["host_field"]) != expected
            and str(entry["host_field"]) not in new_fields
        ]
        candidate_entries = entries + scanned_entries
        candidate_data = _known_hosts_bytes(candidate_entries, extras)

        if credential is None:
            try:
                _verify_ssh_target(
                    tx, key_probe, candidate_data, user, addr, port
                )
                print(f"现有免密登录可用：{user}@{addr}:{port}")
                entries = candidate_entries
                continue
            except SSHVerificationError as exc:
                print(f"现有免密登录不可用：{exc}")
                if exc.kind != "authentication":
                    raise
                credential = _prompt_password_for_host(
                    host_id, addr, user, port, scanned
                )
                state.credentials[host_id] = credential

        if host_id not in state.pending_setups:
            state.pending_setups.append(host_id)
        print(
            f"已准备自动配置免密登录：{user}@{addr}:{port} "
            f"[{credential.os_type}]"
        )
        entries = candidate_entries

    managed_fields = {
        _expected_known_host_field(
            str(host.get("addr", "")),
            int(host.get("ssh_port") or 22),
        )
        for host in hosts
    }
    entries = [
        entry for entry in entries
        if str(entry["host_field"]) in managed_fields
    ]

    known_data = _known_hosts_bytes(entries, extras)
    state.key_source = key_source
    state.key_source_sha256 = hashlib.sha256(key_data).hexdigest()
    state.key_target = key_target
    state.known_hosts_data = known_data
    state.public_key = public_key
    tx.stage_private_key(key_target, key_data)
    tx.stage_bytes(known_target, known_data, 0o600)

    # 保留全局 ssh_user 作为旧版配置加载器的兼容字段；
    # 实际目标账号由 inventory 中每台资产的 ssh_user/ssh_port 决定。
    fallback_user = str(hosts[0]["ssh_user"])
    updated_connection = dict(old)
    updated_connection.update({
        "ssh_user": fallback_user,
        "ssh_key_path": "keys/runner_target_ed25519",
        "known_hosts_path": "keys/known_hosts",
        "strict_host_key_checking": True,
    })
    tx.stage_text(path, dump_yaml(updated_connection))



def _ssh_target_form(old: dict | None = None) -> tuple[str, int]:
    old = old or {}
    user = required(
        "SSH 用户",
        str(old.get("ssh_user") or "root"),
        pattern=SSH_USER,
    )
    while True:
        port_text = required(
            "SSH 端口",
            str(old.get("ssh_port") or 22),
            pattern=SSH_PORT,
        )
        port = int(port_text)
        if 1 <= port <= 65535:
            break
        print("SSH 端口必须在 1-65535 之间。")
    return user, port


def host_form(
    old: dict | None = None,
    *,
    forbidden_ids: set[str] | None = None,
    forbidden_addrs: set[str] | None = None,
) -> dict:
    """只采集资产草稿；网络与凭据验证统一留到 SSH 预检阶段。"""
    old = old or {}

    forbidden_ids = forbidden_ids or set()
    forbidden_addrs = forbidden_addrs or set()

    while True:
        host_id = required(
            "主机 ID", old.get("id", "node-1"), pattern=HOST_ID
        )
        if host_id not in forbidden_ids:
            break
        print("主机 ID 已存在，请重新输入。")

    while True:
        addr = required(
            "主机地址（IP 或 DNS）",
            old.get("addr"),
            pattern=HOST_ADDR,
        )
        if addr not in forbidden_addrs:
            break
        print("该主机地址已存在，每个 IP 只能配置一个 SSH 账号。")
    env = required("环境标识", old.get("env", "dev"))
    while True:
        logical_text = required(
            "逻辑目标 ID（多个用逗号分隔）",
            ",".join(old.get("logical_target_ids") or [host_id]),
        )
        logical_ids = [
            item.strip()
            for item in logical_text.split(",")
            if item.strip()
        ]
        if logical_ids:
            break
        print("至少需要一个逻辑目标 ID。")
    user, port = _ssh_target_form(old)

    updated = dict(old)
    updated.update({
        "id": host_id,
        "addr": addr,
        "env": env,
        "allow_agent_read": old.get("allow_agent_read", True),
        "logical_target_ids": logical_ids,
        "ssh_user": user,
        "ssh_port": port,
    })
    return updated


def configure_inventory(tx: Transaction, state: WizardState) -> None:
    path = CONFIG / "inventory.local.yaml"
    existing_data = load_yaml(tx.read(path), path.name)
    existing_hosts = (
        list(existing_data.get("hosts", []))
        if isinstance(existing_data.get("hosts", []), list)
        else []
    )
    mode = action(path.name, tx.read(path) is not None)
    if mode == "q":
        raise Cancelled
    if mode == "s":
        return

    data = existing_data if mode == "m" else {}
    hosts = (
        list(data.get("hosts", []))
        if isinstance(data.get("hosts", []), list)
        else []
    )
    if mode == "o":
        hosts = []

    while True:
        print("\n当前主机：" + ("" if hosts else "（无）"))
        for index, host in enumerate(hosts, 1):
            ssh_info = ""
            if host.get("ssh_user"):
                ssh_info = (
                    f" SSH={host.get('ssh_user')}@{host.get('addr')}:"
                    f"{host.get('ssh_port', 22)}"
                )
            print(
                f"  {index}. {host.get('id')} -> {host.get('addr')} "
                f"[{host.get('env')}]" + ssh_info
            )

        choice = choose(
            "资产操作：新增、编辑、删除、完成或取消",
            "a/e/d/i/f/q",
        )
        if choice == "q":
            raise Cancelled
        if choice == "f":
            if not hosts:
                print("至少需要配置一台主机。")
                continue
            break

        if choice == "i":
            # The local index is intentionally an internal implementation
            # detail: the inventory list never displays initialization tags.
            sys.path.insert(0, str(ROOT / "runner"))
            from runner.host_context import HostContextStore
            context = HostContextStore(str(ROOT / "state" / "host-context"))
            default_ids = [str(item.get("id")) for item in hosts if context.latest_status(str(item.get("id"))) != "initialized"]
            answer = ask("初始化主机序号（逗号分隔；直接回车=尚未初始化的全部）")
            if answer.strip():
                try:
                    selected = [int(value.strip()) - 1 for value in answer.split(",")]
                except ValueError:
                    print("序号格式不正确。")
                    continue
                if not selected or any(index < 0 or index >= len(hosts) for index in selected):
                    print("序号不存在。")
                    continue
                state.initialize_host_ids = list(dict.fromkeys(str(hosts[index]["id"]) for index in selected))
            else:
                state.initialize_host_ids = default_ids
            print("已暂存初始化：" + ("、".join(state.initialize_host_ids) if state.initialize_host_ids else "无（所有主机均已初始化）"))
            continue

        if choice == "a":
            host = host_form(
                forbidden_ids={
                    str(item.get("id", "")) for item in hosts
                },
                forbidden_addrs={
                    str(item.get("addr", "")) for item in hosts
                },
            )
            hosts.append(host)
            print(
                f"已暂存资产："
                f"{host['ssh_user']}@{host['addr']}:{host['ssh_port']}"
            )
            continue

        if not hosts:
            print("没有可编辑的主机。")
            continue

        index = (
            int(required("主机序号", pattern=re.compile(r"\d+"))) - 1
        )
        if not 0 <= index < len(hosts):
            print("序号不存在。")
            continue

        if choice == "e":
            old_host = hosts[index]
            host = host_form(
                old_host,
                forbidden_ids={
                    str(item.get("id", ""))
                    for i, item in enumerate(hosts)
                    if i != index
                },
                forbidden_addrs={
                    str(item.get("addr", ""))
                    for i, item in enumerate(hosts)
                    if i != index
                },
            )
            hosts[index] = host
            print("资产草稿已更新；SSH 将在后续预检阶段验证。")
        else:
            removed = hosts.pop(index)
            print(f"已暂存删除资产：{removed.get('id')}")

    def ssh_targets(items: list[dict]) -> set[tuple[str, str, str, int]]:
        return {
            (
                str(item.get("id", "")),
                str(item.get("addr", "")),
                str(item.get("ssh_user", "")),
                int(item.get("ssh_port") or 22),
            )
            for item in items
            if isinstance(item, dict)
        }

    state.ssh_inventory_changed = (
        ssh_targets(existing_hosts) != ssh_targets(hosts)
    )
    updated_inventory = dict(data)
    updated_inventory["hosts"] = hosts
    tx.stage_text(path, dump_yaml(updated_inventory))


def migrate_legacy(tx: Transaction) -> None:
    legacy = CONFIG / "local.yaml"
    legacy_data = tx.read(legacy)
    if legacy_data is None: return
    print("检测到旧版 config/local.yaml，需要迁移为分文件覆盖层。")
    if not confirm("迁移旧配置到临时工作区"): raise Cancelled
    old = load_yaml(legacy_data, "local.yaml")
    mapping = {"runner": "runner.local.yaml", "connection": "connection.local.yaml", "inventory": "inventory.local.yaml"}
    for section, name in mapping.items():
        if section not in old: continue
        target = CONFIG / name
        if target.exists() and not confirm(f"{name} 已存在，迁移时覆盖它"): raise Cancelled
        value = old[section]
        if not isinstance(value, dict): raise ValueError(f"旧 local.yaml 的 {section} 必须是 mapping")
        tx.stage_text(target, dump_yaml(value))
    backup = CONFIG / f"local.yaml.migrated.{dt.datetime.now():%Y%m%d%H%M%S}.bak"
    tx.stage_bytes(backup, legacy_data, 0o600)
    tx.delete(legacy)


def _build_validation_snapshot(tx: Transaction, validate_dir: Path) -> None:
    # 构造“提交后的完整快照”：仓库模板 + 所有现有 local 文件 + 本轮变更。
    # 跳过的文件必须按原字节参与校验，否则“严格校验通过”不代表真实生效配置。
    validate_dir.mkdir()
    for name in ("inventory.yaml", "connection.yaml"):
        source = CONFIG / name
        source_data = tx.read(source)
        if source_data is None:
            raise ValueError(f"缺少仓库配置模板：{source}")
        tx.watch(source)
        (validate_dir / name).write_bytes(source_data)
    supported_overlays = {
        CONFIG / name
        for name in (
            "runner.local.yaml",
            "connection.local.yaml",
            "inventory.local.yaml",
            "services.local.yaml",
        )
    }
    overlay_paths = supported_overlays | set(CONFIG.glob("*.local.yaml"))
    for path in sorted(overlay_paths, key=str):
        overlay_data = tx.read(path)
        tx.watch(path)
        if overlay_data is not None:
            (validate_dir / path.name).write_bytes(overlay_data)
    for path, data in tx.files.items():
        if path.parent == CONFIG and path.suffix == ".yaml":
            (validate_dir / path.name).write_bytes(data)
    for path in tx.deletes:
        if path.parent == CONFIG and path.suffix == ".yaml":
            (validate_dir / path.name).unlink(missing_ok=True)


def _validate_kubernetes_configuration(
    tx: Transaction,
    runner_config,
    configured_tokens: dict[str, str],
) -> None:
    kubernetes_config = runner_config.kubernetes
    if not kubernetes_config.enabled:
        return
    inventory_path = Path(kubernetes_config.inventory_file)
    inventory_data = tx.read(inventory_path)
    if inventory_data is None:
        raise ValueError(f"缺少 Kubernetes 集群配置：{inventory_path}")
    tx.watch(inventory_path)
    inventory_value = load_yaml(inventory_data, inventory_path.name)
    clusters = inventory_value.get("clusters")
    if not isinstance(clusters, list) or not clusters:
        raise ValueError("启用 Kubernetes 时 clusters 必须是非空列表")

    validation_root = tx.dir / "kubernetes-validation"
    validation_inventory = validation_root / "config" / "kubernetes.local.yaml"
    validation_inventory.parent.mkdir(parents=True)
    validation_inventory.write_bytes(inventory_data)
    os.chmod(validation_inventory, 0o600)
    history_enabled = False
    for item in clusters:
        if not isinstance(item, dict):
            raise ValueError("Kubernetes 集群配置项必须是对象")
        raw_path = str(item.get("kubeconfig_path") or "")
        source_path = _managed_kubeconfig_path(raw_path)
        if source_path is None:
            raise ValueError("kubeconfig 必须由向导托管在 config/keys 目录")
        data = tx.read(source_path)
        if data is None:
            raise ValueError(f"kubeconfig 不存在：{source_path}")
        tx.watch(source_path)
        _kubeconfig_document(data)
        relative = source_path.relative_to(ROOT)
        target_path = validation_root / relative
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(data)
        os.chmod(target_path, 0o600)
        history_enabled = history_enabled or bool(item.get("vmp") or item.get("tls"))

    if history_enabled:
        missing = [
            name
            for name in VOLCENGINE_ENV_NAMES
            if not configured_tokens.get(name) and not os.environ.get(name)
        ]
        if missing:
            raise ValueError(
                "VMP/TLS 已启用，但缺少火山云环境变量：" + "、".join(missing)
            )

    sys.path.insert(0, str(ROOT / "runner"))
    from runner.kubernetes import KubernetesInventory, OfficialKubernetesClient

    inventory = KubernetesInventory(str(validation_inventory))
    client = OfficialKubernetesClient()
    for cluster in inventory.load().values():
        identity = client.identity(cluster)
        print(
            f"Kubernetes 集群已校验：{cluster.id}，"
            f"UID={identity['cluster_uid']}，版本={identity['version']}"
        )


def validate(tx: Transaction) -> None:
    env_path = ROOT / ".env"
    env_data = tx.read(env_path)
    if env_data is None:
        raise ValueError(
            f"缺少 {env_path.name}；不能跳过必需的 Runner Token 配置"
        )
    tx.watch(env_path)
    configured_tokens = env_values(env_data)
    invalid_tokens = [
        name
        for name in (
            "RUNNER_SHARED_TOKEN",
        )
        if not configured_tokens.get(name)
        or configured_tokens[name].startswith("change-me-")
    ]
    if invalid_tokens:
        raise ValueError(
            f"{env_path.name} 缺少有效的 "
            + "、".join(invalid_tokens)
        )

    validate_dir = tx.dir / "validate-config"
    _build_validation_snapshot(tx, validate_dir)
    connection = load_yaml(
        (validate_dir / "connection.yaml").read_bytes(), "connection.yaml"
    )
    local_connection = validate_dir / "connection.local.yaml"
    if local_connection.exists():
        connection.update(load_yaml(local_connection.read_bytes(), "connection.local.yaml"))
    allowed_connection = {
        "ssh_user", "ssh_key_path", "known_hosts_path", "strict_host_key_checking",
        "connect_timeout_sec", "command_timeout_sec",
    }
    if set(connection) - allowed_connection:
        raise ValueError("connection.yaml 包含不支持的字段")
    inventory = load_yaml((validate_dir / "inventory.yaml").read_bytes(), "inventory.yaml")
    local_inventory = validate_dir / "inventory.local.yaml"
    if local_inventory.exists():
        inventory.update(load_yaml(local_inventory.read_bytes(), "inventory.local.yaml"))
    if not isinstance(inventory.get("hosts"), list):
        raise ValueError("inventory.yaml 的 hosts 必须是列表")

    # connection schema 只验证路径字符串。这里再验证“提交后视图”中的
    # 实际文件，避免用户跳过连接配置编辑时把缺失/宽 ACL/损坏私钥带到运行期。
    def post_commit_path(value: str) -> Path:
        candidate = Path(value)
        resolved = candidate.resolve() if candidate.is_absolute() else (validate_dir / candidate).resolve()
        try:
            relative = resolved.relative_to(validate_dir.resolve())
        except ValueError:
            return resolved
        return CONFIG / relative

    key_path = post_commit_path(str(connection.get("ssh_key_path", "")))
    key_data = tx.read(key_path)
    if not key_data:
        raise ValueError(f"runner SSH 私钥不存在或为空：{key_path}")
    if key_path in tx.private_keys:
        _materialize_private_key_probe(tx, key_data)
    elif key_path in tx.files:
        raise ValueError(
            f"runner SSH 私钥未按私钥方式安全暂存：{key_path}"
        )
    else:
        tx.watch(key_path)
        # 跳过连接配置编辑时必须让 OpenSSH 直接加载最终文件本身，不能复制到
        # 安全 probe 后掩盖最终 Windows DACL 过宽的问题。
        _derive_public_key(key_path)

    known_hosts_path = post_commit_path(
        str(connection.get("known_hosts_path", ""))
    )
    known_hosts_data = tx.read(known_hosts_path)
    if not known_hosts_data:
        raise ValueError(
            f"runner known_hosts 不存在或为空：{known_hosts_path}"
        )
    tx.watch(known_hosts_path)
    if shutil.which("ssh-keygen") is None:
        raise ValueError("缺少 ssh-keygen，无法验证 runner SSH 文件")
    known_hosts_probe = tx.dir / "known-hosts-validation"
    known_hosts_probe.write_bytes(known_hosts_data)
    try:
        fingerprint_result = subprocess.run(
            ["ssh-keygen", "-lf", str(known_hosts_probe)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("验证 runner known_hosts 超时") from exc
    if fingerprint_result.returncode != 0:
        detail = _decode_process_output(
            fingerprint_result.stderr
        ).strip()
        raise ValueError(
            "runner known_hosts 不包含有效的 OpenSSH 主机密钥"
            + (f"：{detail}" if detail else "")
        )
    _, known_hosts_extras = _parse_known_hosts(known_hosts_data)
    invalid_lines = [
        line
        for line in known_hosts_extras
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if invalid_lines:
        raise ValueError(
            "runner known_hosts 包含无法识别的记录："
            + invalid_lines[0]
        )
    record_probe = tx.dir / "known-hosts-record-validation"
    for line_number, line in enumerate(
        known_hosts_data.splitlines(), 1
    ):
        if not line.strip() or line.lstrip().startswith(b"#"):
            continue
        record_probe.write_bytes(line + b"\n")
        try:
            record_result = subprocess.run(
                ["ssh-keygen", "-lf", str(record_probe)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(
                f"验证 known_hosts 第 {line_number} 行超时"
            ) from exc
        if record_result.returncode != 0:
            raise ValueError(
                f"runner known_hosts 第 {line_number} 行不是有效记录"
            )

    for host in inventory.get("hosts", []):
        addr = str(host.get("addr", "")).strip()
        port = int(host.get("ssh_port") or 22)
        host_field = _expected_known_host_field(addr, port)
        try:
            lookup = subprocess.run(
                [
                    "ssh-keygen",
                    "-F",
                    host_field,
                    "-f",
                    str(known_hosts_probe),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(
                f"核对 known_hosts 目标超时：{addr}:{port}"
            ) from exc
        if lookup.returncode != 0 or not lookup.stdout.strip():
            raise ValueError(
                f"runner known_hosts 缺少资产主机密钥：{addr}:{port}"
            )

    sys.path.insert(0, str(ROOT / "runner"))
    from runner.config import (
        RunnerConfig,
        _deep_merge,
        _runner_local_overlay,
    )

    runner_local = validate_dir / "runner.local.yaml"
    overlay = (
        _runner_local_overlay(str(runner_local))
        if runner_local.exists()
        else {}
    )
    runner_base_path = CONFIG / "runner.yaml"
    runner_base_data = tx.read(runner_base_path)
    if runner_base_data is None:
        raise ValueError(f"runner base config 不存在：{runner_base_path}")
    tx.watch(runner_base_path)
    runner_base = load_yaml(
        runner_base_data,
        "runner base config",
    )
    runner_config = RunnerConfig.from_dict(_deep_merge(runner_base, overlay))
    _validate_kubernetes_configuration(tx, runner_config, configured_tokens)
    trusted_config = runner_config.trusted_session
    if trusted_config.enabled:
        required_trusted_env = [trusted_config.token_env]
        missing_trusted_env = [
            name
            for name in required_trusted_env
            if not configured_tokens.get(name)
            or configured_tokens[name].startswith("change-me-")
        ]
        if missing_trusted_env:
            raise ValueError(
                f"{env_path.name} 缺少有效的 "
                + "、".join(missing_trusted_env)
            )
        if configured_tokens[trusted_config.token_env] == configured_tokens["RUNNER_SHARED_TOKEN"]:
            raise ValueError(
                "trusted callback token 与 RUNNER_SHARED_TOKEN 必须不同"
            )
        from runner.instance_identity import load_identity
        from runner.trusted_session import EncryptedTranscriptStore

        identity = load_identity(
            trusted_config.runner_instance_id_file,
            expected=trusted_config.expected_runner_instance_id,
            owner_uid=_trusted_identity_owner_uid(),
        )
        # 仅验证密钥来源、base64长度和文件权限；不输出或记录密钥值。
        EncryptedTranscriptStore.from_config(
            trusted_config, environ=configured_tokens
        )
        print(
            "可信 Runner 实例身份已校验："
            + identity.instance_id
            + "（请确认 AIOps Provider 登记一致）"
        )
    for name in ("runner.local.yaml", "connection.local.yaml", "inventory.local.yaml"):
        path = validate_dir / name
        raw = path.read_bytes() if path.exists() else None
        if raw is not None: load_yaml(raw, name)
    print("配置格式与 target-exec SSH 连接校验通过。")
    if shutil.which("claude"):
        print("claude CLI：已找到。")
    else:
        print("警告：未在 PATH 找到 claude CLI。")


def _show_change_plan(tx: Transaction, state: WizardState) -> None:
    print("\n本地配置计划（Token 不显示）：")
    for path in sorted(tx.files):
        print("  写入", path.relative_to(ROOT))
    for path in sorted(tx.deletes):
        print("  删除", path.relative_to(ROOT))

    if state.pending_setups:
        print("\n远程 SSH 计划（确认后执行，失败时尽力回滚）：")
        for host_id in state.pending_setups:
            credential = state.credentials.get(host_id)
            if credential is None:
                print(f"  {host_id}: 缺少临时凭据")
                continue
            print(
                f"  确保公钥存在并复验 "
                f"{credential.user}@{credential.addr}:{credential.port} "
                f"[{credential.os_type}]"
            )
    elif state.key_target is not None and state.public_key:
        print("\n远程 SSH 计划：无需写入；现有免密登录已通过预检。")
    else:
        print("\n远程 SSH 计划：本次跳过，未执行 SSH 预检。")
    if state.initialize_host_ids:
        print("\n主机上下文初始化计划（本地配置提交后，以 runner 服务账号执行）：")
        for host_id in state.initialize_host_ids:
            print(f"  {host_id}: 只读识别服务并写入远端 ~/AGENT.md")
    if state.old_remote_key_requires_manual_removal:
        print(
            "  安全待办：新配置成功后，仍须从每台目标机人工撤销"
            "旧 runner SSH 公钥；本向导不会自动删除旧 key。"
        )


def _rollback_and_cleanup(
    state: WizardState,
    tx: Transaction | None,
) -> list[str]:
    """即使回滚阶段再次中断，也保证清理本地密码与候选文件。"""
    failures: list[str] = []
    try:
        failures = _rollback_remote_changes(state)
    except BaseException as exc:
        detail = str(exc) or type(exc).__name__
        failures.append(f"回滚流程中断：{detail}")
    finally:
        secret_cleanup_error = ""
        for _attempt in range(2):
            try:
                state.clear_secrets()
                secret_cleanup_error = ""
                break
            except BaseException as exc:
                detail = str(exc) or type(exc).__name__
                secret_cleanup_error = f"清理临时凭据时中断：{detail}"
        if secret_cleanup_error:
            failures.append(secret_cleanup_error)
        if tx is not None:
            local_cleanup_error = ""
            for _attempt in range(2):
                try:
                    tx.cleanup()
                    local_cleanup_error = ""
                    break
                except BaseException as exc:
                    detail = str(exc) or type(exc).__name__
                    local_cleanup_error = f"清理本地事务时中断：{detail}"
            if local_cleanup_error:
                failures.append(local_cleanup_error)
    return failures


def _runner_service_user() -> str:
    """Use the installed service account when possible, never root by default."""
    if os.name != "posix":
        raise ValueError("主机服务上下文初始化仅支持 Linux Runner")
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=User", "--value", "aiops-trusted-runner.service"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=5,
        )
        user = result.stdout.strip()
        if result.returncode == 0 and SSH_USER.fullmatch(user):
            return user
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "claude"


def _initialize_host_contexts(host_ids: list[str]) -> int:
    if not host_ids:
        return 0
    user = _runner_service_user()
    python = ROOT / ".venv" / "bin" / "python"
    python_command = str(python if python.is_file() else Path(sys.executable))
    module_args = [python_command, "-m", "runner.host_context", "--targets", ",".join(host_ids), "--concurrency", "4"]
    # systemd reads the protected EnvironmentFile on behalf of the service
    # account, so Claude's provider configuration is available without giving
    # the wizard a reason to print, parse, or persist any secret.
    if os.geteuid() == 0 and shutil.which("systemd-run") and (ROOT / ".env").is_file():
        command = [
            "systemd-run", "--wait", "--collect", "--quiet",
            f"--property=User={user}", f"--property=WorkingDirectory={ROOT}",
            f"--property=EnvironmentFile={ROOT / '.env'}",
            f"--property=Environment=PYTHONPATH={ROOT / 'runner'}",
            f"--property=Environment=RUNNER_CONFIG={ROOT / 'config' / 'runner.yaml'}",
            *module_args,
        ]
    elif os.geteuid() == 0:
        command = ["runuser", "-u", user, "--", "env", f"PYTHONPATH={ROOT / 'runner'}", f"RUNNER_CONFIG={ROOT / 'config' / 'runner.yaml'}", *module_args]
    else:
        # In the unified service-user setup, the wizard and its .env are both
        # owned by the runner account.  Load that file only into this child so
        # the initialization Claude receives its existing provider settings
        # without exposing them to the wizard output or persistent state.
        command = [
            "/bin/bash", "-c",
            'set -a; . "$1/.env"; set +a; export PYTHONPATH="$1/runner" RUNNER_CONFIG="$1/config/runner.yaml"; exec "$2" -m runner.host_context --targets "$3" --concurrency 4',
            "aiops-runner-host-context", str(ROOT), python_command,
            ",".join(host_ids),
        ]
    print("开始初始化主机服务上下文（并发 4）…")
    try:
        result = subprocess.run(command, cwd=ROOT, check=False)
    except OSError as exc:
        print("初始化无法启动：" + (str(exc) or type(exc).__name__), file=sys.stderr)
        return 1
    if result.returncode:
        print("配置已提交；部分主机上下文初始化失败，可重新运行向导手动选择刷新。", file=sys.stderr)
        return 1
    print("主机服务上下文初始化完成。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    state = WizardState()
    tx: Transaction | None = None
    try:
        tx = Transaction()
        print("== AIOps AIOps Runner 分文件配置向导 ==")
        migrate_legacy(tx)
        configure_runner(tx)
        configure_env(tx)
        kubernetes_setup = configure_kubernetes(tx)
        _stage_kubernetes_env(tx, kubernetes_setup)
        # inventory 先采集每台主机的账号和密码，再统一安装 runner SSH 公钥。
        configure_inventory(tx, state)
        configure_connection(tx, state)
        validate(tx)
        if not tx.changed() and not state.initialize_host_ids:
            state.clear_secrets()
            tx.cleanup()
            if tx.cleanup_error:
                print(
                    "没有配置变更，但临时目录未完全清理："
                    + tx.cleanup_error,
                    file=sys.stderr,
                )
                return 1
            print("没有待提交的配置变更。")
            return 0
        # 在任何远程副作用前完成所有本地候选文件的安全落盘与权限预检。
        tx.prepare()
        _show_change_plan(tx, state)
        if not confirm("确认执行上述远程操作并提交本地配置"):
            raise Cancelled
        _apply_pending_remote_setups(tx, state)
        tx.commit()
        state.remote_changes.clear()
        initialize_host_ids = list(state.initialize_host_ids)
        requires_old_key_removal = (
            state.old_remote_key_requires_manual_removal
        )
        state.clear_secrets()
        if tx.cleanup_error:
            print(
                "配置已经提交，但含敏感候选的临时目录未完全清理："
                + tx.cleanup_error,
                file=sys.stderr,
            )
            return 1
        print("配置已提交。下一步：安装依赖（如需要）后启动 runner。")
        if requires_old_key_removal:
            print(
                "安全待办：确认新私钥可用后，从每台目标机"
                " authorized_keys 人工撤销旧 runner SSH 公钥。"
            )
        return _initialize_host_contexts(initialize_host_ids)
    except (Cancelled, KeyboardInterrupt):
        if tx is not None and tx.committed:
            state.remote_changes.clear()
            state.clear_secrets()
            tx.cleanup()
            if tx.cleanup_error:
                print(
                    "配置已经提交，但临时目录未完全清理："
                    + tx.cleanup_error,
                    file=sys.stderr,
                )
                return 1
            print("配置已经提交；仅收尾输出被中断。")
            return 0
        had_remote_changes = bool(state.remote_changes)
        remote_state_uncertain = state.remote_operation_inflight
        rollback_failures = _rollback_and_cleanup(state, tx)
        cleanup_error = tx.cleanup_error if tx is not None else ""
        if rollback_failures or remote_state_uncertain or cleanup_error:
            details = []
            if rollback_failures:
                details.append(
                    "部分远程公钥未能自动回滚："
                    + "；".join(rollback_failures)
                )
            if remote_state_uncertain:
                details.append(
                    "远程操作在结果确认前中断，请逐台检查 authorized_keys"
                )
            if cleanup_error:
                details.append(
                    "本地事务目录未完全清理：" + cleanup_error
                )
            print(
                "已取消；本地配置未提交，但" + "；".join(details),
                file=sys.stderr,
            )
            return 1
        remote_note = (
            "远程新增公钥已回滚"
            if had_remote_changes
            else "未执行远程写入"
        )
        print(f"已取消；本地配置未作修改，{remote_note}。")
        return 0
    except Exception as exc:
        if tx is not None and tx.committed:
            state.remote_changes.clear()
            state.clear_secrets()
            tx.cleanup()
            if tx.cleanup_error:
                print(
                    "配置已经提交，但临时目录未完全清理："
                    + tx.cleanup_error,
                    file=sys.stderr,
                )
                return 1
            print(
                f"配置已经提交，但收尾提示失败：{exc}",
                file=sys.stderr,
            )
            return 0
        had_remote_changes = bool(state.remote_changes)
        remote_state_uncertain = state.remote_operation_inflight
        rollback_failures = _rollback_and_cleanup(state, tx)
        remote_notes: list[str] = []
        if rollback_failures:
            remote_notes.append(
                "警告：部分远程公钥未能自动回滚："
                + "；".join(rollback_failures)
            )
        elif had_remote_changes:
            remote_notes.append("本次记录到的远程新增公钥已回滚")
        if remote_state_uncertain:
            remote_notes.append(
                "远程操作在结果确认前失败，状态可能不确定；"
                "请逐台检查 authorized_keys"
            )
        elif not had_remote_changes:
            remote_notes.append("未执行远程写入")
        rollback_note = "；" + "；".join(remote_notes)
        local_note = (
            f"本地恢复可能不完整，恢复材料保留在 {tx.dir}"
            if tx is not None and tx.preserve_recovery
            else (
                "本地配置未提交，且事务目录未完全清理："
                + tx.cleanup_error
                if tx is not None and tx.cleanup_error
                else "本地配置未提交"
            )
        )
        print(
            f"配置失败：{exc}；{local_note}{rollback_note}。",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
