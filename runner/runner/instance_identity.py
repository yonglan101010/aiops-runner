"""Fail-closed persistent identity for the Linux trusted-session runner.

The identity is an installation artifact, not configuration and not a
credential.  Service startup only reads it; creation is an explicit operator
action (`python -m runner.instance_identity init`).
"""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


class InstanceIdentityError(RuntimeError):
    """A local identity invariant could not be proven."""


def _linux_only() -> None:
    if sys.platform != "linux":
        raise InstanceIdentityError("trusted runner identity is supported only on Linux")


def _canonical_uuid4(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise InstanceIdentityError("runner instance identity is not a canonical UUIDv4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise InstanceIdentityError("runner instance identity is not a canonical UUIDv4")
    return value


def _no_follow_stat(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise InstanceIdentityError("runner instance identity file is missing or unreadable") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise InstanceIdentityError("runner instance identity must be a regular non-symlink file")
    return value


def _check_directory(path: Path, *, owner_uid: int) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError as exc:
        raise InstanceIdentityError("runner identity state directory is missing") from exc
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISDIR(value.st_mode):
        raise InstanceIdentityError("runner identity state parent must be a non-symlink directory")
    if value.st_uid != owner_uid:
        raise InstanceIdentityError("runner identity state directory owner does not match the service user")
    if stat.S_IMODE(value.st_mode) & 0o077:
        raise InstanceIdentityError("runner identity state directory permissions are too broad")
    return value


@dataclass(frozen=True)
class IdentitySnapshot:
    instance_id: str
    device: int
    inode: int
    owner_uid: int


def load_identity(path: str | os.PathLike[str], *, expected: str = "", owner_uid: int | None = None) -> IdentitySnapshot:
    """Strictly read the persistent ID without ever creating or repairing it."""
    _linux_only()
    uid = os.geteuid() if owner_uid is None else owner_uid
    identity_path = Path(path)
    _check_directory(identity_path.parent, owner_uid=uid)
    info = _no_follow_stat(identity_path)
    if info.st_uid != uid:
        raise InstanceIdentityError("runner instance identity owner does not match the service user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise InstanceIdentityError("runner instance identity permissions are too broad")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(identity_path, flags)
    except OSError as exc:
        raise InstanceIdentityError("runner instance identity cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise InstanceIdentityError("runner instance identity changed while being read")
        raw = os.read(fd, 128)
    finally:
        os.close(fd)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InstanceIdentityError("runner instance identity has invalid encoding") from exc
    if len(raw) != 37 or not text.endswith("\n") or text.count("\n") != 1:
        raise InstanceIdentityError("runner instance identity must have exactly one trailing newline")
    instance_id = _canonical_uuid4(text[:-1])
    if expected and instance_id != _canonical_uuid4(expected):
        raise InstanceIdentityError("runner instance identity does not match expected_runner_instance_id")
    return IdentitySnapshot(instance_id, opened.st_dev, opened.st_ino, opened.st_uid)


@contextlib.contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    _linux_only()
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InstanceIdentityError("identity lock must be a regular file")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _service_uid(service_user: str | None) -> int:
    if not service_user:
        return os.geteuid()
    if service_user.isdigit():
        return int(service_user)
    try:
        import pwd  # POSIX-only; trusted mode rejects Windows before this path.
        return pwd.getpwnam(service_user).pw_uid
    except KeyError as exc:
        raise InstanceIdentityError("requested service user does not exist") from exc


def init_identity(path: str | os.PathLike[str], *, service_user: str | None = None) -> str:
    """Create exactly once, or validate the existing value without replacing it."""
    _linux_only()
    identity_path = Path(path)
    target_uid = _service_uid(service_user)
    parent = identity_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    try:
        parent_info = os.lstat(parent)
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise InstanceIdentityError("runner identity state parent must be a non-symlink directory")
        os.chmod(parent, 0o700)
        if os.geteuid() == 0 and parent.stat().st_uid != target_uid:
            os.chown(parent, target_uid, -1)
    except OSError as exc:
        raise InstanceIdentityError("cannot secure runner identity state directory") from exc
    if parent.stat().st_uid != target_uid:
        raise InstanceIdentityError("identity state directory owner must be the runner service user")
    lock_path = parent / "runner-instance.init.lock"
    with _exclusive_lock(lock_path):
        if identity_path.exists() or identity_path.is_symlink():
            return load_identity(identity_path, owner_uid=target_uid).instance_id
        value = str(uuid.uuid4())
        # O_EXCL is the no-clobber primitive.  The lock coordinates expected
        # installers; O_EXCL still makes a mistaken concurrent writer harmless.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(identity_path, flags, 0o600)
        except FileExistsError:
            return load_identity(identity_path, owner_uid=target_uid).instance_id
        except OSError as exc:
            raise InstanceIdentityError("cannot create runner instance identity safely") from exc
        try:
            payload = (value + "\n").encode("ascii")
            os.write(fd, payload)
            os.fsync(fd)
            os.fchmod(fd, 0o600)
            if os.geteuid() == 0 and os.fstat(fd).st_uid != target_uid:
                os.fchown(fd, target_uid, -1)
        finally:
            os.close(fd)
        _fsync_directory(parent)
        return load_identity(identity_path, owner_uid=target_uid).instance_id


class RunnerInstanceLock:
    """Non-blocking service lifetime lock for one persistent state directory."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._fd: int | None = None

    def acquire(self) -> None:
        _linux_only()
        import fcntl

        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise InstanceIdentityError("runner instance lock must be a regular file")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise InstanceIdentityError("another trusted runner already owns this identity state") from exc
        except Exception:
            os.close(fd)
            raise
        self._fd = fd

    def close(self) -> None:
        if self._fd is None:
            return
        import fcntl
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None


class IdentityGuard:
    """Detect deletion, replacement, permission drift or changed identity."""

    def __init__(self, path: str | os.PathLike[str], *, expected: str = ""):
        self.path = str(path)
        self.expected = expected
        self.snapshot = load_identity(self.path, expected=expected)

    @property
    def instance_id(self) -> str:
        return self.snapshot.instance_id

    def verify(self) -> None:
        current = load_identity(self.path, expected=self.expected)
        if (
            current.instance_id != self.snapshot.instance_id
            or current.device != self.snapshot.device
            or current.inode != self.snapshot.inode
            or current.owner_uid != self.snapshot.owner_uid
        ):
            raise InstanceIdentityError("runner instance identity changed during trusted service lifetime")


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialize the persistent trusted runner identity")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--file", required=True, dest="identity_file")
    init.add_argument("--service-user", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            print(init_identity(args.identity_file, service_user=args.service_user))
            return 0
    except InstanceIdentityError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
