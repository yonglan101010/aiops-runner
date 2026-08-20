import multiprocessing
import os
import stat
import sys
import uuid

import pytest

from runner.config import RunnerConfigError, TrustedSessionConfig
from runner.instance_identity import (
    IdentityGuard,
    InstanceIdentityError,
    RunnerInstanceLock,
    init_identity,
    load_identity,
)


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="trusted identity is Linux-only")


def _initialize(path: str, queue):
    try:
        queue.put((True, init_identity(path)))
    except Exception as exc:  # pragma: no cover - assertion reports child detail
        queue.put((False, str(exc)))


def test_identity_init_is_no_clobber_and_concurrent(tmp_path):
    identity = tmp_path / "state" / "runner-instance-id"
    queue = multiprocessing.Queue()
    workers = [multiprocessing.Process(target=_initialize, args=(str(identity), queue)) for _ in range(2)]
    for worker in workers:
        worker.start()
    values = [queue.get(timeout=10) for _ in workers]
    for worker in workers:
        worker.join(10)
        assert worker.exitcode == 0
    assert all(ok for ok, _ in values)
    assert len({value for _, value in values}) == 1
    assert identity.read_text(encoding="ascii") == values[0][1] + "\n"
    assert stat.S_IMODE(identity.stat().st_mode) == 0o600
    assert stat.S_IMODE(identity.parent.stat().st_mode) == 0o700


def test_identity_rejects_bad_shape_symlink_permissions_and_drift(tmp_path):
    state = tmp_path / "state"
    identity = state / "runner-instance-id"
    value = init_identity(identity)
    guard = IdentityGuard(identity, expected=value)
    guard.verify()
    os.chmod(identity, 0o644)
    with pytest.raises(InstanceIdentityError, match="permissions"):
        guard.verify()
    os.chmod(identity, 0o600)
    identity.unlink()
    identity.symlink_to(state / "other")
    with pytest.raises(InstanceIdentityError):
        load_identity(identity)


def test_identity_expected_assertion_and_lifetime_lock(tmp_path):
    identity = tmp_path / "state" / "runner-instance-id"
    value = init_identity(identity)
    with pytest.raises(InstanceIdentityError, match="expected"):
        load_identity(identity, expected=str(uuid.uuid4()))
    first = RunnerInstanceLock(identity.parent / "runner-instance.lock")
    second = RunnerInstanceLock(identity.parent / "runner-instance.lock")
    first.acquire()
    try:
        with pytest.raises(InstanceIdentityError, match="another trusted runner"):
            second.acquire()
    finally:
        first.close()
    second.acquire()
    second.close()


def test_inline_identity_is_not_accepted_as_configuration():
    with pytest.raises(RunnerConfigError, match="runner_instance_id"):
        TrustedSessionConfig.from_dict({"runner_instance_id": str(uuid.uuid4())})
