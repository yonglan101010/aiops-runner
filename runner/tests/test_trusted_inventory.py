import pytest

from runner.trusted_inventory import ManagedInventory
from runner.trusted_session import TrustedSessionError


def _write_inventory(tmp_path, hosts, *, local=False):
    name = "inventory.local.yaml" if local else "inventory.yaml"
    lines = ["hosts:"]
    for host_id, address, targets in hosts:
        lines += [f"  - id: {host_id}", f"    addr: {address}", "    logical_target_ids:"]
        lines += [f"      - {target}" for target in targets]
    (tmp_path / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_managed_inventory_accepts_exactly_one_registered_target(tmp_path):
    _write_inventory(tmp_path, [("node-1", "10.0.0.1", ["node-1"])])
    inventory = ManagedInventory(str(tmp_path))
    inventory.validate()
    inventory.require_unique_target("node-1")
    assert inventory.summary() == {"managed_host_count": 1, "logical_target_count": 1}


def test_public_targets_exposes_only_literal_ip_addresses(tmp_path):
    _write_inventory(tmp_path, [("node-1", "10.0.0.1", ["node-1"]), ("node-2", "host.internal", ["node-2"])])

    assert ManagedInventory(str(tmp_path)).public_targets() == [
        {"logical_target_id": "node-1", "display_name": "node-1", "environment": "", "ip_address": "10.0.0.1"},
        {"logical_target_id": "node-2", "display_name": "node-2", "environment": ""},
    ]


@pytest.mark.parametrize(
    "target, hosts, code",
    [
        ("unknown", [("node-1", "10.0.0.1", ["node-1"])], "TRUSTED_TARGET_NOT_MANAGED"),
        ("cluster-a", [("node-1", "10.0.0.1", ["cluster-a"]), ("node-2", "10.0.0.2", ["cluster-a"])], "TRUSTED_TARGET_NOT_UNIQUELY_RESOLVED"),
    ],
)
def test_managed_inventory_rejects_missing_or_group_target(tmp_path, target, hosts, code):
    _write_inventory(tmp_path, hosts)
    with pytest.raises(TrustedSessionError) as exc:
        ManagedInventory(str(tmp_path)).require_unique_target(target)
    assert exc.value.code == code


def test_local_inventory_replaces_base_host_list(tmp_path):
    _write_inventory(tmp_path, [("base", "10.0.0.1", ["base"])])
    _write_inventory(tmp_path, [("local", "10.0.0.2", ["local"])], local=True)
    inventory = ManagedInventory(str(tmp_path))
    inventory.require_unique_target("local")
    with pytest.raises(TrustedSessionError) as exc:
        inventory.require_unique_target("base")
    assert exc.value.code == "TRUSTED_TARGET_NOT_MANAGED"


def test_inventory_builds_local_only_ssh_profile(tmp_path):
    _write_inventory(tmp_path, [("node-1", "10.0.0.1", ["node-1"])])
    key, known_hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("private", encoding="utf-8")
    known_hosts.write_text("known", encoding="utf-8")
    (tmp_path / "inventory.local.yaml").write_text(
        "hosts:\n  - id: node-1\n    addr: 10.0.0.1\n    ssh_user: root\n"
        "    ssh_port: 2222\n    logical_target_ids: [node-1]\n", encoding="utf-8"
    )
    (tmp_path / "connection.yaml").write_text(
        "ssh_user: root\nssh_key_path: key\nknown_hosts_path: known_hosts\n"
        "strict_host_key_checking: true\ncommand_timeout_sec: 30\n", encoding="utf-8"
    )
    assert ManagedInventory(str(tmp_path)).ssh_profile("node-1") == {
        "user": "root", "address": "10.0.0.1", "port": 2222,
        "key_path": str(key), "known_hosts_path": str(known_hosts), "command_timeout_sec": 30,
    }
