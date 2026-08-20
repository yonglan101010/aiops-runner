"""Read-only preflight for the node-local Kubernetes inventory."""

from __future__ import annotations

import argparse
import json

from runner.config import load_config
from runner.kubernetes import KubernetesInventory, OfficialKubernetesClient


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Kubernetes inventory, file security, context, certificate and API identity")
    parser.add_argument("--runner-config", default=None)
    args = parser.parse_args()
    cfg = load_config(args.runner_config)
    inventory = KubernetesInventory(cfg.kubernetes.inventory_file)
    client = OfficialKubernetesClient()
    results = []
    for cluster in inventory.load().values():
        local = inventory.validate_local_file(cluster)
        identity = client.identity(cluster)
        results.append({"runner_cluster_id": cluster.id, "local": local, "cluster_uid": identity["cluster_uid"], "version": identity["version"], "ok": True})
    print(json.dumps({"clusters": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
