import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
import pytest
import yaml

import runner.kubernetes as kubernetes_module
from runner.kubernetes import (
    AssetCollectionSnapshot,
    ClusterConfig,
    KubernetesBoundaryError,
    KubernetesInventory,
    KubernetesService,
    OfficialKubernetesClient,
    VolcengineHistoryClient,
)


class FakeClusterClient:
    def identity(self, cluster):
        return {"cluster_uid": "cluster-uid-1", "version": "v1.30.1"}

    def capabilities(self, cluster):
        return [{"name": "kubernetes_api", "status": "AVAILABLE", "detail": "ok"}]

    def assets(self, cluster):
        return [{"api_version": "v1", "kind": "Pod", "namespace": "prod", "name": "api-1", "uid": "pod-1", "resource_version": "7", "owners": [], "labels": {"app": "api"}, "status_summary": {"phase": "Running"}}]

    def current_metrics(self, cluster, query):
        return {"resource_type": query["resource_type"], "items": [{"metadata": {"name": "node-1"}}]}

    def current_logs(self, cluster, query):
        return {"lines": ["ok"], "bytes": 2, "previous": query.get("previous", False)}

    def current_events(self, cluster, query):
        return {"items": []}


class FakeHistoryClient:
    def metrics(self, cluster, query):
        return {"series": [{"metric": query["metric"], "values": [[1, "2"]]}], "step_seconds": 60}

    def logs(self, cluster, query):
        return {"items": [], "next_cursor": None}

    def events(self, cluster, query):
        return {"items": [], "next_cursor": None}


def service(tmp_path):
    inventory = tmp_path / "kubernetes.local.yaml"
    inventory.write_text(yaml.safe_dump({"clusters": [{
        "id": "vke-prod", "display_name": "VKE", "environment": "prod",
        "kubeconfig_path": "keys/vke.kubeconfig", "context": "vke-prod",
        "namespace_allowlist": ["prod"],
        "vmp": {"region": "cn-beijing", "workspace_id": "w-1"},
        "tls": {"region": "cn-beijing", "log_topic_id": "l-1", "event_topic_id": "e-1"},
    }]}), encoding="utf-8")
    cfg = SimpleNamespace(inventory_file=str(inventory), state_dir=str(tmp_path / "state"), current_metrics_cache_sec=15)
    return KubernetesService(cfg, "runner-1", client=FakeClusterClient(), history=FakeHistoryClient())


class FakeHealthClient(FakeClusterClient):
    def __init__(self, assets, *, resources=None, events=None):
        self._assets = assets
        self._resources = resources or [
            {
                "api_version": api_version,
                "kind": kind,
                "status": "COMPLETE",
                "checked_count": sum(1 for item in assets if item.get("kind") == kind),
            }
            for api_version, kind in OfficialKubernetesClient.RESOURCES
        ]
        self._events = events or []
        self.event_queries = []

    def assets(self, _cluster):
        return self._assets

    def collect_assets(self, _cluster):
        return AssetCollectionSnapshot(self._assets, self._resources)

    def current_events(self, _cluster, _query):
        self.event_queries.append(dict(_query))
        return {"items": self._events, "truncated": False}


def health_service(tmp_path, assets, *, resources=None, events=None):
    instance = service(tmp_path)
    instance.client = FakeHealthClient(assets, resources=resources, events=events)
    instance.cfg.inspection_report_version = "v2"
    return instance


def request(cluster="vke-prod", **extra):
    return json.dumps({"runner_cluster_id": cluster, "expected_cluster_uid": "cluster-uid-1", **extra}).encode()


def collection_service(tmp_path):
    instance = service(tmp_path)
    instance.cfg.continuous_collection_enabled = False
    instance.cfg.collection_memory_limit_mb = 16
    instance.cfg.collection_interval_sec = 15
    instance.cfg.reconcile_interval_sec = 21600
    instance.cfg.log_request_timeout_sec = 10
    instance.cfg.log_collection_concurrency = 16
    collector = kubernetes_module.ClusterCollector.__new__(kubernetes_module.ClusterCollector)
    collector.service = instance
    collector.cluster = instance._cluster("vke-prod")
    collector.epoch = "epoch-1"
    collector.streams = {name: kubernetes_module.CollectionStream(1024 * 1024) for name in ("resources", "events", "logs")}
    collector.current = {}
    collector.raw_current = {}
    collector.current_lock = kubernetes_module.threading.Lock()
    collector.last_success = {name: None for name in collector.streams}
    collector.last_error = {name: None for name in collector.streams}
    collector.started_at = "2026-08-12T00:00:00Z"
    collector.stop_event = kubernetes_module.threading.Event()
    collector.reconcile_requested = kubernetes_module.threading.Event()
    collector._event_keys = set()
    collector._log_keys = set()
    instance._collectors["vke-prod"] = collector
    return instance, collector


def test_collection_pull_is_bound_sequenced_and_fingerprinted(tmp_path):
    instance, collector = collection_service(tmp_path)
    collector.streams["resources"].append({"change_type": "ADDED", "asset": {"uid": "pod-1"}, "observed_at": "2026-08-12T00:00:00Z"})
    body = request(expected_runner_instance_id="runner-1", epoch=None, sequences={"resources": 0, "events": 0, "logs": 0}, remaining_log_bytes=1024, limit=100)
    code, payload = instance.handle("POST", "/kubernetes/collections/pull", body)
    assert code == 200
    assert payload["data"]["epoch"] == "epoch-1"
    assert payload["data"]["streams"]["resources"]["next_sequence"] == 1
    assert len(payload["content_fingerprint"]) == 64


def test_collection_stream_reports_overflow_gap():
    stream = kubernetes_module.CollectionStream(80)
    for number in range(6):
        stream.append({"value": "x" * 30, "number": number})
    result = stream.read(1, limit=100, maximum_bytes=1024)
    assert result["dropped"] > 0
    assert result["gap"] is True


def test_collection_pull_discards_queued_logs_when_quota_is_exhausted(tmp_path):
    instance, collector = collection_service(tmp_path)
    collector.streams["logs"].append({"content": "secret-safe", "bytes": 11})
    body = request(
        expected_runner_instance_id="runner-1", epoch="epoch-1",
        sequences={"resources": 0, "events": 0, "logs": 0},
        remaining_log_bytes=0, limit=100,
    )
    code, payload = instance.handle("POST", "/kubernetes/collections/pull", body)
    assert code == 200
    logs = payload["data"]["streams"]["logs"]
    assert logs["items"] == []
    assert logs["next_sequence"] == 1
    assert logs["quota_skipped"] == 1


def test_resource_reconciliation_emits_complete_baseline(tmp_path):
    _, collector = collection_service(tmp_path)
    collector._collect_resources(baseline=True)
    result = collector.streams["resources"].read(0, limit=100, maximum_bytes=1024 * 1024)
    assert result["items"][0]["change_type"] == "BASELINE"
    assert result["items"][-1]["change_type"] == "BASELINE_COMPLETE"
    assert result["items"][-1]["expected_count"] == 1
    assert result["items"][0]["baseline_id"] == result["items"][-1]["baseline_id"]


def test_cluster_catalogue_is_public_and_fingerprinted(tmp_path):
    code, payload = service(tmp_path).handle("GET", "/kubernetes/clusters")
    assert code == 200
    assert payload["runner_instance_id"] == "runner-1"
    assert payload["clusters"][0]["cluster_uid"] == "cluster-uid-1"
    assert len(payload["content_fingerprint"]) == 64
    assert "kubeconfig_path" not in json.dumps(payload)


def test_sync_is_idempotent_and_assets_are_paginated(tmp_path):
    instance = service(tmp_path)
    body = request(idempotency_key="manual-1")
    first = instance.handle("POST", "/kubernetes/syncs", body)[1]
    second = instance.handle("POST", "/kubernetes/syncs", body)[1]
    assert first["data"]["sync_id"] == second["data"]["sync_id"]
    sync_id = first["data"]["sync_id"]
    for _ in range(50):
        status = instance.handle("GET", f"/kubernetes/syncs/{sync_id}")[1]
        if status["data"]["status"] == "SUCCEEDED":
            break
        time.sleep(0.01)
    code, page = instance.handle("GET", f"/kubernetes/syncs/{sync_id}/assets")
    assert code == 200
    assert page["data"]["items"][0]["uid"] == "pod-1"


def test_sync_excludes_scaled_to_zero_workloads_and_their_descendants(tmp_path):
    class ScaledClient(FakeClusterClient):
        def assets(self, _cluster):
            return [
                {
                    "kind": "Deployment", "namespace": "prod", "name": "stopped",
                    "uid": "stopped-deploy", "owners": [],
                    "status_summary": {"desired_replicas": 0},
                },
                {
                    "kind": "ReplicaSet", "namespace": "prod", "name": "stopped-rs",
                    "uid": "stopped-rs", "owners": [{"uid": "stopped-deploy"}],
                    "status_summary": {"desired_replicas": 0},
                },
                {
                    "kind": "Pod", "namespace": "prod", "name": "stopped-pod",
                    "uid": "stopped-pod", "owners": [{"uid": "stopped-rs"}],
                    "status_summary": {"phase": "Failed"},
                },
                {
                    "kind": "Deployment", "namespace": "prod", "name": "active",
                    "uid": "active-deploy", "owners": [],
                    "status_summary": {"desired_replicas": 1, "ready_replicas": 1},
                },
                {
                    "kind": "ReplicaSet", "namespace": "prod", "name": "active-old-rs",
                    "uid": "active-old-rs", "owners": [{"uid": "active-deploy"}],
                    "status_summary": {"desired_replicas": 0, "revision": 1},
                },
            ]

    instance = service(tmp_path)
    instance.client = ScaledClient()
    code, started = instance.handle(
        "POST", "/kubernetes/syncs", request(idempotency_key="scaled-zero")
    )
    assert code == 202
    sync_id = started["data"]["sync_id"]
    for _ in range(50):
        status = instance.handle("GET", f"/kubernetes/syncs/{sync_id}")[1]
        if status["data"]["status"] == "SUCCEEDED":
            break
        time.sleep(0.01)

    code, page = instance.handle("GET", f"/kubernetes/syncs/{sync_id}/assets")

    assert code == 200
    assert {item["uid"] for item in page["data"]["items"]} == {
        "active-deploy", "active-old-rs"
    }


def test_inspection_excludes_scaled_to_zero_workloads_and_their_events(tmp_path):
    stopped = {
        "kind": "Deployment", "namespace": "prod", "name": "stopped",
        "uid": "stopped-deploy", "owners": [],
        "status_summary": {"desired_replicas": 0, "ready_replicas": 0},
    }
    stopped_pod = {
        "kind": "Pod", "namespace": "prod", "name": "stopped-pod",
        "uid": "stopped-pod", "owners": [{"uid": "stopped-deploy"}],
        "status_summary": {"phase": "Failed"},
    }
    active = {
        "kind": "Deployment", "namespace": "prod", "name": "active",
        "uid": "active-deploy", "owners": [],
        "status_summary": {
            "desired_replicas": 1, "ready_replicas": 1,
            "available_replicas": 1, "replica_status_observed": True,
        },
    }
    events = [{
        "namespace": "prod", "type": "Warning", "reason": "BackOff",
        "message": "stopped workload event", "object": {
            "kind": "Pod", "name": "stopped-pod", "uid": "stopped-pod"
        },
    }]

    report = health_service(
        tmp_path, [stopped, stopped_pod, active], events=events
    ).deterministic_health("vke-prod")

    assert report["checked_assets"] == 1
    assert report["overall_status"] == "HEALTHY"
    assert report["findings"] == []
    workload = next(
        item for item in report["coverage"] if item["domain"] == "workload"
    )
    assert workload["checked_count"] == 1


def test_official_client_discovers_assets_by_kind(monkeypatch):
    calls = []

    class FakeResource:
        namespaced = False

        def get(self):
            return SimpleNamespace(items=[])

    class FakeResources:
        def get(self, **kwargs):
            calls.append(kwargs)
            return FakeResource()

    client = OfficialKubernetesClient()
    dynamic_client = SimpleNamespace(resources=FakeResources())
    monkeypatch.setattr(client, "_apis", lambda _cluster: (None, None, dynamic_client))
    cluster = ClusterConfig("vke-prod", "VKE", "prod", "unused", "vke-prod")

    assert client.assets(cluster) == []
    assert len(calls) == len(client.RESOURCES)
    assert all(set(call) == {"api_version", "kind"} for call in calls)


def test_official_client_rejects_partial_asset_snapshot(monkeypatch):
    class Forbidden(Exception):
        status = 403

    class FakeResource:
        namespaced = False

        def __init__(self, kind):
            self.kind = kind

        def get(self):
            if self.kind == "Node":
                raise Forbidden("forbidden")
            return SimpleNamespace(items=[])

    class FakeResources:
        def get(self, **kwargs):
            return FakeResource(kwargs["kind"])

    client = OfficialKubernetesClient()
    monkeypatch.setattr(
        client,
        "_apis",
        lambda _cluster: (None, None, SimpleNamespace(resources=FakeResources())),
    )
    cluster = ClusterConfig("vke-prod", "VKE", "prod", "unused", "vke-prod")

    with pytest.raises(KubernetesBoundaryError) as error:
        client.assets(cluster)
    assert error.value.code == "ASSET_COLLECTION_PARTIAL"


def test_safe_asset_normalizes_camel_case_status_and_owner_fields():
    class Item:
        def to_dict(self):
            return {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "api",
                    "namespace": "prod",
                    "uid": "deployment-1",
                    "resourceVersion": "42",
                    "generation": 3,
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                    "managedFields": [
                        {"manager": "deployment-controller", "time": "2026-01-01T01:00:00Z"},
                        {"manager": "kubectl", "time": "2026-01-01T02:00:00Z"},
                    ],
                    "ownerReferences": [
                        {"kind": "Application", "name": "api", "uid": "app-1", "controller": True}
                    ],
                },
                "spec": {"replicas": 2},
                "status": {
                    "observedGeneration": 3,
                    "replicas": 2,
                    "readyReplicas": 2,
                    "availableReplicas": 2,
                    "conditions": [{"type": "Available", "status": "True"}],
                },
            }

    asset = OfficialKubernetesClient()._safe_asset(Item())

    assert asset["resource_version"] == "42"
    assert asset["object_updated_at"] == "2026-01-01T02:00:00Z"
    assert asset["owners"] == [
        {"kind": "Application", "name": "api", "uid": "app-1", "controller": True}
    ]
    assert asset["status_summary"]["ready_replicas"] == 2
    assert asset["status_summary"]["available_replicas"] == 2
    assert asset["status_summary"]["replica_status_observed"] is True


def test_safe_asset_never_defaults_missing_ready_replica_fields_to_zero():
    asset = OfficialKubernetesClient()._safe_asset({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api", "namespace": "prod", "uid": "deployment-1", "generation": 3},
        "spec": {"replicas": 2},
        "status": {"observedGeneration": 3, "replicas": 2},
    })

    summary = asset["status_summary"]
    assert "ready_replicas" not in summary
    assert "available_replicas" not in summary
    assert summary["replica_status_observed"] is False


def test_safe_pod_summary_retains_kubectl_ready_container_counts():
    asset = OfficialKubernetesClient()._safe_asset({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "api", "namespace": "prod", "uid": "pod-1"},
        "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "False"}], "containerStatuses": [
            {"name": "api", "ready": False, "restartCount": 0, "state": {"running": {}}},
        ]}, "spec": {"containers": [{"name": "api", "image": "example/api:1"}]},
    })
    assert asset["status_summary"]["ready_containers"] == 0
    assert asset["status_summary"]["total_containers"] == 1
    assert asset["health_status"] == "WARNING"


def test_generated_watch_registry_covers_every_registered_resource():
    client = OfficialKubernetesClient()
    assert set(client._WATCH_METHODS) == set(client.RESOURCES)
    assert client._WATCH_METHODS[("v1", "Pod")][1:] == (
        "list_pod_for_all_namespaces", "list_namespaced_pod"
    )


def test_raw_endpoint_slice_list_accepts_empty_endpoints_without_model_validation():
    class Response:
        data = b'{"metadata":{"resourceVersion":"42"},"items":[{"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"empty"}}]}'
        closed = False

        def close(self):
            self.closed = True

    response = Response()
    items, resource_version = kubernetes_module._raw_list_payload(response)

    assert resource_version == "42"
    assert items[0]["metadata"]["name"] == "empty"
    assert response.closed is True


def test_v2_does_not_report_healthy_workload_or_managed_replicaset(tmp_path):
    deployment = {
        "api_version": "apps/v1", "kind": "Deployment", "namespace": "prod",
        "name": "api", "uid": "deployment-1", "owners": [], "labels": {},
        "status_summary": {
            "desired_replicas": 2, "replicas": 2, "ready_replicas": 2,
            "available_replicas": 2, "replica_status_observed": True,
            "age_seconds": 3600,
        },
    }
    replica_set = {
        "api_version": "apps/v1", "kind": "ReplicaSet", "namespace": "prod",
        "name": "api-abc", "uid": "rs-1", "labels": {},
        "owners": [{"kind": "Deployment", "name": "api", "uid": "deployment-1", "controller": True}],
        "status_summary": {"desired_replicas": 2, "replicas": 2},
    }

    report = health_service(tmp_path, [deployment, replica_set]).deterministic_health("vke-prod")

    assert report["overall_status"] == "HEALTHY"
    assert report["completion_status"] == "COMPLETE"
    assert report["findings"] == []


def test_v2_groups_failed_job_pods_under_one_root_finding(tmp_path):
    job = {
        "api_version": "batch/v1", "kind": "Job", "namespace": "prod",
        "name": "daily", "uid": "job-1", "owners": [], "labels": {},
        "status_summary": {"failed": 4, "succeeded": 0, "active": 0, "age_seconds": 3600},
    }
    pods = [
        {
            "api_version": "v1", "kind": "Pod", "namespace": "prod",
            "name": f"daily-{index}", "uid": f"pod-{index}", "labels": {},
            "owners": [{"kind": "Job", "name": "daily", "uid": "job-1", "controller": True}],
            "status_summary": {"phase": "Failed", "exit_codes": [1], "age_seconds": 600},
        }
        for index in range(4)
    ]

    report = health_service(tmp_path, [job, *pods]).deterministic_health("vke-prod")

    findings = [item for item in report["findings"] if item["rule_id"] == "K8S_JOB_FAILED"]
    assert len(findings) == 1
    assert findings[0]["root_object_ref"]["kind"] == "Job"
    assert findings[0]["affected_object_count"] == 5


def test_v2_uses_node_ready_condition_and_never_phase(tmp_path):
    node = {
        "api_version": "v1", "kind": "Node", "namespace": None,
        "name": "node-1", "uid": "node-1", "owners": [], "labels": {},
        "status_summary": {
            "conditions": [{"type": "Ready", "status": "False", "reason": "KubeletNotReady"}],
            "age_seconds": 3600,
        },
    }

    report = health_service(tmp_path, [node]).deterministic_health("vke-prod")

    assert report["overall_status"] == "CRITICAL"
    assert report["findings"][0]["rule_id"] == "K8S_NODE_NOT_READY"


def test_v2_partial_collection_cannot_report_healthy(tmp_path):
    resources = [
        {
            "api_version": "v1", "kind": "Node", "status": "UNAUTHORIZED",
            "checked_count": 0, "failure_code": "KUBERNETES_RBAC_UNAUTHORIZED",
        }
    ]

    report = health_service(tmp_path, [], resources=resources).deterministic_health("vke-prod")

    assert report["overall_status"] == "UNKNOWN"
    assert report["completion_status"] == "PARTIAL"
    assert any(item["domain"] == "node" and item["status"] == "UNAVAILABLE" for item in report["coverage"])


def test_v2_missing_workload_ready_evidence_is_unknown_not_replica_gap(tmp_path):
    deployment = {
        "api_version": "apps/v1", "kind": "Deployment", "namespace": "prod",
        "name": "api", "uid": "deployment-1", "owners": [], "labels": {},
        "status_summary": {
            "desired_replicas": 2, "replicas": 2,
            "replica_status_observed": False, "age_seconds": 3600,
        },
    }

    report = health_service(tmp_path, [deployment]).deterministic_health("vke-prod")

    assert report["overall_status"] == "UNKNOWN"
    assert report["completion_status"] == "PARTIAL"
    assert not any(item["rule_id"] == "K8S_WORKLOAD_REPLICA_GAP" for item in report["findings"])
    assert next(item for item in report["coverage"] if item["domain"] == "workload")["status"] == "PARTIAL"


def test_v2_running_pod_without_ready_evidence_cannot_make_report_healthy(tmp_path):
    pod = {
        "api_version": "v1", "kind": "Pod", "namespace": "prod",
        "name": "api-1", "uid": "pod-1", "owners": [], "labels": {},
        "status_summary": {"phase": "Running", "age_seconds": 3600},
    }

    report = health_service(tmp_path, [pod]).deterministic_health("vke-prod")

    assert report["overall_status"] == "UNKNOWN"
    assert next(item for item in report["coverage"] if item["domain"] == "pod")["status"] == "PARTIAL"


def test_v2_endpoint_slice_denied_does_not_create_false_network_finding(tmp_path):
    service_asset = {
        "api_version": "v1", "kind": "Service", "namespace": "prod",
        "name": "api", "uid": "service-1", "owners": [], "labels": {},
        "status_summary": {"selector_count": 1, "service_type": "ClusterIP", "age_seconds": 3600},
    }
    resources = [
        {
            "api_version": api_version,
            "kind": kind,
            "status": "UNAUTHORIZED" if kind == "EndpointSlice" else "COMPLETE",
            "checked_count": 1 if kind == "Service" else 0,
            **({"failure_code": "KUBERNETES_RBAC_UNAUTHORIZED"} if kind == "EndpointSlice" else {}),
        }
        for api_version, kind in OfficialKubernetesClient.RESOURCES
    ]

    report = health_service(tmp_path, [service_asset], resources=resources).deterministic_health("vke-prod")

    assert not any(item["rule_id"] == "K8S_SERVICE_NO_READY_ENDPOINT" for item in report["findings"])
    assert next(item for item in report["coverage"] if item["domain"] == "network")["status"] == "PARTIAL"


def test_v2_complete_endpoint_evidence_detects_service_without_ready_backend(tmp_path):
    service_asset = {
        "api_version": "v1", "kind": "Service", "namespace": "prod",
        "name": "api", "uid": "service-1", "owners": [], "labels": {},
        "status_summary": {"selector_count": 1, "service_type": "ClusterIP", "age_seconds": 3600},
    }

    report = health_service(tmp_path, [service_asset]).deterministic_health("vke-prod")

    assert any(item["rule_id"] == "K8S_SERVICE_NO_READY_ENDPOINT" for item in report["findings"])


def test_v2_transient_pending_pod_observes_grace_period(tmp_path):
    pod = {
        "api_version": "v1", "kind": "Pod", "namespace": "prod",
        "name": "api-pending", "uid": "pod-1", "owners": [], "labels": {},
        "status_summary": {"phase": "Pending", "age_seconds": 120},
    }

    report = health_service(tmp_path, [pod]).deterministic_health("vke-prod")

    assert not any(item["rule_id"] == "K8S_POD_PENDING" for item in report["findings"])


def test_v2_covers_daemonset_crashloop_hpa_pvc_and_deduplicated_events(tmp_path):
    deployment = {
        "api_version": "apps/v1", "kind": "Deployment", "namespace": "prod",
        "name": "api", "uid": "deployment-1", "owners": [], "labels": {},
        "status_summary": {
            "desired_replicas": 1, "available_replicas": 1,
            "replica_status_observed": True, "age_seconds": 3600,
        },
    }
    replica_set = {
        "api_version": "apps/v1", "kind": "ReplicaSet", "namespace": "prod",
        "name": "api-abc", "uid": "rs-1", "labels": {},
        "owners": [{"kind": "Deployment", "name": "api", "uid": "deployment-1", "controller": True}],
        "status_summary": {},
    }
    pod = {
        "api_version": "v1", "kind": "Pod", "namespace": "prod",
        "name": "api-abc-1", "uid": "pod-1", "labels": {},
        "owners": [{"kind": "ReplicaSet", "name": "api-abc", "uid": "rs-1", "controller": True}],
        "status_summary": {
            "phase": "Running", "ready": False, "waiting_reasons": ["CrashLoopBackOff"],
            "restart_count": 8, "age_seconds": 3600,
        },
    }
    daemon_set = {
        "api_version": "apps/v1", "kind": "DaemonSet", "namespace": "kube-system",
        "name": "agent", "uid": "ds-1", "owners": [], "labels": {},
        "status_summary": {
            "desired_number_scheduled": 3, "number_ready": 3,
            "replica_status_observed": True, "age_seconds": 3600,
        },
    }
    hpa = {
        "api_version": "autoscaling/v2", "kind": "HorizontalPodAutoscaler", "namespace": "prod",
        "name": "api", "uid": "hpa-1", "owners": [], "labels": {},
        "status_summary": {"conditions": [{"type": "ScalingActive", "status": "False", "reason": "FailedGetMetric"}]},
    }
    pvc = {
        "api_version": "v1", "kind": "PersistentVolumeClaim", "namespace": "prod",
        "name": "data", "uid": "pvc-1", "owners": [], "labels": {},
        "status_summary": {"phase": "Lost", "storage_class": "vke-ebs"},
    }
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events = [
        {
            "type": "Warning", "reason": "BackOff", "namespace": "prod",
            "object": {"kind": "Pod", "name": "api-abc-1", "uid": "pod-1"},
            "count": count, "last_timestamp": timestamp,
        }
        for count in (1, 2)
    ]

    report = health_service(
        tmp_path, [deployment, replica_set, pod, daemon_set, hpa, pvc], events=events,
    ).deterministic_health("vke-prod")

    rules = [item["rule_id"] for item in report["findings"]]
    assert "K8S_DAEMONSET_READY_GAP" not in rules
    assert "K8S_POD_CONTAINER_WAITING" in rules
    assert "K8S_HPA_CONDITION_ABNORMAL" in rules
    assert "K8S_PVC_LOST" in rules
    event_findings = [item for item in report["findings"] if item["rule_id"] == "K8S_WARNING_EVENT"]
    assert len(event_findings) == 1
    assert event_findings[0]["root_object_ref"]["kind"] == "Deployment"


def test_v2_deterministic_report_matches_shared_json_schema(tmp_path):
    report = health_service(tmp_path, []).deterministic_health("vke-prod")
    schema_path = Path(__file__).parents[2] / "contracts" / "kubernetes-inspection-v2.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert list(Draft202012Validator(schema).iter_errors(report)) == []


def test_v2_finding_truncation_is_explicitly_partial(tmp_path, monkeypatch):
    pods = [
        {
            "api_version": "v1", "kind": "Pod", "namespace": "prod",
            "name": f"failed-{index}", "uid": f"pod-{index}", "owners": [], "labels": {},
            "status_summary": {"phase": "Failed", "age_seconds": 3600},
        }
        for index in range(2)
    ]
    monkeypatch.setattr(kubernetes_module, "INSPECTION_MAX_FINDINGS", 1)

    report = health_service(tmp_path, pods).deterministic_health("vke-prod")

    assert report["snapshot"]["truncated"] is True
    assert report["snapshot"]["finding_count"] == 2
    assert len(report["findings"]) == 1
    assert report["completion_status"] == "PARTIAL"
    report_coverage = next(item for item in report["coverage"] if item["domain"] == "report")
    assert report_coverage["failure_codes"] == ["FINDINGS_TRUNCATED"]


def test_v2_namespace_scope_is_applied_to_event_queries(tmp_path):
    instance = health_service(tmp_path, [])

    instance.deterministic_health("vke-prod", ["prod"])

    assert instance.client.event_queries == [{"namespace": "prod"}]


def test_structured_filters_reject_raw_query_and_namespace_escape(tmp_path):
    instance = service(tmp_path)
    code, payload = instance.handle("POST", "/kubernetes/metrics/history", request(resource_type="pod", metric="cpu_usage", range="1h", promql="up"))
    assert code == 400
    assert payload["error_code"] == "UNSUPPORTED_FILTER"
    code, payload = instance.handle("POST", "/kubernetes/events/current", request(namespace="kube-system"))
    assert code == 403
    assert payload["error_code"] == "NAMESPACE_NOT_ALLOWED"


def test_current_logs_are_bounded_to_one_pod_and_container(tmp_path):
    code, payload = service(tmp_path).handle("POST", "/kubernetes/logs/current", request(namespace="prod", pod="api-1", container="api", tail_lines=99999, previous=True))
    assert code == 200
    assert payload["data"]["previous"] is True


def test_object_queries_resolve_workload_instances_revisions_events_and_logs(tmp_path):
    class ObjectClient(FakeClusterClient):
        def assets(self, _cluster):
            return [
                {
                    "summary_schema_version": 2,
                    "api_version": "apps/v1",
                    "kind": "Deployment",
                    "namespace": "prod",
                    "name": "api",
                    "uid": "deploy-1",
                    "owners": [],
                    "labels": {},
                    "status_summary": {},
                    "spec_summary": {},
                },
                {
                    "summary_schema_version": 2,
                    "api_version": "apps/v1",
                    "kind": "ReplicaSet",
                    "namespace": "prod",
                    "name": "api-abc",
                    "uid": "rs-1",
                    "owners": [
                        {
                            "kind": "Deployment",
                            "name": "api",
                            "uid": "deploy-1",
                            "controller": True,
                        }
                    ],
                    "labels": {},
                    "status_summary": {"revision": 7},
                    "spec_summary": {
                        "containers": [{"name": "api", "image": "example/api:7"}]
                    },
                    "object_created_at": "2026-08-11T00:00:00Z",
                },
                {
                    "summary_schema_version": 2,
                    "api_version": "v1",
                    "kind": "Pod",
                    "namespace": "prod",
                    "name": "api-abc-1",
                    "uid": "pod-1",
                    "owners": [
                        {
                            "kind": "ReplicaSet",
                            "name": "api-abc",
                            "uid": "rs-1",
                            "controller": True,
                        }
                    ],
                    "labels": {},
                    "status_summary": {"phase": "Running"},
                    "spec_summary": {
                        "containers": [{"name": "api", "image": "example/api:7"}]
                    },
                },
            ]

        def current_events(self, _cluster, _query):
            return {
                "items": [
                    {
                        "type": "Warning",
                        "reason": "BackOff",
                        "object": {"uid": "pod-1"},
                        "message": "bounded",
                    }
                ]
            }

    instance = service(tmp_path)
    instance.client = ObjectClient()
    obj = {
        "api_version": "apps/v1",
        "kind": "Deployment",
        "namespace": "prod",
        "name": "api",
        "uid": "deploy-1",
    }

    code, payload = instance.handle(
        "POST", "/kubernetes/objects/instances", request(object=obj, limit=100)
    )
    assert code == 200
    assert payload["data"]["items"][0]["uid"] == "pod-1"

    code, payload = instance.handle(
        "POST", "/kubernetes/objects/revisions", request(object=obj, limit=100)
    )
    assert code == 200
    assert payload["data"]["items"][0]["revision"] == 7

    code, payload = instance.handle(
        "POST",
        "/kubernetes/objects/events/current",
        request(object=obj, scope="SELF_AND_INSTANCES", limit=100),
    )
    assert code == 200
    assert payload["data"]["items"][0]["reason"] == "BackOff"

    code, payload = instance.handle(
        "POST",
        "/kubernetes/objects/logs/current",
        request(object=obj, pod_uid="pod-1", container="api", tail_lines=10),
    )
    assert code == 200
    assert payload["data"]["lines"] == ["ok"]


def test_vmp_promql_is_built_only_from_allowlisted_metric_shape():
    query = {"resource_type": "pod", "metric": "cpu_usage", "namespace": "prod", "resource_name": "api", "range": "1h"}
    rendered = VolcengineHistoryClient()._promql(query)
    assert "container_cpu_usage_seconds_total" in rendered
    assert 'namespace="prod"' in rendered
    assert 'pod="api"' in rendered


def test_runtime_rejects_kubeconfig_exec_authentication(tmp_path):
    kubeconfig = tmp_path / "vke.kubeconfig"
    kubeconfig.write_text(
        yaml.safe_dump(
            {
                "current-context": "vke-prod",
                "contexts": [{"name": "vke-prod", "context": {}}],
                "users": [
                    {
                        "name": "operator",
                        "user": {"exec": {"command": "credential-helper"}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        kubeconfig.chmod(0o600)
    cluster = ClusterConfig(
        id="vke-prod",
        display_name="VKE",
        environment="prod",
        kubeconfig_path=str(kubeconfig),
        context="vke-prod",
    )

    with pytest.raises(KubernetesBoundaryError) as caught:
        KubernetesInventory.validate_local_file(cluster)

    assert caught.value.code == "KUBECONFIG_EXEC_UNSUPPORTED"


def test_inventory_accepts_vke_context_name_with_at_sign(tmp_path):
    context = "cluster-identifier@vke-user-identifier"
    kubeconfig = tmp_path / "vke.kubeconfig"
    kubeconfig.write_text(
        yaml.safe_dump(
            {
                "current-context": context,
                "contexts": [{"name": context, "context": {}}],
                "users": [
                    {"name": "operator", "user": {"token": "local-token"}}
                ],
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        kubeconfig.chmod(0o600)
    inventory_file = tmp_path / "kubernetes.local.yaml"
    inventory_file.write_text(
        yaml.safe_dump(
            {
                "clusters": [
                    {
                        "id": "vke-prod",
                        "display_name": "VKE",
                        "environment": "prod",
                        "kubeconfig_path": str(kubeconfig),
                        "context": context,
                        "namespace_allowlist": [],
                        "vmp": {},
                        "tls": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    cluster = KubernetesInventory(str(inventory_file)).load()["vke-prod"]

    assert cluster.context == context
    assert KubernetesInventory.validate_local_file(cluster)["context"] == context
