"""R4 — generic resource list endpoint: GET /api/v1/clusters/<id>/resources/<kind>.

Docker-free unit tier: the k8s path is a ``FakeK8s`` double injected through
the pool's ``factory`` seam (same as test_clusters.py) and the SAR is the real
``rbac.can`` reading the fake redis (``_cache_get``/``_cache_set`` are the
module seams the unit tests patch). The kind integration tier (``@pytest.mark
.integration``) runs the same endpoint against a real kind cluster —
env-block where no Docker is available, deselected with ``-m "not
integration"``.
"""
import pytest

from app.core.errors import ClusterUnreachableError

KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    "contexts:\n"
    "- name: c\n"
    "  context:\n"
    "    cluster: c\n"
    "    user: u\n"
    "current-context: c\n"
    "users:\n"
    "- name: u\n"
    "  user: {}\n"
)


class FakeK8s:
    """Double standing in for a live K8sClient; ``list_pods`` echoes the
    configured pod list (namespaced, per call)."""

    def __init__(self, kubeconfig: bytes) -> None:
        self.kubeconfig = kubeconfig
        self.created_namespaces: list[str] = []
        self.deleted_namespaces: list[str] = []
        # Toggle (set per test) for the cilium-crds-error-502 scenario: when
        # True the Cilium list methods raise ClusterUnreachableError like the
        # real K8sClient does against an unreachable apiserver.
        self.cilium_unreachable = False
        # Namespaces forwarded to list_volume_snapshots (the SAR-denied test
        # asserts it stays empty — the client call was never made).
        self.vs_ns_calls: list[str | None] = []
        # Namespaces forwarded to list_persistent_volume_claims (the
        # SAR-denied test asserts it stays empty — the client call was
        # never made).
        self.pvc_ns_calls: list[str | None] = []

    def create_namespace(self, name: str) -> dict:
        self.created_namespaces.append(name)
        return {"metadata": {"name": name}}

    def delete_namespace(self, name: str) -> None:
        self.deleted_namespaces.append(name)

    def list_namespaces(self, namespace: str | None) -> list[dict]:
        return [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "team-a"}},
        ]

    def list_pods(self, namespace: str | None) -> list[dict]:
        if namespace is None:
            return [
                {"metadata": {"name": "kubedash-pod", "namespace": "default"}},
                {"metadata": {"name": "other-pod", "namespace": "kube-system"}},
            ]
        return [
            {"metadata": {"name": "kubedash-pod", "namespace": namespace}},
        ]

    def list_nodes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is ignored (mirrors the real
        # K8sClient.list_nodes). NodeStatus + a Ready condition are present so
        # the dashboard's node view can assert on the real shape.
        return [
            {
                "metadata": {"name": "worker-1"},
                "status": {
                    "conditions": [
                        {"type": "Ready", "status": "True"},
                        {"type": "MemoryPressure", "status": "False"},
                    ],
                    "node_info": {"kubelet_version": "v1.31.0", "os_image": "kind"},
                    "addresses": [{"type": "InternalIP", "address": "192.168.0.2"}],
                },
            },
            {
                "metadata": {"name": "control-plane"},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "node_info": {"kubelet_version": "v1.31.0", "os_image": "kind"},
                },
            },
        ]

    def list_roles(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit", "namespace": namespace},
                "rules": [{"resources": ["pods"], "verbs": ["get"]}],
            },
        ]

    def list_rolebindings(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit-binding", "namespace": namespace},
                "role_ref": {
                    "api_group": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "edit",
                },
                "subjects": [
                    {"kind": "User", "name": "jane"},
                    {"kind": "Group", "name": "devs"},
                    {"kind": "ServiceAccount", "name": "builder", "namespace": "team-a"},
                ],
            },
        ]

    def list_cluster_role_bindings(self, _namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "cluster-admin"},
                "role_ref": {
                    "api_group": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "cluster-admin",
                },
                "subjects": [
                    {"kind": "User", "name": "jane"},
                    {"kind": "Group", "name": "system:masters"},
                    {"kind": "ServiceAccount", "name": "builder", "namespace": "ci"},
                ],
            },
        ]

    def list_cluster_roles(self, _namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "edit"},
                "rules": [{"resources": ["pods"], "verbs": ["get"]}],
            },
        ]

    def list_serviceaccounts(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "builder", "namespace": namespace},
                "secrets": [{"name": "builder-token"}],
                "image_pull_secrets": [{"name": "registry-cred"}],
            },
        ]

    def list_secrets(self, namespace: str | None) -> list[dict]:
        return [
            {
                "metadata": {"name": "builder-token", "namespace": namespace},
                "type": "kubernetes.io/service-account-token",
            },
        ]

    def get_secret(self, namespace: str, name: str) -> list[dict]:
        if name != "builder-token":
            return []
        return [
            {
                "metadata": {"name": name, "namespace": namespace},
                "type": "kubernetes.io/service-account-token",
                "data": {"token": "dG9rZW4="},
            },
        ]

    def list_crds(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is ignored (mirrors the real
        # K8sClient.list_crds). The shape mirrors a real CRD to_dict — the
        # instances route reads spec.group/names/scope/versions off it.
        return [
            {
                "metadata": {"name": "applications.argoproj.io"},
                "spec": {
                    "group": "argoproj.io",
                    "names": {"kind": "Application", "plural": "applications"},
                    "scope": "Namespaced",
                    "versions": [
                        {"name": "v1alpha1", "served": True, "storage": True},
                        {"name": "v1", "served": True, "storage": False},
                    ],
                },
            }
        ]

    def get_crd(self, _namespace: str, name: str) -> list[dict]:
        [crd] = self.list_crds(None)
        if crd["metadata"]["name"] != name:
            return []
        return [crd]

    def list_crd_instances(
        self, group: str, version: str, plural: str, namespace: str | None
    ) -> list[dict]:
        # Projected 4.1 shape; the fake echoes the namespace when namespaced.
        self.crd_instance_calls: list[tuple] = []
        self.crd_instance_calls.append((group, version, plural, namespace))
        return [
            {
                "name": "app-1",
                "namespace": namespace,
                "status": "True",
                "type": "Ready",
                "reason": "Ok",
                "message": "all good",
                "created": "2026-01-02T03:04:05Z",
            }
        ]

    def list_network_policies(self, namespace: str | None) -> list[dict]:
        # The all-namespaces branch is DISTINCTLY named (team-b) so the API
        # tests can tell the two branches apart, mirroring list_pods.
        if namespace is None:
            return [
                {
                    "metadata": {"name": "deny-all", "namespace": "default"},
                    "spec": {
                        "pod_selector": {},
                        "policy_types": ["Ingress", "Egress"],
                        "ingress": [],
                        "egress": [{"to": [{"ip_block": {"cidr": "0.0.0.0/0"}}]}],
                    },
                },
                {
                    "metadata": {"name": "deny-all", "namespace": "team-b"},
                    "spec": {"pod_selector": {}, "policy_types": ["Ingress"]},
                },
            ]
        return [
            {
                "metadata": {"name": "deny-all", "namespace": namespace},
                "spec": {
                    "pod_selector": {},
                    "policy_types": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": [{"to": [{"ip_block": {"cidr": "0.0.0.0/0"}}]}],
                },
            }
        ]

    def get_network_policy(self, namespace: str, name: str) -> list[dict]:
        if name != "deny-all":
            return []
        return [
            {
                "metadata": {"name": name, "namespace": namespace},
                "spec": {
                    "pod_selector": {},
                    "policy_types": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": [{"to": [{"ip_block": {"cidr": "0.0.0.0/0"}}]}],
                },
            }
        ]

    def list_cilium_network_policies(self, namespace: str | None) -> list[dict]:
        # The fake models Cilium PRESENT by default (the absence case is
        # tested by overriding to [] on the instance). Namespaced kind: the
        # namespace is honored like the real K8sClient.
        if self.cilium_unreachable:
            raise ClusterUnreachableError("cilium cluster unreachable (test)")
        self.cilium_ns_calls: list[str | None] = []
        self.cilium_ns_calls.append(namespace)
        return [
            {
                "metadata": {"name": "cnp", "namespace": namespace},
                "spec": {"endpointSelector": {}, "ingress": [{"from": []}]},
            }
        ]

    def list_cilium_clusterwide_network_policies(
        self, _namespace: str | None
    ) -> list[dict]:
        # Cluster-scoped: the namespace argument is accepted-and-ignored
        # (mirrors the real K8sClient.list_cilium_clusterwide_network_policies).
        return [
            {"metadata": {"name": "ccnp"}, "spec": {"endpointSelector": {}, "egress": []}}
        ]

    def get_cilium_network_policy(self, namespace: str, name: str) -> list[dict]:
        if name != "cnp":
            return []
        return [
            {
                "metadata": {"name": name, "namespace": namespace},
                "spec": {"endpointSelector": {}, "ingress": [{"from": []}]},
            }
        ]

    def list_priority_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is accepted-and-ignored
        # (mirrors the real K8sClient.list_priority_classes).
        return [
            {
                "metadata": {
                    "name": "high",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "annotations": None,
                    "labels": {"tier": "critical"},
                },
                "value": 1000,
                "global_default": False,
                "preemption_policy": "PreemptLowerPriority",
                "description": "High priority",
            }
        ]

    def get_priority_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "high":
            return self.list_priority_classes(None)
        return []

    def list_runtime_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is accepted-and-ignored
        # (mirrors the real K8sClient.list_runtime_classes).
        return [
            {
                "metadata": {
                    "name": "runc",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"provider": "docker"},
                },
                "handler": "runc",
                "overwrite_node_sel_no_toleration": False,
                "scheduling": {
                    "node_selector": {"kubernetes.io/runtime": "runc"},
                    "tolerations": [],
                },
                "pod_level_overhead": {"memory": "128Mi", "cpu": "100m"},
            }
        ]

    def get_runtime_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "runc":
            return self.list_runtime_classes(None)
        return []

    def list_storage_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped (storage/v1): the namespace is accepted-and-ignored
        # (mirrors the real K8sClient.list_storage_classes). The route
        # forwards the raw query value; the recording is the "the
        # cluster-scoped call was used" evidence for the ignores-namespace
        # test (the returned fixture is the cluster-scoped item).
        self.storageclass_ns_calls: list[str | None] = []
        self.storageclass_ns_calls.append(_namespace)
        return [
            {
                "metadata": {
                    "name": "csi-fast",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "annotations": {"storageclass.kubernetes.io/is-default-class": "true"},
                    "labels": {"team": "a"},
                },
                "provisioner": "csi.example.com",
                "reclaim_policy": "Delete",
                "volume_binding_mode": "WaitForFirstConsumer",
                "parameters": {"type": "standard"},
            }
        ]

    def get_storage_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "csi-fast":
            return self.list_storage_classes(None)
        return []

    def list_resource_quotas(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (core): the namespace is forwarded (the real
        # K8sClient.list_resource_quotas pattern). The all-namespaces branch is
        # DISTINCTLY named (team-b) so the API tests can tell the branches
        # apart, mirroring list_network_policies.
        if namespace is None:
            return [
                {
                    "metadata": {"name": "compute", "namespace": "team-b"},
                    "status": {"used": {"pods": "1"}, "hard": {"pods": "10"}},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "compute",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {"quota.kubernetes.io/managed-by": "kubedash"},
                },
                "spec": {
                    "hard": {
                        "requests.cpu": "4",
                        "requests.memory": "10Gi",
                        "limits.cpu": "8",
                        "limits.memory": "20Gi",
                    },
                    "scopes": ["NotBestEffort"],
                },
                "status": {
                    "hard": {
                        "requests.cpu": "4",
                        "requests.memory": "10Gi",
                        "limits.cpu": "8",
                        "limits.memory": "20Gi",
                    },
                    "used": {
                        "requests.cpu": "2",
                        "requests.memory": "4Gi",
                        "limits.cpu": "4",
                        "limits.memory": "8Gi",
                    },
                },
            }
        ]

    def get_resource_quota(self, namespace: str, name: str) -> list[dict]:
        if name == "compute":
            return self.list_resource_quotas(namespace)
        return []

    def list_pod_disruption_budgets(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (policy/v1): the namespace is forwarded (the real
        # K8sClient.list_pod_disruption_budgets pattern). The all-namespaces
        # branch is DISTINCTLY named (team-b) so the API tests can tell the
        # branches apart, mirroring list_network_policies.
        if namespace is None:
            return [
                {
                    "metadata": {"name": "web", "namespace": "team-b"},
                    "spec": {"min_available": 3, "selector": {"match_labels": {"app": "web"}}},
                    "status": {"disruptions_allowed": 1, "current_healthy": 4},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "web",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {"pdb.kubernetes.io/managed-by": "kubedash"},
                },
                "spec": {
                    "min_available": 3,
                    "selector": {"match_labels": {"app": "web"}},
                    "unhealthy_pod_eviction_policy": "AlwaysAllow",
                },
                "status": {
                    "observed_generation": 1,
                    "current_healthy": 4,
                    "desired": 3,
                    "total_pods": 4,
                    "expected_pods": 3,
                    "disruptions_allowed": 1,
                    "conditions": [
                        {
                            "type": "Available",
                            "status": "True",
                            "reason": "SufficientPods",
                            "message": "PodDisruptionBudget is available",
                        }
                    ],
                },
            }
        ]

    def get_pod_disruption_budget(self, namespace: str, name: str) -> list[dict]:
        if name == "web":
            return self.list_pod_disruption_budgets(namespace)
        return []

    def list_vertical_pod_autoscalers(self, namespace: str | None) -> list[dict]:
        # Namespaced CRD (autoscaling.k8s.io): the namespace is forwarded;
        # the FULL custom object (spec + status) is returned (camelCase). The
        # all-namespaces branch is DISTINCTLY named (team-b) so the API tests
        # can tell the branches apart, mirroring list_network_policies.
        self.vpa_ns_calls: list[str | None] = []
        self.vpa_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "web-vpa", "namespace": "team-b"},
                    "spec": {"targetRef": {"kind": "Deployment", "name": "web"}},
                    "status": {},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "web-vpa",
                    "namespace": namespace or "team-a",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {"vpa.kubernetes.io/managed-by": "kubedash"},
                },
                "spec": {
                    "targetRef": {"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"},
                    "updatePolicy": {"updateMode": "Auto"},
                    "resourcePolicy": {
                        "containerPolicies": [
                            {
                                "containerName": "app",
                                "controlledValues": "RequestsLimits",
                                "mode": "Auto",
                                "minAllowed": {"memory": "128Mi"},
                                "maxAllowed": {"memory": "1Gi"},
                                "controlledResources": ["cpu", "memory"],
                            }
                        ]
                    },
                },
                "status": {
                    "conditions": [
                        {
                            "type": "RecommendationProvided",
                            "status": "True",
                            "lastTransitionTime": "2026-01-02T03:04:06Z",
                            "reason": "RecommendationAvailable",
                            "message": "recommendation available",
                        }
                    ]
                },
            }
        ]

    def get_vertical_pod_autoscaler(self, namespace: str, name: str) -> list[dict]:
        if name == "web-vpa":
            return self.list_vertical_pod_autoscalers(namespace)
        return []

    def list_horizontal_pod_autoscalers(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (autoscaling/v1, core): the namespace is forwarded
        # (the real K8sClient.list_horizontal_pod_autoscalers pattern). The
        # all-namespaces branch is DISTINCTLY named (team-b) so the API
        # tests can tell the branches apart, mirroring list_network_policies.
        self.hpa_ns_calls: list[str | None] = []
        self.hpa_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "web-hpa", "namespace": "team-b"},
                    "spec": {"max_replicas": 10, "min_replicas": 2},
                    "status": {"current_replicas": 3},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "web-hpa",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {},
                },
                "spec": {
                    "scale_target_ref": {"kind": "Deployment", "name": "web", "api_version": "apps/v1"},
                    "min_replicas": 2,
                    "max_replicas": 10,
                    "target_cpu_utilization_percentage": 80,
                },
                "status": {
                    "current_replicas": 3,
                    "desired_replicas": 3,
                    "current_cpu_utilization_percentage": 50,
                    "conditions": [
                        {
                            "type": "AbleToScale",
                            "status": "True",
                            "last_transition_time": "2026-01-02T03:04:06Z",
                            "reason": "SuccessfulRescale",
                            "message": "Ready to scale",
                        }
                    ],
                },
            }
        ]

    def get_horizontal_pod_autoscaler(self, namespace: str, name: str) -> list[dict]:
        if name == "web-hpa":
            return self.list_horizontal_pod_autoscalers(namespace)
        return []

    def list_limit_ranges(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (core): the namespace is forwarded (the real
        # K8sClient.list_limit_ranges pattern). The all-namespaces branch is
        # DISTINCTLY named (team-b) so the API tests can tell the branches
        # apart, mirroring list_network_policies.
        self.limitrange_ns_calls: list[str | None] = []
        self.limitrange_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "default", "namespace": "team-b"},
                    "spec": {"limits": [{"type": "Container", "max": {"memory": "4Gi"}}]},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "default",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"app": "limits"},
                },
                "spec": {
                    "limits": [
                        {
                            "type": "Container",
                            "max": {"cpu": "2", "memory": "4Gi"},
                            "min": {"cpu": "500m", "memory": "1Gi"},
                            "default": {"cpu": "1", "memory": "2Gi"},
                            "defaultRequest": {"cpu": "250m", "memory": "512Mi"},
                            "maxLimitRequestRatio": {"cpu": "2", "memory": "4"},
                        }
                    ]
                },
            }
        ]

    def get_limit_range(self, namespace: str, name: str) -> list[dict]:
        if name == "default":
            return self.list_limit_ranges(namespace)
        return []

    def list_configmaps(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (core): the namespace is forwarded (the real
        # K8sClient.list_configmaps pattern). The all-namespaces branch is
        # DISTINCTLY named (team-b) so the API tests can tell the branches
        # apart, mirroring list_network_policies. ``data`` is present (NOT
        # stripped, unlike secrets) — the list view's Data Keys column
        # reads it.
        self.configmap_ns_calls: list[str | None] = []
        self.configmap_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "app-config", "namespace": "team-b"},
                    "data": {"LOG_LEVEL": "warn"},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "app-config",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "resource_version": "4242",
                    "labels": {"app": "web"},
                    "annotations": {
                        "kubectl.kubernetes.io/last-applied-configuration": "{}",
                        "owner": "platform",
                    },
                },
                "data": {"LOG_LEVEL": "info", "URL": "https://internal"},
            },
            {
                "metadata": {
                    "name": "empty-cm",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-03T00:00:00Z",
                },
                "data": {},
            },
            {
                "metadata": {
                    "name": "no-data-cm",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-04T00:00:00Z",
                },
            },
        ]

    def get_configmap(self, namespace: str, name: str) -> list[dict]:
        return [cm for cm in self.list_configmaps(namespace) if cm["metadata"]["name"] == name]

    def list_volume_snapshot_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped CRD (snapshot.storage.k8s.io): the namespace is
        # accepted-and-ignored (mirrors the real
        # K8sClient.list_volume_snapshot_classes). FULL custom object,
        # camelCase (driver / deletionPolicy / parameters intact). The route
        # forwards the raw query value; the recording is the "the
        # cluster-scoped call was used" evidence for the ignores-namespace
        # test.
        self.snapshotclass_ns_calls: list[str | None] = []
        self.snapshotclass_ns_calls.append(_namespace)
        return [
            {
                "apiVersion": "snapshot.storage.k8s.io/v1",
                "kind": "VolumeSnapshotClass",
                "metadata": {
                    "name": "csi-default",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "annotations": {
                        "snapshot.storage.kubernetes.io/is-default-class": "true",
                    },
                    "labels": {"team": "a"},
                },
                "driver": "csi-driver.example.com",
                "deletionPolicy": "Delete",
                "parameters": {"blockVolume": "true", "fstype": "ext4"},
            }
        ]

    def get_volume_snapshot_class(self, _namespace: str, name: str) -> list[dict]:
        return [
            sc for sc in self.list_volume_snapshot_classes(None) if sc["metadata"]["name"] == name
        ]

    def list_volume_snapshots(self, namespace: str | None) -> list[dict]:
        # Namespaced CRD (snapshot.storage.k8s.io): the namespace is honored;
        # the FULL custom object (spec + status) is returned (camelCase). The
        # all-namespaces branch is DISTINCTLY named (team-b) so the API tests
        # can tell the branches apart, mirroring list_vertical_pod_autoscalers.
        self.vs_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "snap-a", "namespace": "team-b"},
                    "spec": {"source": {"persistentVolumeClaimName": "pvc-snap-a"}},
                    "status": {},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "snap-a",
                    "namespace": namespace or "team-a",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                },
                "spec": {
                    "source": {"persistentVolumeClaimName": "pvc-snap-a"},
                    "volumeSnapshotClassName": "csi-snap",
                },
                "status": {
                    "readyToUse": True,
                    "restoreSize": "1Gi",
                    "boundVolumeSnapshotContentName": "content-snap-a",
                },
            }
        ]

    def get_volume_snapshot(self, namespace: str, name: str) -> list[dict]:
        if name == "snap-a":
            return self.list_volume_snapshots(namespace)
        return []

    def list_persistent_volume_claims(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (core v1): the namespace is forwarded (the real
        # K8sClient.list_persistent_volume_claims pattern). The all-namespaces
        # branch is DISTINCTLY named (team-b) so the API tests can tell the
        # branches apart, mirroring list_network_policies.
        self.pvc_ns_calls.append(namespace)
        if namespace is None:
            return [
                {
                    "metadata": {"name": "data-pvc", "namespace": "team-b"},
                    "status": {"phase": "Bound", "capacity": {"storage": "1Gi"}},
                },
            ]
        return [
            {
                "metadata": {
                    "name": "data-pvc",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
                    "labels": {"team": "a"},
                },
                "spec": {
                    "storage_class_name": "csi-fast",
                    "volume_name": "pv-1",
                    "access_modes": ["ReadWriteOnce"],
                    "volume_mode": "Filesystem",
                },
                "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
            }
        ]

    def get_persistent_volume_claim(self, namespace: str, name: str) -> list[dict]:
        if name == "data-pvc":
            return self.list_persistent_volume_claims(namespace)
        return []

    def readyz(self) -> bool:
        return True


@pytest.fixture()
def fake_k8s(api_app, monkeypatch) -> FakeK8s:
    """Inject the FakeK8s factory into the module pool (the Task 4 seam).

    The handler does ``from app.services.k8s_client import pool`` — a copy
    into ``api_app.api.resources.__dict__`` — so the patch must target the
    ``resources`` module's binding, not ``k8s_client.pool`` (the test_clusters
    fixture patches ``kc.pool`` and works there because no module holds a
    copied reference to the pool).
    """
    import importlib

    import app.services.k8s_client as kc

    fake = FakeK8s(b"unused")
    res = importlib.import_module("app.api.resources")
    fake_pool = kc.K8sClientPool(factory=lambda plain: fake)
    monkeypatch.setitem(res.__dict__, "pool", fake_pool)
    return fake


def _allow_sar(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let every SAR through (the unit tier does not model cluster RBAC)."""
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", lambda client, verb, resource, ns, name, group="": True)


def _make_admin(api_client) -> None:
    """OIDC login creates a role=user row; namespace mutations require admin."""
    from app.extensions import db
    from app.models.user import User

    with api_client.application.app_context():
        user = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        user.role = "admin"
        db.session.commit()


def _register(api_client, headers, name="prod") -> object:
    return api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )


def test_unknown_kind_404_stable_code(api_client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/widgets", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_unbound_cluster_404(api_client, auth_client) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    # No cluster 999 was ever registered — the binding gate fails first.
    r = api_client.get("/api/v1/clusters/999/resources/pods", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_unbound_user_404(api_client, auth_client, api_app, fake_k8s, monkeypatch) -> None:
    """A cluster that exists but is bound to another user is invisible —
    same CLUSTER_NOT_FOUND, the binding gate does not distinguish (R3)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r1 = _register(api_client, h, name="other-users-cluster")
    assert r1.status_code == 201
    # A second, unbound user.
    with api_app.app_context():
        from app.core.security import issue_token_pair
        from app.extensions import db
        from app.models.user import User

        u = User(sub="unbound-user", email="ub@example.com")
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
    r = api_client.get(
        f"/api/v1/clusters/{r1.get_json()['id']}/resources/pods",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_list_pods_200_with_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """list-pods-for-bound-cluster (SATISFIES; acceptance.feature pending,
    Task 12): a bound user listing pods gets the pod list back."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "pods"
    assert body["cluster"] == "prod"
    names = [p["metadata"]["name"] for p in body["items"]]
    assert "kubedash-pod" in names


def test_list_namespaces_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The header selector lists namespaces on the selected cluster."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/namespaces", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "namespaces"
    assert [item["metadata"]["name"] for item in body["items"]] == ["default", "team-a"]


def test_list_nodes_200_cluster_scoped(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The node view lists cluster-scoped nodes (SATISFIES the node route).

    Nodes are cluster-scoped: the namespace query does not apply, and the
    SAR verb is ``list`` on ``nodes`` (ADR-0004 enforcement point)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/nodes", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "nodes"
    assert [item["metadata"]["name"] for item in body["items"]] == ["worker-1", "control-plane"]


def test_list_pods_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods?namespace=prod-ns", headers=h)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert [p["metadata"]["namespace"] for p in items] == ["prod-ns"]


def test_list_rolebindings_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > RoleBindings page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/rolebindings?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "rolebindings"
    [binding] = body["items"]
    assert binding["metadata"] == {"name": "edit-binding", "namespace": "team-a"}
    assert binding["role_ref"]["kind"] == "Role"
    assert binding["role_ref"]["name"] == "edit"
    assert binding["subjects"][0]["name"] == "jane"


def test_list_roles_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > Roles page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/roles?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "roles"
    [role] = body["items"]
    assert role["metadata"] == {"name": "edit", "namespace": "team-a"}
    assert role["rules"] == [{"resources": ["pods"], "verbs": ["get"]}]


def test_list_clusterrolebindings(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """Cluster Permissions > Cluster Role Bindings lists the cluster-scoped kind."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/clusterrolebindings?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "clusterrolebindings"
    [binding] = body["items"]
    assert binding["metadata"] == {"name": "cluster-admin"}
    assert binding["role_ref"]["kind"] == "ClusterRole"
    assert binding["role_ref"]["name"] == "cluster-admin"
    assert binding["subjects"][0]["name"] == "jane"


def test_list_clusterroles(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """Cluster Permissions > Cluster Role lists the cluster-scoped kind."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/clusterroles?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "clusterroles"
    [role] = body["items"]
    assert role["metadata"] == {"name": "edit"}
    assert role["rules"] == [{"resources": ["pods"], "verbs": ["get"]}]


def test_list_serviceaccounts_namespaced(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Cluster Permissions > ServiceAccounts page lists one namespace."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/serviceaccounts?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "serviceaccounts"
    [sa] = body["items"]
    assert sa["metadata"] == {"name": "builder", "namespace": "team-a"}
    assert sa["secrets"] == [{"name": "builder-token"}]
    assert sa["image_pull_secrets"] == [{"name": "registry-cred"}]


def test_list_secrets_namespaced_without_data(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The Security > Secrets page lists one namespace: names and types only."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "secrets"
    [secret] = body["items"]
    assert secret == {
        "metadata": {"name": "builder-token", "namespace": "team-a"},
        "type": "kubernetes.io/service-account-token",
    }


def test_get_secret_by_name_returns_data(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The secret data page reads one secret, data still base64."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/secrets?namespace=team-a&name=builder-token", headers=h
    )
    assert r.status_code == 200
    [secret] = r.get_json()["items"]
    assert secret["metadata"] == {"name": "builder-token", "namespace": "team-a"}
    assert secret["data"] == {"token": "dG9rZW4="}


def test_get_missing_secret_returns_no_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a&name=gone", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def _record_sar(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Deny every SAR and record what was asked."""
    import app.services.rbac as rb

    asked: list[tuple] = []
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)

    def deny(client, verb, resource, ns, name, group=""):
        asked.append((verb, resource, ns, name, group))
        return False

    monkeypatch.setattr(rb, "_sar_allowed", deny)
    return asked


def test_list_secrets_asks_sar_for_list(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a", headers=h)
    assert r.status_code == 403
    assert asked == [("list", "secrets", "team-a", None, "")]


def test_get_secret_asks_sar_for_get_on_that_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/secrets?namespace=team-a&name=db", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [("get", "secrets", "team-a", "db", "")]


def test_name_lookup_on_kind_without_getter_404(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/pods?namespace=team-a&name=web", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_rbac_denied_403(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """SAR deny -> 403 RBAC_DENIED: the service seam (``_sar_allowed``) is
    the unit-tier stand-in for a cluster that lacks the grant."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", lambda api_client, verb, resource, ns, name, group="": False)
    r = api_client.get("/api/v1/clusters/1/resources/pods", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


def test_admin_creates_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 201
    assert r.get_json()["name"] == "team-b"
    assert fake_k8s.created_namespaces == ["team-b"]


@pytest.mark.parametrize(
    "name", ["default", "kube-system", "kube-public", "kube-node-lease"]
)
def test_protected_namespace_delete_is_rejected_without_client_call(
    api_client, auth_client, fake_k8s, monkeypatch, name
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        f"/api/v1/clusters/1/resources/namespaces/{name}", headers=h
    )
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "CLUSTER_ALREADY_EXISTS"
    assert fake_k8s.deleted_namespaces == []


def test_admin_deletes_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.delete(
        "/api/v1/clusters/1/resources/namespaces/team-b", headers=h
    )
    assert r.status_code == 200
    assert r.get_json() == {"name": "team-b"}
    assert fake_k8s.deleted_namespaces == ["team-b"]


def test_namespace_create_requires_admin(
    api_client, auth_client, api_app, fake_k8s, monkeypatch
) -> None:
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User

    auth_client.login()
    admin_headers = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, admin_headers)
    with api_app.app_context():
        cluster = db.session.get(Cluster, 1)
        user = User(sub="plain-user", email="plain@example.com", role="user")
        db.session.add(user)
        db.session.flush()
        db.session.add(ClusterBinding(user_id=user.id, cluster_id=cluster.id, role="viewer"))
        db.session.commit()
        access, _ = issue_token_pair(user)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert fake_k8s.created_namespaces == []


def test_namespace_create_asks_sar_for_create(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "team-b"},
        headers=h,
    )
    assert r.status_code == 403
    assert asked == [("create", "namespaces", None, None, "")]


def test_invalid_namespace_name_is_422(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    _make_admin(api_client)
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.post(
        "/api/v1/clusters/1/resources/namespaces",
        json={"name": "Not Valid"},
        headers=h,
    )
    assert r.status_code == 422
    assert r.get_json()["error"]["code"] == "INVALID_KUBECONFIG"
    assert fake_k8s.created_namespaces == []


def test_list_crds_200_cluster_scoped(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The CRDs view lists cluster-scoped CRDs (SAR on
    ``list customresourcedefinitions`` in ``apiextensions.k8s.io``)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "crds"
    assert body["cluster"] == "prod"
    [crd] = body["items"]
    assert crd["metadata"]["name"] == "applications.argoproj.io"


def test_get_crd_by_name_returns_single_item(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The CRD detail page reads one CRD via the ``_GETTERS`` path."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 200
    [crd] = r.get_json()["items"]
    assert crd["spec"]["group"] == "argoproj.io"


def test_get_missing_crd_returns_no_items(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds?name=gone.example.io", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_crds_asks_sar_for_list(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds", headers=h)
    assert r.status_code == 403
    assert asked == [("list", "customresourcedefinitions", None, None, "apiextensions.k8s.io")]


def test_get_crd_asks_sar_for_get_on_that_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """The ``?name=`` lookup is SAR-gated with ``get`` (matching the secrets
    ``_GETTERS`` precedent), not ``list``."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # namespace defaults to "default" on the ``?name=`` path (the shared
    # _GETTERS convention — see the secrets ``?name=`` tests); the CRD is
    # cluster-scoped so the value is cosmetic, but the SAR cache key carries it.
    assert asked == [
        ("get", "customresourcedefinitions", "default", "applications.argoproj.io", "apiextensions.k8s.io")
    ]


def test_get_crd_by_name_sar_allow_returns_item(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds?name=applications.argoproj.io", headers=h
    )
    assert r.status_code == 200
    assert len(r.get_json()["items"]) == 1


def test_list_crd_instances_200_namespaced(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """The CRD detail page lists the CRD's instances: two SARs (list on the
    CRD + list on the instances) both pass, the namespace is applied because
    the fake CRD is Namespaced-scoped."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances"
        "?name=applications.argoproj.io&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "crds"
    [inst] = body["items"]
    assert inst["name"] == "app-1"
    assert inst["namespace"] == "team-a"
    # The instances route prefers the STORAGE served version (v1alpha1 in the
    # fake CRD), not the first declared version.
    assert fake_k8s.crd_instance_calls == [("argoproj.io", "v1alpha1", "applications", "team-a")]


def test_list_crd_instances_first_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """A deny on the FIRST gate (list on the CRD) short-circuits: only one
    SAR is recorded, and the 403 names customresourcedefinitions. The second
    SAR (list on the instances) is never asked."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=applications.argoproj.io",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [
        ("list", "customresourcedefinitions", None, "applications.argoproj.io", "apiextensions.k8s.io")
    ]


def test_list_crd_instances_second_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """The first SAR (list on the CRD) passes; the second (list on the
    instances) is denied — the 403 names the instance plural, and the client
    method is never called."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    import app.services.rbac as rb

    asked: list[tuple] = []

    def selective(client, verb, resource, ns, name, group=""):
        asked.append((verb, resource, ns, name, group))
        # Allow the CRD read, deny the instance list.
        return resource == "customresourcedefinitions"

    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", selective)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=applications.argoproj.io&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert asked == [
        ("list", "customresourcedefinitions", None, "applications.argoproj.io", "apiextensions.k8s.io"),
        ("list", "applications", "team-a", None, "argoproj.io"),
    ]


def test_list_crd_instances_missing_crd_404(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """A ``?name=`` that no CRD matches is a CLUSTER_NOT_FOUND, not a 500 —
    the second SAR is never asked (the CRD read is what resolves it)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/crds/instances?name=gone.example.io", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_list_crd_instances_requires_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/crds/instances", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_networkpolicies_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[networkpolicies-list-namespaced] a bound user listing
    networkpolicies in one namespace gets the to_dict items back, spec
    (policy_types, ingress, egress) intact."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "networkpolicies"
    [policy] = body["items"]
    assert policy["metadata"]["name"] == "deny-all"
    assert policy["metadata"]["namespace"] == "team-a"
    assert policy["spec"]["policy_types"] == ["Ingress", "Egress"]
    assert policy["spec"]["egress"] == [{"to": [{"ip_block": {"cidr": "0.0.0.0/0"}}]}]


def test_list_networkpolicies_all_namespaces(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[networkpolicies-list-all-namespaces] no namespace query hits the
    all-namespaces branch: the distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/networkpolicies", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "networkpolicies"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["default", "team-b"]


def test_get_network_policy_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[networkpolicies-get-by-name] ``?name=`` returns a 0/1-item list: a
    hit returns the one item, a miss returns ``[]`` (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a&name=deny-all",
        headers=h,
    )
    assert r.status_code == 200
    [policy] = r.get_json()["items"]
    assert policy["metadata"] == {"name": "deny-all", "namespace": "team-a"}
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a&name=ghost",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_networkpolicies_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[networkpolicies-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the group — a deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/networkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # the SAR was asked BEFORE the read, with the group (ADR-0004 cache key):
    assert ("list", "networkpolicies", "team-a", None, "networking.k8s.io") in asked


def test_networkpolicies_binding_404(api_client, auth_client) -> None:
    """[networkpolicies-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/networkpolicies", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_kind_singular_network_policy_rejected(api_client, auth_client) -> None:
    """[networkpolicies-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/network-policy", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_ciliumnetworkpolicies_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[cilium-list-uses-served-version] a bound user listing ciliumnetworkpolicies
    in one namespace gets the to_dict items back, spec (endpointSelector,
    ingress) intact. The served version is resolved from the CRD's own spec
    (autodetect) — the fake models Cilium present on v2alpha1."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "ciliumnetworkpolicies"
    [policy] = body["items"]
    assert policy["metadata"]["name"] == "cnp"
    assert policy["metadata"]["namespace"] == "team-a"
    assert policy["spec"]["endpointSelector"] == {}
    assert policy["spec"]["ingress"] == [{"from": []}]


def test_list_ciliumclusterwidenetworkpolicies_200_ignores_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[cilium-clusterwide-ignores-namespace] called WITH ?namespace=team-a,
    still 200; the clusterwide kind is cluster-scoped — the namespace is
    accepted-and-ignored (the same ccnp item comes back)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "ciliumclusterwidenetworkpolicies"
    [policy] = body["items"]
    assert policy["metadata"]["name"] == "ccnp"
    # No namespace on a cluster-scoped item.
    assert "namespace" not in policy["metadata"]


def test_ciliumclusterwidenetworkpolicies_name_lookup_not_supported(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[cilium-clusterwide-ignores-namespace] ?name= on the clusterwide kind
    is 404 RESOURCE_KIND_NOT_SUPPORTED (no _GETTERS row — list-only by design)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies?name=ccnp",
        headers=h,
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_cilium_sar_gated(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[cilium-sar-gated] ADR-0004: the SAR is asked BEFORE the read, with the
    cilium.io group — a deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # The SAR was asked BEFORE the read, with the cilium.io group and the
    # namespace (ADR-0004 cache key).
    assert ("list", "ciliumnetworkpolicies", "team-a", None, "cilium.io") in asked


def test_cilium_absent_crds_empty_200(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[cilium-crds-absent-empty] Cilium not installed = expected state, not
    an error: the FakeK8s Cilium methods return [] and the API responds 200
    with zero items for both Cilium kinds."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    # Model Cilium absent: both Cilium kinds return empty.
    fake_k8s.list_cilium_network_policies = lambda ns: []
    fake_k8s.list_cilium_clusterwide_network_policies = lambda ns: []
    fake_k8s.get_cilium_network_policy = lambda ns, name: []

    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []
    assert r.get_json()["kind"] == "ciliumnetworkpolicies"

    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []
    assert r.get_json()["kind"] == "ciliumclusterwidenetworkpolicies"


def test_list_ciliumnetworkpolicies_502_on_unreachable(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[cilium-crds-error-502] API tier: the FakeK8s Cilium list raises
    ClusterUnreachableError (the same exception the real K8sClient raises
    against an unreachable apiserver) and the handler maps it to 502 with
    the shared CLUSTER_UNREACHABLE error code — pinned here, not just at
    the service tier."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    # Model an unreachable apiserver for the Cilium read (the fake's default
    # models it reachable — the absence case is a separate, empty-list test).
    fake_k8s.cilium_unreachable = True
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 502
    assert r.get_json()["error"]["code"] == "CLUSTER_UNREACHABLE"


def test_get_cilium_network_policy_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[cilium-get-by-name] ?name= on the namespaced kind: a hit returns the
    one item, a miss returns [] (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a&name=cnp",
        headers=h,
    )
    assert r.status_code == 200
    [policy] = r.get_json()["items"]
    assert policy["metadata"]["name"] == "cnp"
    assert policy["metadata"]["namespace"] == "team-a"
    assert policy["spec"]["ingress"] == [{"from": []}]

    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a&name=ghost",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_get_cilium_network_policy_absent_crds_empty(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[cilium-get-by-name] CRD absent (Cilium not installed) -> 200 with
    zero items, not an error."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    fake_k8s.get_cilium_network_policy = lambda ns, name: []
    r = api_client.get(
        "/api/v1/clusters/1/resources/ciliumnetworkpolicies?namespace=team-a&name=cnp",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_priorityclasses_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[priorityclasses-list-200] a bound user listing priorityclasses gets
    the to_dict items back, spec fields (value, preemption_policy,
    global_default, description) intact."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/priorityclasses", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "priorityclasses"
    [item] = body["items"]
    assert item["metadata"]["name"] == "high"
    assert item["value"] == 1000
    assert item["preemption_policy"] == "PreemptLowerPriority"
    assert item["global_default"] is False
    assert item["description"] == "High priority"


def test_list_priorityclasses_ignores_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[priorityclasses-list-ignores-namespace] the kind is cluster-scoped:
    ?namespace=team-a is accepted and ignored — the same "high" item comes
    back."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/priorityclasses?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    [item] = body["items"]
    assert item["metadata"]["name"] == "high"
    assert "namespace" not in item["metadata"]


def test_get_priority_class_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[priorityclasses-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one item, a miss returns [] (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/priorityclasses?name=high", headers=h)
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "high"
    r = api_client.get("/api/v1/clusters/1/resources/priorityclasses?name=ghost", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_priorityclasses_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[priorityclasses-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the scheduling.k8s.io group and namespace None (the
    cluster-scoped SAR cache key) — a deny short-circuits to 403
    RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/priorityclasses", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "priorityclasses", None, None, "scheduling.k8s.io") in asked


def test_priorityclasses_binding_404(api_client, auth_client) -> None:
    """[priorityclasses-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/priorityclasses", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_priorityclass_kind_singular_rejected(api_client, auth_client) -> None:
    """[priorityclasses-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/priorityclass", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_runtimeclasses_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[runtimeclasses-list-200] a bound user listing runtimeclasses gets
    the to_dict items back, spec fields (handler,
    overwrite_node_sel_no_toleration, scheduling, pod_level_overhead)
    intact."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/runtimeclasses", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "runtimeclasses"
    [item] = body["items"]
    assert item["metadata"]["name"] == "runc"
    assert item["handler"] == "runc"
    assert item["overwrite_node_sel_no_toleration"] is False
    assert item["scheduling"]["node_selector"] == {"kubernetes.io/runtime": "runc"}
    assert item["pod_level_overhead"] == {"memory": "128Mi", "cpu": "100m"}


def test_list_runtimeclasses_ignores_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[runtimeclasses-list-ignores-namespace] the kind is cluster-scoped:
    ?namespace=team-a is accepted and ignored — the same "runc" item comes
    back."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/runtimeclasses?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    [item] = body["items"]
    assert item["metadata"]["name"] == "runc"
    assert "namespace" not in item["metadata"]


def test_list_runtimeclasses_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[runtimeclasses-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one item, a miss returns [] (mirrors get_priority_class)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/runtimeclasses?name=runc", headers=h)
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "runc"
    r = api_client.get("/api/v1/clusters/1/resources/runtimeclasses?name=ghost", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_runtimeclasses_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[runtimeclasses-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the node.k8s.io group and namespace None (the
    cluster-scoped SAR cache key) — a deny short-circuits to 403
    RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/runtimeclasses", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "runtimeclasses", None, None, "node.k8s.io") in asked


def test_runtimeclasses_binding_404(api_client, auth_client) -> None:
    """[runtimeclasses-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/runtimeclasses", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_runtimeclass_kind_singular_rejected(api_client, auth_client) -> None:
    """[runtimeclass-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/runtimeclass", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_storageclasses_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[storageclasses-list-200] a bound user listing storageclasses gets
    the to_dict items back, spec fields (provisioner, reclaim_policy,
    volume_binding_mode, parameters) intact."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/storageclasses", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "storageclasses"
    [item] = body["items"]
    assert item["metadata"]["name"] == "csi-fast"
    assert item["provisioner"] == "csi.example.com"
    assert item["reclaim_policy"] == "Delete"
    assert item["volume_binding_mode"] == "WaitForFirstConsumer"
    assert item["parameters"] == {"type": "standard"}


def test_list_storageclasses_ignores_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[storageclasses-list-ignores-namespace] the kind is cluster-scoped:
    ?namespace=team-a is accepted and ignored — the same "csi-fast" item
    comes back. The route forwards the raw query value to the client; the
    cluster-scoped method ignores it (the list_nodes pattern) — the
    recorded call + the cluster-scoped fixture are the evidence the
    cluster-scoped list call was used."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/storageclasses?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    [item] = body["items"]
    assert item["metadata"]["name"] == "csi-fast"
    assert "namespace" not in item["metadata"]
    assert fake_k8s.storageclass_ns_calls == ["team-a"]  # query value forwarded, client ignores


def test_list_storageclasses_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[storageclasses-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one item, a miss returns [] (mirrors get_priority_class)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/storageclasses?name=csi-fast", headers=h)
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "csi-fast"
    r = api_client.get("/api/v1/clusters/1/resources/storageclasses?name=ghost", headers=h)
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_storageclasses_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[storageclasses-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the core group (empty string) and namespace None (the
    cluster-scoped SAR cache key) — a deny short-circuits to 403
    RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/storageclasses", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "storageclasses", None, None, "") in asked


def test_storageclasses_binding_404(api_client, auth_client) -> None:
    """[storageclasses-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/storageclasses", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_storageclass_kind_singular_rejected(api_client, auth_client) -> None:
    """[storageclass-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/storageclass", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_resourcequotas_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[resourcequotas-list-200-in-namespace] a bound user listing
    resourcequotas?namespace=team-a gets the to_dict items back, and the
    namespace is forwarded to the client (namespaced core kind)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/resourcequotas?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "resourcequotas"
    assert body["cluster"] == "prod"
    [item] = body["items"]
    assert item["metadata"]["name"] == "compute"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["status"]["used"]["requests.cpu"] == "2"
    assert item["status"]["hard"]["limits.memory"] == "20Gi"


def test_list_resourcequotas_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[resourcequotas-list-all-namespaces-without-param] no namespace query
    hits the all-namespaces branch: the FakeK8s receives None and the
    distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/resourcequotas", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "resourcequotas"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]


def test_list_resourcequotas_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[resourcequotas-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one item in team-a, a miss returns [] (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/resourcequotas?name=compute&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "compute"
    assert item["metadata"]["namespace"] == "team-a"
    r = api_client.get(
        "/api/v1/clusters/1/resources/resourcequotas?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_resourcequotas_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[resourcequotas-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the core group (empty string) and the query namespace — a
    deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/resourcequotas?namespace=team-a", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "resourcequotas", "team-a", None, "") in asked


def test_resourcequotas_binding_404(api_client, auth_client) -> None:
    """[resourcequotas-binding-404] an unbound user: the binding gate fails
    before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/resourcequotas?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_resourcequota_kind_singular_rejected(api_client, auth_client) -> None:
    """[resourcequota-kind-singular-rejected] the 4.1 route name (singular)
    is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/resourcequota", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_poddisruptionbudgets_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[poddisruptionbudgets-list-200-in-namespace] a bound user listing
    poddisruptionbudgets?namespace=team-a gets the to_dict items back, and
    the namespace is forwarded to the client (namespaced policy kind)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "poddisruptionbudgets"
    assert body["cluster"] == "prod"
    [item] = body["items"]
    assert item["metadata"]["name"] == "web"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["min_available"] == 3
    assert item["status"]["disruptions_allowed"] == 1


def test_list_poddisruptionbudgets_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[poddisruptionbudgets-list-all-namespaces-without-param] no namespace
    query hits the all-namespaces branch: the FakeK8s receives None and the
    distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/poddisruptionbudgets", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "poddisruptionbudgets"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]


def test_list_poddisruptionbudgets_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[poddisruptionbudgets-get-by-name] ?name= returns a 0/1-item list: a
    hit returns the one item in team-a, a miss returns [] (mirrors
    get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/poddisruptionbudgets?name=web&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "web"
    assert item["metadata"]["namespace"] == "team-a"
    r = api_client.get(
        "/api/v1/clusters/1/resources/poddisruptionbudgets?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_poddisruptionbudgets_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[poddisruptionbudgets-sar-denied] ADR-0004: the SAR is asked BEFORE
    the read, with the policy group and the query namespace — a deny
    short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "poddisruptionbudgets", "team-a", None, "policy") in asked


def test_poddisruptionbudgets_binding_404(api_client, auth_client) -> None:
    """[poddisruptionbudgets-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/poddisruptionbudgets?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_poddisruptionbudget_kind_singular_rejected(api_client, auth_client) -> None:
    """[poddisruptionbudget-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/poddisruptionbudget", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_verticalpodautoscalers_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[verticalpodautoscalers-list-200-in-namespace] a bound user listing
    verticalpodautoscalers?namespace=team-a gets the FULL custom objects
    back (spec + status intact, camelCase), and the namespace is forwarded
    to the client (namespaced autoscaling.k8s.io CRD)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "verticalpodautoscalers"
    assert body["cluster"] == "prod"
    [item] = body["items"]
    assert item["metadata"]["name"] == "web-vpa"
    assert item["metadata"]["namespace"] == "team-a"
    # full object: spec + status intact (camelCase wire form).
    assert item["spec"]["targetRef"]["kind"] == "Deployment"
    assert item["spec"]["updatePolicy"]["updateMode"] == "Auto"
    assert item["status"]["conditions"][0]["type"] == "RecommendationProvided"
    # the namespace was forwarded to the client.
    assert fake_k8s.vpa_ns_calls == ["team-a"]


def test_list_verticalpodautoscalers_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[verticalpodautoscalers-list-all-namespaces-without-param] no
    namespace query hits the all-namespaces branch: the FakeK8s receives
    None and the distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/verticalpodautoscalers", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "verticalpodautoscalers"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.vpa_ns_calls == [None]


def test_list_verticalpodautoscalers_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[verticalpodautoscalers-get-by-name] ?name= returns a 0/1-item list:
    a hit returns the one full object in team-a, a miss returns [] (mirrors
    get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/verticalpodautoscalers?name=web-vpa&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "web-vpa"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["targetRef"]["name"] == "web"
    r = api_client.get(
        "/api/v1/clusters/1/resources/verticalpodautoscalers?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_verticalpodautoscalers_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[verticalpodautoscalers-sar-denied] ADR-0004: the SAR is asked BEFORE
    the read, with the autoscaling.k8s.io group and the query namespace — a
    deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "verticalpodautoscalers", "team-a", None, "autoscaling.k8s.io") in asked


def test_verticalpodautoscalers_binding_404(api_client, auth_client) -> None:
    """[verticalpodautoscalers-binding-404] an unbound user: the binding
    gate fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/verticalpodautoscalers?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_verticalpodautoscaler_kind_singular_rejected(api_client, auth_client) -> None:
    """[verticalpodautoscaler-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/verticalpodautoscaler", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_horizontalpodautoscalers_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[horizontalpodautoscalers-list-200-in-namespace] a bound user listing
    horizontalpodautoscalers in one namespace gets the to_dict items back,
    spec (scale_target_ref, min/max replicas) and status (conditions)
    intact; the namespace is forwarded to the client."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "horizontalpodautoscalers"
    [item] = body["items"]
    assert item["metadata"]["name"] == "web-hpa"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["scale_target_ref"]["name"] == "web"
    assert item["spec"]["min_replicas"] == 2
    assert item["spec"]["max_replicas"] == 10
    assert item["status"]["conditions"][0]["type"] == "AbleToScale"
    assert fake_k8s.hpa_ns_calls == ["team-a"]


def test_list_horizontalpodautoscalers_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[horizontalpodautoscalers-list-all-namespaces-without-param] no
    namespace query hits the all-namespaces branch: the FakeK8s receives
    None and the distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/horizontalpodautoscalers", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "horizontalpodautoscalers"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.hpa_ns_calls == [None]


def test_list_horizontalpodautoscalers_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[horizontalpodautoscalers-get-by-name] ?name= returns a 0/1-item
    list: a hit returns the one object in team-a, a miss returns []
    (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/horizontalpodautoscalers?name=web-hpa&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "web-hpa"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["target_cpu_utilization_percentage"] == 80
    r = api_client.get(
        "/api/v1/clusters/1/resources/horizontalpodautoscalers?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_horizontalpodautoscalers_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[horizontalpodautoscalers-sar-denied] ADR-0004: the SAR is asked
    BEFORE the read, on the CORE group ("") with the query namespace — a
    deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # the SAR was asked BEFORE the read, core group (a generated v1 kind):
    assert ("list", "horizontalpodautoscalers", "team-a", None, "") in asked


def test_horizontalpodautoscalers_binding_404(api_client, auth_client) -> None:
    """[horizontalpodautoscalers-binding-404] an unbound user: the binding
    gate fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/horizontalpodautoscalers?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_horizontalpodautoscaler_kind_singular_rejected(api_client, auth_client) -> None:
    """[horizontalpodautoscaler-kind-singular-rejected] the 4.1 route name
    (singular) is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/horizontalpodautoscaler", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_limitranges_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[limitranges-list-200] a bound user listing limitranges in one
    namespace gets the to_dict items back, spec.limits intact; the namespace
    is forwarded to the client."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/limitranges?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "limitranges"
    [item] = body["items"]
    assert item["metadata"]["name"] == "default"
    assert item["metadata"]["namespace"] == "team-a"
    [limit] = item["spec"]["limits"]
    assert limit["type"] == "Container"
    assert limit["max"] == {"cpu": "2", "memory": "4Gi"}
    assert limit["min"] == {"cpu": "500m", "memory": "1Gi"}
    assert limit["defaultRequest"] == {"cpu": "250m", "memory": "512Mi"}


def test_list_limitranges_respects_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[limitranges-list-respects-namespace] the kind is NAMESPACED: the
    query namespace reaches the client (the contrast to priorityclasses'
    ignores-namespace)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/limitranges?namespace=team-a", headers=h)
    assert r.status_code == 200
    assert fake_k8s.limitrange_ns_calls == ["team-a"]


def test_list_limitranges_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[limitranges-list-200] no namespace query hits the all-namespaces
    branch: the FakeK8s receives None and the distinctly-named team-b item
    is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/limitranges", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "limitranges"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.limitrange_ns_calls == [None]


def test_list_limitranges_get_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[limitranges-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one object in team-a, a miss returns [] (mirrors
    get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/limitranges?name=default&namespace=team-a", headers=h
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "default"
    assert item["metadata"]["namespace"] == "team-a"
    r = api_client.get(
        "/api/v1/clusters/1/resources/limitranges?name=ghost&namespace=team-a", headers=h
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_limitranges_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[limitranges-sar-denied] ADR-0004: the SAR is asked BEFORE the read,
    on the CORE group ("") with the query namespace (namespaced kind) — a
    deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/limitranges?namespace=team-a", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # core group + the namespace are the load-bearing assertions:
    assert ("list", "limitranges", "team-a", None, "") in asked


def test_limitranges_binding_404(api_client, auth_client) -> None:
    """[limitranges-binding-404] an unbound user: the binding gate fails
    before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/limitranges", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_limitrange_kind_singular_rejected(api_client, auth_client) -> None:
    """[limitrange-kind-singular-rejected] the 4.1 route name (singular) is
    not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/limitrange", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_configmaps_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[configmaps-list-200] a bound user listing configmaps?namespace=team-a
    gets the to_dict items back, the namespace is forwarded, and ``data`` is
    present (NOT stripped, unlike secrets — the list view's Data Keys
    column reads it)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/configmaps?namespace=team-a", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "configmaps"
    assert body["cluster"] == "prod"
    [item] = [i for i in body["items"] if i["metadata"]["name"] == "app-config"]
    assert item["metadata"]["namespace"] == "team-a"
    assert item["data"] == {"LOG_LEVEL": "info", "URL": "https://internal"}  # NOT stripped
    assert fake_k8s.configmap_ns_calls == ["team-a"]  # the namespace is forwarded


def test_list_configmaps_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[configmaps-list-all-namespaces] no namespace query hits the
    all-namespaces branch: the FakeK8s receives None and the
    distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/configmaps", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "configmaps"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.configmap_ns_calls == [None]


def test_list_configmaps_get_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[configmaps-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one object in team-a (with ``data``), a miss returns []
    (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/configmaps?name=app-config&namespace=team-a", headers=h
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "app-config"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["data"] == {"LOG_LEVEL": "info", "URL": "https://internal"}
    r = api_client.get(
        "/api/v1/clusters/1/resources/configmaps?name=ghost&namespace=team-a", headers=h
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_configmaps_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[configmaps-sar-denied] ADR-0004: the SAR is asked BEFORE the read,
    on the CORE group ("") with the query namespace (namespaced kind) — a
    deny short-circuits to 403 RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/configmaps?namespace=team-a", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    # core group + the namespace are the load-bearing assertions:
    assert ("list", "configmaps", "team-a", None, "") in asked


def test_configmaps_binding_404(api_client, auth_client) -> None:
    """[configmaps-binding-404] an unbound user: the binding gate fails
    before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/configmaps?namespace=team-a", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_configmap_kind_singular_rejected(api_client, auth_client) -> None:
    """[configmap-kind-singular-rejected] the 4.1 route name (singular) is
    not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/configmap", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_volumesnapshotclasses_200(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[volumesnapshotclasses-list-200] a bound user listing
    volumesnapshotclasses gets the FULL custom objects back (CRD, camelCase —
    driver / deletionPolicy / parameters intact, NOT the lossy CRD
    projection)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshotclasses", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "volumesnapshotclasses"
    [item] = body["items"]
    assert item["metadata"]["name"] == "csi-default"
    assert item["driver"] == "csi-driver.example.com"
    assert item["deletionPolicy"] == "Delete"
    assert item["parameters"] == {"blockVolume": "true", "fstype": "ext4"}


def test_list_volumesnapshotclasses_ignores_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshotclasses-list-ignores-namespace] the kind is
    cluster-scoped: ?namespace=team-a is accepted and ignored — the same
    "csi-default" item comes back. The route forwards the raw query value to
    the client; the cluster-scoped method ignores it (the list_crds pattern)
    — the recorded call + the cluster-scoped fixture are the evidence the
    cluster-scoped list call was used."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshotclasses?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    [item] = body["items"]
    assert item["metadata"]["name"] == "csi-default"
    assert "namespace" not in item["metadata"]
    assert fake_k8s.snapshotclass_ns_calls == ["team-a"]  # query value forwarded, client ignores


def test_list_volumesnapshotclasses_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshotclasses-get-by-name] ?name= returns a 0/1-item list: a
    hit returns the one FULL object, a miss returns [] (mirrors
    get_storage_class)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshotclasses?name=csi-default", headers=h
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "csi-default"
    assert item["driver"] == "csi-driver.example.com"  # full object
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshotclasses?name=ghost", headers=h
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_volumesnapshotclasses_sar_denied(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshotclasses-sar-denied] ADR-0004: the SAR is asked BEFORE
    the read, with the CRD group (snapshot.storage.k8s.io) and namespace None
    (the cluster-scoped SAR cache key) — a deny short-circuits to 403
    RBAC_DENIED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshotclasses", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "volumesnapshotclasses", None, None, "snapshot.storage.k8s.io") in asked


def test_volumesnapshotclasses_binding_404(api_client, auth_client) -> None:
    """[volumesnapshotclasses-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get("/api/v1/clusters/999/resources/volumesnapshotclasses", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_volumesnapshotclass_kind_singular_rejected(api_client, auth_client) -> None:
    """[volumesnapshotclass-kind-singular-rejected] the singular
    volumesnapshotclass is not a kind — RESOURCE_KIND_NOT_SUPPORTED."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshotclass", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_volumesnapshots_200_in_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshots-list-200-in-namespace] a bound user listing
    volumesnapshots?namespace=team-a gets the FULL custom objects back
    (spec + status intact, camelCase — the namespaced snapshot.storage.k8s.io
    CRD)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshots?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "volumesnapshots"
    assert body["cluster"] == "prod"
    [item] = body["items"]
    assert item["metadata"]["name"] == "snap-a"
    assert item["metadata"]["namespace"] == "team-a"
    # full object: spec + status intact (camelCase wire form).
    assert item["spec"]["source"]["persistentVolumeClaimName"] == "pvc-snap-a"
    assert item["spec"]["volumeSnapshotClassName"] == "csi-snap"
    assert item["status"]["readyToUse"] is True
    assert item["status"]["boundVolumeSnapshotContentName"] == "content-snap-a"


def test_list_volumesnapshots_honors_namespace(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshots-list-honors-namespace] the query namespace is
    forwarded to the client (the namespaced branch was taken — a fix for
    4.1's hardcoded all-namespaces read)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshots?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    assert fake_k8s.vs_ns_calls == ["team-a"]


def test_list_volumesnapshots_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshots-list-all-namespaces-without-param] no
    namespace query hits the all-namespaces branch: the FakeK8s receives
    None and the distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshots", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "volumesnapshots"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.vs_ns_calls == [None]


def test_list_volumesnapshots_get_by_name(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[volumesnapshots-get-by-name] ?name= returns a 0/1-item list: a hit
    returns the one FULL object in team-a, a miss returns [] (mirrors
    get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    # Record AND allow (a deny would 403 before the read).
    import app.services.rbac as rb

    asked: list[tuple] = []

    def record_and_allow(client, verb, resource, ns, name, group=""):
        asked.append((verb, resource, ns, name, group))
        return True

    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    monkeypatch.setattr(rb, "_sar_allowed", record_and_allow)
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshots?name=snap-a&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "snap-a"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["source"]["persistentVolumeClaimName"] == "pvc-snap-a"  # full object
    r = api_client.get(
        "/api/v1/clusters/1/resources/volumesnapshots?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []
    assert ("get", "volumesnapshots", "team-a", "snap-a", "snapshot.storage.k8s.io") in asked


def test_list_volumesnapshots_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[volumesnapshots-sar-denied] ADR-0004: the SAR is asked BEFORE the
    read, with the snapshot.storage.k8s.io group and namespace None (the
    all-namespaces SAR cache key) — a deny short-circuits to 403
    RBAC_DENIED and the client call is never made."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshots", headers=h)
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "volumesnapshots", None, None, "snapshot.storage.k8s.io") in asked
    assert fake_k8s.vs_ns_calls == []  # the client call was never made


def test_volumesnapshots_binding_404(api_client, auth_client) -> None:
    """[volumesnapshots-binding-404] an unbound user: the binding gate
    fails before the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/volumesnapshots?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_volumesnapshot_kind_singular_rejected(api_client, auth_client) -> None:
    """[volumesnapshot-kind-singular-rejected] the singular volumesnapshot is
    not a kind — RESOURCE_KIND_NOT_SUPPORTED (the API kind is the plural)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/volumesnapshot", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_list_pvcs_200_in_namespace(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvcs-list-200] a bound user listing
    persistentvolumeclaims?namespace=team-a gets the to_dict items back
    (spec/status intact), and the namespace is forwarded to the client
    (namespaced core kind)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a", headers=h
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "persistentvolumeclaims"
    assert body["cluster"] == "prod"
    [item] = body["items"]
    assert item["metadata"]["name"] == "data-pvc"
    assert item["metadata"]["namespace"] == "team-a"
    assert item["spec"]["storage_class_name"] == "csi-fast"
    assert item["spec"]["volume_name"] == "pv-1"
    assert item["status"]["phase"] == "Bound"
    assert item["status"]["capacity"]["storage"] == "10Gi"
    assert fake_k8s.pvc_ns_calls == ["team-a"]  # the namespace is forwarded


def test_list_pvcs_all_namespaces_without_param(
    api_client, auth_client, fake_k8s, monkeypatch
) -> None:
    """[pvcs-list-all-namespaces] no namespace query hits the
    all-namespaces branch: the FakeK8s receives None and the
    distinctly-named team-b item is present."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get("/api/v1/clusters/1/resources/persistentvolumeclaims", headers=h)
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "persistentvolumeclaims"
    assert [item["metadata"]["namespace"] for item in body["items"]] == ["team-b"]
    assert fake_k8s.pvc_ns_calls == [None]


def test_list_pvcs_get_by_name(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvcs-get-by-name] ?name= returns a 0/1-item list: a hit returns the
    one item in team-a, a miss returns [] (mirrors get_secret)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    _allow_sar(monkeypatch)
    r = api_client.get(
        "/api/v1/clusters/1/resources/persistentvolumeclaims?name=data-pvc&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    [item] = r.get_json()["items"]
    assert item["metadata"]["name"] == "data-pvc"
    assert item["metadata"]["namespace"] == "team-a"
    r = api_client.get(
        "/api/v1/clusters/1/resources/persistentvolumeclaims?name=ghost&namespace=team-a",
        headers=h,
    )
    assert r.status_code == 200
    assert r.get_json()["items"] == []


def test_list_pvcs_sar_denied(api_client, auth_client, fake_k8s, monkeypatch) -> None:
    """[pvcs-sar-denied] ADR-0004: the SAR is asked BEFORE the read, with
    the core group (empty string) and the query namespace — a deny
    short-circuits to 403 RBAC_DENIED and the client call is never made."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    asked = _record_sar(monkeypatch)  # denies every SAR and records calls
    r = api_client.get(
        "/api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a", headers=h
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
    assert ("list", "persistentvolumeclaims", "team-a", None, "") in asked
    assert fake_k8s.pvc_ns_calls == []  # the client call was never made


def test_pvcs_binding_404(api_client, auth_client) -> None:
    """[pvcs-binding-404] an unbound user: the binding gate fails before
    the SAR, CLUSTER_NOT_FOUND."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    r = api_client.get(
        "/api/v1/clusters/999/resources/persistentvolumeclaims?namespace=team-a", headers=h
    )
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "CLUSTER_NOT_FOUND"


def test_pvc_kind_singular_rejected(api_client, auth_client) -> None:
    """[pvc-kind-singular-rejected] the singular persistentvolumeclaim is
    not a kind — RESOURCE_KIND_NOT_SUPPORTED (the API kind is the plural)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/persistentvolumeclaim", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


def test_pvc_kind_41_name_rejected(api_client, auth_client) -> None:
    """[pvc-kind-singular-rejected] 4.1's route name (``pvc``) is NOT a kind
    identifier — RESOURCE_KIND_NOT_SUPPORTED (documents that the 4.1 name
    was never a valid kind; the API kind is the plural)."""
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    _register(api_client, h)
    r = api_client.get("/api/v1/clusters/1/resources/pvc", headers=h)
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "RESOURCE_KIND_NOT_SUPPORTED"


@pytest.mark.integration
def test_list_pods_on_kind(api_client, auth_client, kind_client) -> None:
    cid, kubeconfig = kind_client
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    api_client.post(
        "/api/v1/clusters",
        json={
            "name": "kind-test",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kubeconfig.decode(),
            "context": "kind-kind-test",
        },
        headers=h,
    )
    r = api_client.get(f"/api/v1/clusters/{cid}/resources/pods?namespace=default", headers=h)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert any(p["metadata"]["name"] == "kubedash-pod" for p in items)


@pytest.mark.integration
def test_demo_serviceaccount_with_secret_and_pullsecret(
    api_client, auth_client, kind_client
) -> None:
    """The kind fixture's demo account lists its token secret and pull secret,
    and the pull secret's value is only on the single-object read."""
    cid, kubeconfig = kind_client
    auth_client.login()
    h = {"Authorization": f"Bearer {auth_client.jwt}"}
    api_client.post(
        "/api/v1/clusters",
        json={
            "name": "kind-test",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kubeconfig.decode(),
            "context": "kind-kind-test",
        },
        headers=h,
    )
    accounts = api_client.get(
        f"/api/v1/clusters/{cid}/resources/serviceaccounts?namespace=default", headers=h
    )
    assert accounts.status_code == 200, accounts.get_json()
    account = next(
        item
        for item in accounts.get_json()["items"]
        if item["metadata"]["name"] == "kubedash-builder"
    )
    assert account["secrets"] == [{"name": "kubedash-builder-token"}]
    assert account["image_pull_secrets"] == [{"name": "kubedash-registry"}]

    listed = api_client.get(
        f"/api/v1/clusters/{cid}/resources/secrets?namespace=default", headers=h
    )
    assert listed.status_code == 200, listed.get_json()
    by_name = {item["metadata"]["name"]: item for item in listed.get_json()["items"]}
    assert by_name["kubedash-builder-token"]["type"] == "kubernetes.io/service-account-token"
    assert by_name["kubedash-registry"]["type"] == "kubernetes.io/dockerconfigjson"
    assert "data" not in by_name["kubedash-registry"]

    one = api_client.get(
        f"/api/v1/clusters/{cid}/resources/secrets?namespace=default&name=kubedash-registry",
        headers=h,
    )
    assert one.status_code == 200, one.get_json()
    [secret] = one.get_json()["items"]
    assert ".dockerconfigjson" in secret["data"]


@pytest.mark.integration
def test_rbac_denied_403_on_kind(api_client, kind_client, api_app) -> None:
    """Denial path without kind RBAC gymnastics: a KubeDash user whose K8s
    identity has no grants. The kind kubeconfig's user is 'kind' (admin) —
    create a second binding for a KubeDash user and patch the SAR for that
    (cluster, user) pair to deny (the service seam), then expect 403."""
    cid, kubeconfig = kind_client
    import app.services.rbac as rb
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User
    from app.services.k8s_client import encrypt_kubeconfig

    with api_app.app_context():
        c = Cluster.query.filter_by(name="kind-test").first()
        if c is None:  # test ordering: the register happens in the pod test
            enc = encrypt_kubeconfig(kubeconfig)
            u0 = db.session.execute(
                db.select(User).filter_by(sub="sub-oidc-1")
            ).scalar_one()
            c = Cluster(
                name="kind-test",
                api_server="https://127.0.0.1:6443",
                kubeconfig_enc=enc,
                context="kind-kind-test",
            )
            db.session.add(c)
            db.session.flush()
            db.session.add(ClusterBinding(user_id=u0.id, cluster_id=c.id, role="admin"))
        u = User(sub="denied-sa", email="d@example.com")
        db.session.add_all([u, ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")])
        db.session.commit()
        access, _ = issue_token_pair(u)
    orig = rb._sar_allowed
    rb._sar_allowed = lambda *a, **k: False
    try:
        r = api_client.get(
            f"/api/v1/clusters/{c.id}/resources/pods",
            headers={"Authorization": f"Bearer {access}"},
        )
    finally:
        rb._sar_allowed = orig
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"


# A minimal deny-all NetworkPolicy: no ingress rule + an empty egress rule
# deny every flow, so spec.policy_types is exactly ["Ingress", "Egress"] —
# the assertion below matches this fixture (not vice versa).
_DENY_ALL_NP = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubedash-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
"""


# --- kind-tier login + cluster registration ---------------------------------
#
# The kind tier CANNOT use ``kind_client`` as-is: it is session-scoped
# against the function-scoped PG ``app`` fixture, which pytest 9 rejects at
# setup with ScopeMismatch (known debt — all three pre-existing kind tests
# fail identically, so they are not green evidence either). These two tests
# sidestep it by depending on the session-scoped ``kind_cluster`` fixture
# DIRECTLY (kubeconfig bytes + demo seed only — no PG ``app``), and register
# the cluster on the sqlite ``api_app`` the api-tier tests run against
# (uncommitted; rolled back by ``api_app`` teardown, so no DB pollution).
#
# Local admin login (ADR-0021) is the docker-free auth path: no OIDC mock
# (the ``mock_oidc`` monkeypatch is function-scoped and cannot reach the
# session-scoped PG app context the fixture row would need). The admin has
# K8s role ``admin`` via the cluster binding, so SAR and namespace
# mutations pass.


@pytest.fixture()
def kind_kubeconfig(kind_cluster) -> bytes:
    """The session-scoped kind cluster's kubeconfig (no PG ``app`` involved),
    so these tests avoid the ``kind_client`` ScopeMismatch debt."""
    return kind_cluster


@pytest.fixture()
def kind_admin_api_client(api_app, monkeypatch) -> object:
    """A sqlite api-tier client whose app has the bootstrap admin row
    (``_bootstrap_local_admin`` — wsgi runs it at boot; the test fixture must
    mirror it because the api_app fixture's sqlite tier has no boot hook).

    The SAR cache is BYPASSED (``_cache_get``/``_cache_set`` stubbed): the
    sqlite ``api_app``'s fake-redis swap does not cover the rbac module's
    own ``redis_client`` import (a different binding), so a real cache read
    would dial redis://localhost:6390 and 500. The decision itself is the
    REAL SAR against the kind apiserver (``_sar_allowed`` unpatched) — the
    kind kubeconfig's user is the cluster admin, so the verdict is true,
    exactly like production."""
    import app.services.rbac as rb
    from app import _bootstrap_local_admin

    _bootstrap_local_admin(api_app)
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    return api_app.test_client()


def _kind_admin_jwt(api_client) -> str:
    """Login as the bootstrapped local admin (ADR-0021); return the access
    JWT from the response's Set-Cookie (ADR-0025 delivery contract). The
    302's ``Location`` (``/``) is NOT followed — under ``TESTING`` the SPA
    catch-all is not registered, so it would 404; the cookies are set on the
    login response itself, which is all the JWT read needs."""
    r1 = api_client.post(
        "/api/v1/auth/local", json={"email": "admin@local", "password": "correct-horse"}
    )
    assert r1.status_code == 302, r1.get_json()
    cookie = api_client.get_cookie("kd_access")
    assert cookie is not None, "no kd_access cookie after local login"
    return str(cookie.value)


def _register_kind_cluster(api_client, h: dict, kubeconfig: bytes) -> int:
    """Register the kind cluster on the sqlite app (uncommitted); return the
    new cluster id. Idempotent per test: each test registers its own row
    (no cross-test DB assumptions, mirroring test_rbac_denied_403_on_kind's
    self-sufficient setup)."""
    r = api_client.post(
        "/api/v1/clusters",
        json={
            "name": "kind-test",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig": kubeconfig.decode(),
            "context": "kind-kind-test",
        },
        headers=h,
    )
    assert r.status_code == 201, r.get_json()
    return r.get_json()["id"]


@pytest.mark.integration
def test_list_networkpolicies_on_kind(kind_admin_api_client, kind_kubeconfig) -> None:
    """[networkpolicies-list-on-kind] a real NetworkPolicy round-trips through
    the R4 route on a live kind cluster: apply a deny-all policy into
    ``default``, GET the list, assert the item's spec is intact, then clean
    up (the dev cluster is reused — a leaked policy would pollute later runs)."""
    import subprocess

    api_client = kind_admin_api_client
    h = {"Authorization": f"Bearer {_kind_admin_jwt(api_client)}"}
    cid = _register_kind_cluster(api_client, h, kind_kubeconfig)
    applied = subprocess.run(
        ["kubectl", "--context=kind-kubedash-test", "apply", "-f", "-"],
        input=_DENY_ALL_NP,
        capture_output=True,
        text=True,
    )
    assert applied.returncode == 0, applied.stderr
    try:
        r = api_client.get(
            f"/api/v1/clusters/{cid}/resources/networkpolicies?namespace=default",
            headers=h,
        )
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["kind"] == "networkpolicies"
        [policy] = [
            item for item in body["items"] if item["metadata"]["name"] == "kubedash-deny-all"
        ]
        assert policy["metadata"]["namespace"] == "default"
        assert policy["spec"]["policy_types"] == ["Ingress", "Egress"]
        # The real API server returns null for the empty ingress/egress
        # lists; to_dict() maps JSON null -> None. The unit fake returns []
        # (its own dict literal). Assert the deny-all shape (both types
        # declared, no rules) without pinning empty-list vs null.
        assert not policy["spec"].get("ingress")
        assert not policy["spec"].get("egress")
    finally:
        deleted = subprocess.run(
            [
                "kubectl",
                "--context=kind-kubedash-test",
                "delete",
                "networkpolicy",
                "kubedash-deny-all",
                "-n",
                "default",
            ],
            capture_output=True,
            text=True,
        )
        assert deleted.returncode == 0, deleted.stderr


@pytest.mark.integration
def test_cilium_absent_degrades_to_empty_on_kind(kind_admin_api_client, kind_kubeconfig) -> None:
    """[cilium-absent-on-live-cluster-empty] the backstop the unit fakes
    cannot cover: on a REAL apiserver, a bare cluster (no cilium.io CRDs)
    degrades to 200 with ``items == []`` for both Cilium kinds — never a 502.
    A Cilium-installed cluster (e.g. the dev cluster) takes the other path —
    group registered, list empty — and degrades to the SAME 200 + []. If
    either ever 502s, the CRD-absent/_crd_body contract is wrong in
    production."""
    api_client = kind_admin_api_client
    h = {"Authorization": f"Bearer {_kind_admin_jwt(api_client)}"}
    cid = _register_kind_cluster(api_client, h, kind_kubeconfig)
    r = api_client.get(
        f"/api/v1/clusters/{cid}/resources/ciliumnetworkpolicies?namespace=default",
        headers=h,
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["kind"] == "ciliumnetworkpolicies"
    assert r.get_json()["items"] == []

    r = api_client.get(
        f"/api/v1/clusters/{cid}/resources/ciliumclusterwidenetworkpolicies",
        headers=h,
    )
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["kind"] == "ciliumclusterwidenetworkpolicies"
    assert r.get_json()["items"] == []


@pytest.mark.integration
def test_list_priorityclasses_on_kind(kind_admin_api_client, kind_kubeconfig) -> None:
    """[priorityclasses-list-on-kind] the held-out backstop: the REAL
    K8sClient (not the FakeK8s double) lists cluster-scoped PriorityClasses
    through the R4 route. A bare kind cluster ships the built-in
    system-cluster-critical PriorityClass — assert it comes back.
    ponytail: the built-in is asserted as-is; no kubectl fallback, no
    kubectl-created object (upgrade path: kubectl apply an inline
    PriorityClass if a future kind base image ever drops the built-in)."""
    api_client = kind_admin_api_client
    h = {"Authorization": f"Bearer {_kind_admin_jwt(api_client)}"}
    cid = _register_kind_cluster(api_client, h, kind_kubeconfig)
    r = api_client.get(f"/api/v1/clusters/{cid}/resources/priorityclasses", headers=h)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["kind"] == "priorityclasses"
    [critical] = [
        item
        for item in body["items"]
        if item["metadata"]["name"] == "system-cluster-critical"
    ]
    assert critical["value"] == 2000000000
    assert critical["preemption_policy"] == "PreemptLowerPriority"
    # Cluster-scoped: the real apiserver serializes namespace as null
    # (to_dict maps it to None) — unlike namespace-scoped kinds.
    assert critical["metadata"].get("namespace") is None
