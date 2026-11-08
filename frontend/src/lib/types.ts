/**
 * Frontend API types — derived from the backend OpenAPI contract
 * (openapi.json, dumped from Flask-Smorest via the backend test client;
 * `pnpm exec openapi-typescript openapi.json` generated the raw schema,
 * these are the view-facing extracts of its components).
 */

export interface Me {
  sub: string
  email: string | null
  display_name: string | null
  groups: string[]
  role: string
  // MeOut growth (TICKET-16, re-dumped openapi.json): the Profile page's
  // identity fields. auth_source is a plain string in the schema (no
  // enum), so it stays un-unioned; kubeconfig_source/last_login_at are
  // nullable.
  auth_source: string
  kubeconfig_source: string | null
  last_login_at: string | null
}

export interface Cluster {
  id: number
  name: string
  api_server?: string
  context?: string | null
  status?: string
  last_probe_at?: string | null
  // ClusterOut growth (TICKET-16): 'registry' on every real row, 'admin' on
  // the synthetic id-0 row the list prepends for admins. Plain string in the
  // schema (no enum) — added for contract completeness; no view reads it yet.
  source?: string
}

export interface ClusterIn {
  name: string
  api_server: string
  kubeconfig: string
  context: string
}

export interface Health {
  status: string
}

/** A Pod item as returned by /api/v1/clusters/<id>/resources/pods. */
export interface Pod {
  metadata?: {
    name?: string
    namespace?: string
    /** kubernetes to_dict, snake_case — the Service data page's Pods tab
     *  renders the first entry as `kind.lower() + "/" + name`. */
    owner_references?: { kind?: string; name?: string }[]
    [key: string]: unknown
  }
  spec?: {
    /** kubernetes to_dict, snake_case — the pod's assigned node (absent
     *  when unscheduled). */
    node_name?: string
    [key: string]: unknown
  }
  status?: {
    phase?: string
    /** kubernetes to_dict, snake_case — the pod IP (absent when not yet
     *  assigned). */
    pod_ip?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

export interface ResourceList<T = Pod> {
  kind?: string
  cluster?: string
  items: T[]
}

export interface K8sNamespace {
  metadata?: {
    name?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  status?: {
    phase?: string | null
  }
  [key: string]: unknown
}

/** A Node item as returned by /api/v1/clusters/<id>/resources/nodes. */
export interface K8sNode {
  metadata?: {
    name?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  spec?: {
    unschedulable?: boolean | null
    taints?: Array<{ key?: string | null; value?: string | null; effect?: string | null }> | null
    [key: string]: unknown
  }
  status?: {
    conditions?: Array<{ type?: string | null; status?: string | null }> | null
    node_info?: {
      kubelet_version?: string | null
      kube_proxy_version?: string | null
      container_runtime_version?: string | null
      os_image?: string | null
      kernel_version?: string | null
    } | null
    addresses?: Array<{ type?: string | null; address?: string | null }> | null
    allocatable?: Record<string, string> | null
    capacity?: Record<string, string> | null
  }
  [key: string]: unknown
}

/** A Role item as returned by /api/v1/clusters/<id>/resources/roles. */
export interface K8sRole {
  metadata?: {
    name?: string
    namespace?: string
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  rules?: PolicyRule[] | null
  [key: string]: unknown
}

/** A RoleBinding item as returned by /api/v1/clusters/<id>/resources/rolebindings. */
export interface K8sRoleBinding {
  metadata?: {
    name?: string
    namespace?: string
  }
  role_ref?: {
    kind?: string
    name?: string
    api_group?: string
  } | null
  subjects?:
    | {
        kind?: string
        name?: string
        namespace?: string
      }[]
    | null
}

/** A ClusterRole item from /resources/clusterroles. Same rule shape as a Role. */
export type K8sClusterRole = K8sRole

/** A ClusterRoleBinding item from /resources/clusterrolebindings. */
export type K8sClusterRoleBinding = K8sRoleBinding

/** One rule on a Role. Kubernetes ``to_dict`` uses snake_case. */
export interface PolicyRule {
  api_groups?: string[] | null
  resource_names?: string[] | null
  resources?: string[] | null
  verbs?: string[] | null
}

/** A ServiceAccount item as returned by /api/v1/clusters/<id>/resources/serviceaccounts. */
export interface ServiceAccount {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
    [key: string]: unknown
  }
  secrets?: { name?: string }[] | null
  image_pull_secrets?: { name?: string }[] | null
  [key: string]: unknown
}

/**
 * A Secret item as returned by /api/v1/clusters/<id>/resources/secrets.
 * ``data`` (base64 values) is only present on a ``?name=`` lookup.
 */
export interface K8sSecret {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    resource_version?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  type?: string | null
  data?: Record<string, string> | null
  [key: string]: unknown
}

/** A Service port entry (kubernetes to_dict, snake_case). */
export interface ServicePort {
  name?: string
  port?: number
  protocol?: string
  target_port?: number | string
  node_port?: number
}

/** A Service item as returned by /api/v1/clusters/<id>/resources/services (kubernetes to_dict, snake_case; namespaced, core v1). ``spec``/``status`` are present (NOT stripped, unlike secrets — the data page's Ports/Pods tabs and the list's External IP cell read them). */
export interface ServiceItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    resource_version?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  spec?: {
    type?: string
    cluster_ip?: string
    selector?: Record<string, string>
    ports?: ServicePort[]
  }
  status?: {
    load_balancer?: { ingress?: { ip?: string; hostname?: string }[] }
  }
  [key: string]: unknown
}

/** A ConfigMap item as returned by /api/v1/clusters/<id>/resources/configmaps (kubernetes to_dict, snake_case; namespaced, core v1). ``data`` is present (NOT stripped, unlike secrets — it is public config, and the list view's Data Keys column counts its keys). */
export interface ConfigMapItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    resource_version?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  /** Plain-string config values (public, NOT base64). */
  data?: Record<string, string> | null
  /** Base64-encoded binary values (camelCase — the kubernetes client preserves the API casing for non-metadata fields). */
  binaryData?: Record<string, string> | null
  [key: string]: unknown
}

/** A NetworkPolicy item as returned by /api/v1/clusters/<id>/resources/networkpolicies (kubernetes to_dict, snake_case). */
export interface NetworkPolicyItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  spec?: {
    pod_selector?: { match_labels?: Record<string, string> | null } | null
    policy_types?: string[] | null
    ingress?: unknown[] | null
    egress?: unknown[] | null
  }
  [key: string]: unknown
}

/** A HorizontalPodAutoscaler item as returned by /api/v1/clusters/<id>/resources/horizontalpodautoscalers (kubernetes to_dict, snake_case; namespaced, autoscaling/v1). */
export interface HorizontalPodAutoscalerItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    scale_target_ref?: { kind?: string; name?: string; api_version?: string }
    min_replicas?: number
    max_replicas?: number
    target_cpu_utilization_percentage?: number
    metrics?: unknown[]
  }
  status?: {
    current_replicas?: number
    desired_replicas?: number
    current_cpu_utilization_percentage?: number
    conditions?: Array<{
      type?: string
      status?: string
      last_transition_time?: string
      reason?: string
      message?: string
    }>
  }
  [key: string]: unknown
}

/** One spec.limits[] entry of a LimitRange (kubernetes to_dict). */
export interface LimitRangeLimitItem {
  type?: string
  min?: { cpu?: string; memory?: string }
  max?: { cpu?: string; memory?: string }
  default?: { cpu?: string; memory?: string }
  default_request?: { cpu?: string; memory?: string }
  max_limit_request_ratio?: { cpu?: string; memory?: string }
  [key: string]: unknown
}

/** A LimitRange item as returned by /api/v1/clusters/<id>/resources/limitranges (kubernetes to_dict, snake_case; namespaced, core group). */
export interface LimitRangeItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: { limits?: LimitRangeLimitItem[] }
  [key: string]: unknown
}

/** A CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy item (full CRD to_dict). */
export interface CiliumPolicyItem {
  metadata?: {
    name?: string
    namespace?: string | null
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
  }
  spec?: {
    endpointSelector?: { matchLabels?: Record<string, string> | null } | null
    ingress?: unknown[] | null
    egress?: unknown[] | null
  }
  [key: string]: unknown
}

/** A VolumeSnapshotClass custom object as returned by /api/v1/clusters/<id>/resources/volumesnapshotclasses (snapshot.storage.k8s.io CRD, camelCase wire form; cluster-scoped). */
export interface VolumeSnapshotClassItem {
  metadata?: {
    name?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  driver?: string
  deletionPolicy?: string
  parameters?: Record<string, string>
  [key: string]: unknown
}

/** A PriorityClass item as returned by /api/v1/clusters/<id>/resources/priorityclasses (kubernetes to_dict, snake_case; cluster-scoped). */
export interface PriorityClassItem {
  metadata?: {
    name?: string
    creation_timestamp?: string | null
    labels?: Record<string, string> | null
    annotations?: Record<string, string> | null
  }
  value?: number
  global_default?: boolean
  preemption_policy?: string
  description?: string
  [key: string]: unknown
}

/** A RuntimeClass item as returned by /api/v1/clusters/<id>/resources/runtimeclasses (kubernetes to_dict, snake_case; cluster-scoped). */
export interface RuntimeClassItem {
  metadata?: {
    name?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  handler?: string
  overwrite_node_sel_no_toleration?: boolean
  scheduling?: {
    node_selector?: Record<string, string>
    tolerations?: unknown[]
  }
  pod_level_overhead?: { memory?: string; cpu?: string }
  [key: string]: unknown
}

/** A StorageClass item as returned by /api/v1/clusters/<id>/resources/storageclasses (kubernetes to_dict, snake_case; cluster-scoped, storage/v1). */
export interface StorageClassItem {
  metadata?: {
    name?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  provisioner?: string
  reclaim_policy?: string
  volume_binding_mode?: string
  allow_volume_expansion?: boolean
  parameters?: Record<string, string>
  [key: string]: unknown
}

/** A ResourceQuota item as returned by /api/v1/clusters/<id>/resources/resourcequotas (kubernetes to_dict, snake_case; namespaced, core group). */
export interface ResourceQuotaItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    hard?: Record<string, string>
    scopes?: string[]
    scope_selector?: unknown
  }
  status?: {
    hard?: Record<string, string>
    used?: Record<string, string>
  }
  [key: string]: unknown
}

/** A PodDisruptionBudget item as returned by /api/v1/clusters/<id>/resources/poddisruptionbudgets (kubernetes to_dict, snake_case; namespaced, policy/v1). */
export interface PodDisruptionBudgetItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    min_available?: number
    max_unavailable?: number
    selector?: {
      match_labels?: Record<string, string>
      match_expressions?: unknown[]
    }
    unhealthy_pod_eviction_policy?: string
  }
  status?: {
    observed_generation?: number
    current_healthy?: number
    desired?: number
    total_pods?: number
    expected_pods?: number
    disruptions_allowed?: number
    conditions?: Array<{
      type?: string
      status?: string
      reason?: string
      message?: string
      last_transition_time?: string
    }>
  }
  [key: string]: unknown
}

/** A VerticalPodAutoscaler custom object as returned by /api/v1/clusters/<id>/resources/verticalpodautoscalers (autoscaling.k8s.io CRD, camelCase wire form; namespaced). */
export interface VerticalPodAutoscalerItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    targetRef?: { kind?: string; name?: string; apiVersion?: string }
    updatePolicy?: { updateMode?: string }
    resourcePolicy?: {
      containerPolicies?: Array<{
        containerName?: string
        controlledValues?: string
        mode?: string
        minAllowed?: Record<string, string>
        maxAllowed?: Record<string, string>
        controlledResources?: string[]
      }>
    }
  }
  status?: {
    conditions?: Array<{
      type?: string
      status?: string
      lastTransitionTime?: string
      reason?: string
      message?: string
    }>
  }
  [key: string]: unknown
}

/** A VolumeSnapshot custom object as returned by /api/v1/clusters/<id>/resources/volumesnapshots (snapshot.storage.k8s.io CRD, namespaced, camelCase wire form — the raw custom object, NOT the generated-model snake_case). */
export interface VolumeSnapshotItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    source?: {
      persistentVolumeClaimName?: string
      volume?: string
    }
    volumeSnapshotClassName?: string
  }
  status?: {
    readyToUse?: boolean
    restoreSize?: string
    boundVolumeSnapshotContentName?: string
    creationTime?: string
  }
  [key: string]: unknown
}

/** A PVC item as returned by /api/v1/clusters/<id>/resources/persistentvolumeclaims (kubernetes to_dict, snake_case; namespaced, core v1). */
export interface PvcItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    access_modes?: string[]
    volume_mode?: string
    storage_class_name?: string
    volume_name?: string
  }
  status?: {
    phase?: string
    capacity?: { storage?: string }
  }
  [key: string]: unknown
}

/** One PersistentVolume (cluster-scoped core v1) from the generic resources route. */
export interface PersistentVolumeItem {
  metadata?: {
    name?: string
    creation_timestamp?: string
    deletion_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    capacity?: { storage?: string }
    access_modes?: string[]
    persistent_volume_reclaim_policy?: string
    volume_mode?: string
    storage_class_name?: string
    claim_ref?: { name?: string; namespace?: string }
    csi?: { driver?: string; fs_type?: string; volume_attributes?: Record<string, string> }
    host_path?: { path?: string }
  }
  status?: { phase?: string; message?: string }
  [key: string]: unknown
}

/** One PVC-usage entry from /api/v1/clusters/<id>/metrics/pvcs (kubelet stats/summary). */
export interface PvcUsage {
  name: string
  capacity_bytes: number
  used_bytes: number
  available_bytes: number
  percentage_used: number
}

/** The metrics/pvcs response (ADR-0003 two-tier: unavailable/denied are 200 flags, not errors). */
export interface PvcUsageResponse {
  cluster: string
  namespace: string
  source: string
  metrics_available: boolean
  metrics_denied: boolean
  items: PvcUsage[]
}

// --- Network (2026-10-28-ingressclass-gatewayclass-views) — shapes mirror the wire contract ---

/** An IngressClass item (kubernetes to_dict, snake_case; cluster-scoped, networking.k8s.io/v1). */
export interface IngressClassItem {
  metadata?: {
    name?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    controller?: string
    /** LocalObjectReference — the 4.1 data page's Parameters table. */
    parameters?: { api_version?: string; kind?: string; name?: string }
  }
  [key: string]: unknown
}

/** A GatewayClass item (FULL custom object, camelCase; cluster-scoped CRD, gateway.networking.k8s.io/v1). */
export interface GatewayClassItem {
  metadata?: {
    name?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: { controllerName?: string }
  status?: {
    conditions?: { type?: string; status?: string; reason?: string; message?: string }[]
  }
  [key: string]: unknown
}

/** An Ingress item (kubernetes to_dict, snake_case; namespaced, networking.k8s.io/v1). */
export interface IngressItem {
  metadata?: {
    name?: string
    namespace?: string
    creation_timestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    ingress_class_name?: string
    tls?: { secret_name?: string; hosts?: string[] }[]
    rules?: {
      host?: string
      http?: {
        paths?: {
          path?: string
          path_type?: string
          backend?: {
            service?: {
              name?: string
              port?: { number?: number; name?: string }
            }
          }
        }[]
      }
    }[]
  }
  [key: string]: unknown
}

/** A Gateway item (FULL custom object, camelCase; namespaced CRD, gateway.networking.k8s.io/v1). */
export interface GatewayItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    gatewayClassName?: string
    listeners?: { name?: string; protocol?: string; port?: number; hostname?: string }[]
    addresses?: { type?: string; value?: string }[]
  }
  status?: {
    conditions?: { type?: string; status?: string; reason?: string; message?: string }[]
  }
  [key: string]: unknown
}

/** An HTTPRoute item (FULL custom object, camelCase; namespaced CRD, gateway.networking.k8s.io/v1). */
export interface HTTPRouteItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    hostnames?: string[]
    parentRefs?: { name?: string; namespace?: string; kind?: string; group?: string }[]
    rules?: unknown[]
  }
  [key: string]: unknown
}

/** A ReferenceGrant item (FULL custom object, camelCase; CLUSTER-scoped CRD, gateway.networking.k8s.io/v1). */
export interface ReferenceGrantItem {
  metadata?: {
    name?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    from?: { group?: string; kind?: string; namespace?: string }[]
    to?: { group?: string; kind?: string }[]
  }
  [key: string]: unknown
}

// ---- cert-manager.io/v1 CRDs (full custom objects, camelCase wire form) ----

/** A cert-manager status condition (full custom object, camelCase). The list
 *  views' Status badge renders the LAST condition's `reason` (green when its
 *  `status === "True"`, red otherwise — the 4.1 mapping). */
export interface CertManagerCondition {
  type?: string
  status?: string
  reason?: string
  message?: string
}

/** An ownerReference on a custom object's metadata (camelCase wire form). */
export interface OwnerReference {
  apiVersion?: string
  kind?: string
  name?: string
  uid?: string
  controller?: boolean
  blockOwnerDeletion?: boolean
}

/** A cert-manager ACME solver (full custom object, camelCase). */
export interface AcmeSolver {
  http01?: Record<string, unknown>
  dns01?: Record<string, unknown>
  [key: string]: unknown
}

/** A cert-manager issuer ACME spec (full custom object, camelCase). */
export interface AcmeSpec {
  email?: string
  server?: string
  solvers?: AcmeSolver[]
  privateKeySecretRef?: { name?: string }
  [key: string]: unknown
}

/** A cert-manager issuer Vault spec (full custom object, camelCase). */
export interface VaultSpec {
  path?: string
  server?: string
  authMethod?: string
  secretName?: string
  auth?: {
    appRole?: { roleId?: string; secretRef?: { name?: string } }
    tokenSecretRef?: { name?: string }
    kubernetes?: { role?: string; serviceAccountRef?: { name?: string } }
  }
  [key: string]: unknown
}

/** The spec shared by ClusterIssuer and Issuer (full custom object, camelCase). The 4.1 type classification reads spec.selfSigned / spec.ca / spec.acme / spec.vault (a later-present key wins; 5.0 renders `Self Signed` — 4.1's "Sel Signed" typo fixed). */
export interface IssuerSpec {
  selfSigned?: Record<string, unknown>
  ca?: { secretName?: string; [key: string]: unknown }
  acme?: AcmeSpec
  vault?: VaultSpec
  [key: string]: unknown
}

/** A ClusterIssuer (cert-manager.io/v1 CRD, CLUSTER-scoped; full custom object, camelCase — the raw object, NOT a projection). */
export interface ClusterIssuerItem {
  metadata?: {
    name?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
    ownerReferences?: OwnerReference[]
  }
  spec?: IssuerSpec
  status?: {
    conditions?: CertManagerCondition[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/** An Issuer (cert-manager.io/v1 CRD, namespaced; full custom object, camelCase). */
export interface IssuerItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
    ownerReferences?: OwnerReference[]
  }
  spec?: IssuerSpec
  status?: {
    conditions?: CertManagerCondition[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/** A CertificateRequest (cert-manager.io/v1 CRD, namespaced; full custom object, camelCase). */
export interface CertificateRequestItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
    ownerReferences?: OwnerReference[]
  }
  spec?: {
    request?: string
    issuerRef?: { name?: string; kind?: string }
    [key: string]: unknown
  }
  status?: {
    conditions?: CertManagerCondition[]
    certificate?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

/** A Certificate (cert-manager.io/v1 CRD, namespaced; full custom object, camelCase). */
export interface CertificateItem {
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
    ownerReferences?: OwnerReference[]
  }
  spec?: {
    secretName?: string
    issuerRef?: { name?: string; kind?: string }
    dnsNames?: string[]
    [key: string]: unknown
  }
  status?: {
    conditions?: CertManagerCondition[]
    notAfter?: string
    renewalTime?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

// ---- MetalLB / Cilium external-LB CRDs (full custom objects, camelCase) ----

/** A k8s LabelSelector (camelCase wire form). */
export interface LabelSelector {
  matchLabels?: Record<string, string>
  matchExpressions?: { key?: string; operator?: string; values?: string[] }[]
}

/**
 * An IP Address Pool — provider-detected (MetalLB `ipaddresspools`,
 * namespaced, primary; Cilium `ciliumloadbalancerippools`, cluster-scoped,
 * fallback). Full custom object (camelCase) tagged with a top-level
 * `provider` field (`"metallb"` / `"cilium"`) — the list view's Type column.
 */
export interface IpAddressPoolItem {
  provider?: string
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    // MetalLB
    addresses?: string[]
    autoAssign?: boolean
    avoidBuggyIPs?: boolean
    serviceAllocation?: {
      priority?: number
      namespaces?: string[]
      namespaceSelectors?: LabelSelector[]
      podSelector?: LabelSelector
      serviceSelectors?: LabelSelector[]
    }
    // Cilium
    cidrs?: string[]
    allowFirstLastIPs?: boolean
    disabled?: boolean
    ipFamilyPolicy?: string
    ipFamilies?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/**
 * An L2 Advertisement — provider-detected (MetalLB `l2advertisements`,
 * namespaced, primary; Cilium `ciliuml2announcementpolicies`, cluster-scoped,
 * fallback). Full custom object (camelCase) + the `provider` tag.
 */
export interface L2AdvertisementItem {
  provider?: string
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    // MetalLB
    ipAddressPools?: string[]
    interfaces?: string[]
    ipAddressPoolSelectors?: LabelSelector[]
    nodeSelectors?: LabelSelector[]
    // Cilium
    serviceSelector?: LabelSelector
    nodeSelector?: LabelSelector
    externalIPs?: string[]
    loadBalancerIPs?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/**
 * A BGP Peer — provider-detected (MetalLB `bgppeers`, namespaced, primary;
 * Cilium `ciliumbgppeeringpolicies`, cluster-scoped, fallback). Full custom
 * object (camelCase) + the `provider` tag.
 */
export interface BgpPeerItem {
  provider?: string
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    // MetalLB
    myASN?: number
    peerASN?: number
    peerAddress?: string
    sourceAddress?: string
    peerPort?: number
    holdTime?: number
    keepaliveTime?: number
    connectTime?: number
    routerID?: string
    nodeSelectors?: LabelSelector[]
    passwordSecret?: { name?: string }
    bfdProfile?: string
    ebgpMultiHop?: number
    vrf?: string
    disableMP?: boolean
    // Cilium
    nodeSelector?: LabelSelector
    virtualRouters?: {
      localASN?: number
      exportPodCIDR?: boolean
      neighbors?: { peerAddress?: string; peerASN?: number }[]
      [key: string]: unknown
    }[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/**
 * A BGP Advertisement — MetalLB `bgpadvertisements` ONLY (no Cilium
 * fallback — no Cilium equivalent). Full custom object (camelCase) + the
 * `provider` tag (always `"metallb"`).
 */
export interface BgpAdvertisementItem {
  provider?: string
  metadata?: {
    name?: string
    namespace?: string
    creationTimestamp?: string
    labels?: Record<string, string>
    annotations?: Record<string, string>
  }
  spec?: {
    aggregationLength?: number
    aggregationLengthV6?: number
    localPref?: number
    communities?: string[]
    ipAddressPools?: string[]
    ipAddressPoolSelectors?: LabelSelector[]
    nodeSelectors?: LabelSelector[]
    peers?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/** One generated resource from the Ingress -> Gateway API converter (the
 *  converter's dict output — the same shape the apply endpoint consumes). */
export interface ConvertedResource {
  kind: string
  apiVersion: string
  metadata: { name: string; namespace?: string }
  spec?: Record<string, unknown>
}

/** The POST /clusters/<id>/gateway-api/convert response (GatewayConvertOut). */
export interface GatewayConvertResult {
  cluster: string
  namespace: string
  source: string
  gatewayClassName: string
  resources: ConvertedResource[]
  warnings: string[]
}

/** One per-object apply result (AppliedOut / ApplyErrorOut). A partial
 *  failure is a 200 with `errors` populated, not an error envelope. */
export interface ApplyResult {
  applied: { kind: string; name: string; namespace: string | null; status: 'created' | 'unchanged' }[]
  errors: { kind: string; name: string; message: string }[]
}

/** Closed set for the detail page's ?kind= param (4.1 parity). */
export const POLICY_KINDS = ['NetworkPolicy', 'CiliumNetworkPolicy', 'CiliumClusterwideNetworkPolicy'] as const
export type PolicyKind = (typeof POLICY_KINDS)[number]

/**
 * A CustomResourceDefinition item as returned by
 * /api/v1/clusters/<id>/resources/crds. Kubernetes ``to_dict`` uses snake_case
 * on the metadata/spec nesting, but the CustomObjectsApi items keep the
 * camelCase ``creationTimestamp`` (the raw dict, not a generated model).
 */
export interface K8sCrd {
  metadata?: {
    name?: string
    creationTimestamp?: string | null
    [key: string]: unknown
  }
  spec?: {
    group?: string | null
    names?: {
      kind?: string | null
      plural?: string | null
    } | null
    scope?: string | null
    versions?:
      | {
          name?: string | null
          served?: boolean | null
          storage?: boolean | null
        }[]
      | null
  }
  [key: string]: unknown
}

/**
 * A projected row of GET /api/v1/clusters/<id>/resources/crds/instances —
 * the 4.1 condition projection ({name, namespace, status, type, reason,
 * message, created}), not a raw custom object (CRD schemas are arbitrary).
 */
export interface CrdInstance {
  name: string
  namespace: string | null
  status: string
  type: string
  reason: string
  message: string
  created: string | null
}

// --- Cluster dashboard (2026-10-21-cluster-dashboard) — shapes mirror the wire contract ---

/** A row of GET /api/v1/clusters/<id>/metrics/summary. `used_*` are null when the Metrics API is unreachable (certainty rule: unknown, never 0). */
export interface MetricsSummary {
  metrics_available: boolean
  /**
   * True when the caller lacks the metrics.k8s.io read grant (SAR denied).
   * Distinct from `metrics_available`: the UI must not tell a denied user
   * "install metrics-server".
   */
  metrics_denied: boolean
  cpu: {
    capacity_millicores: number
    used_millicores: number | null
    requests_millicores: number
    limits_millicores: number
  }
  memory: {
    capacity_bytes: number
    used_bytes: number | null
    requests_bytes: number
    limits_bytes: number
  }
  pods: {
    capacity: number
    running: number
    pending: number
    completed: number
  }
}

/** A row of GET /api/v1/clusters/<id>/events (bare list, newest-first). */
export interface ClusterEvent {
  type: string
  reason: string
  involved_object: {
    kind: string
    name: string
    namespace: string
  }
  message: string
  count: number | null
  last_timestamp: string | null
}


/** A row of GET /api/v1/permissions/my-access — the caller's own bindings. */
export interface MyAccessBinding {
  cluster: string
  namespace: string | null
  template: string | null
  created_at: string
}

// --- Admin (TICKET-07) — shapes mirror backend/app/schemas/permissions.py ---

/** A row of GET /api/v1/admin/users (UserOut). */
export interface AdminUser {
  id: number
  sub: string
  email: string | null
  display_name: string | null
  groups: string[]
  role: string
  status: string
  /** `oidc` renders as OpenID, `local` as Local (4.1 Type column). */
  auth_source?: string
  cluster_count: number
  last_login_at: string | null
  /** The main-branch "Type" column: "Local" (auth_source=local) or "OIDC". */
  user_type: string
}

/** A row of GET /api/v1/admin/groups (group → member_count). */
export interface GroupOut {
  group: string
  member_count: number
}

/** One {api_groups, resources, verbs} row of an RBAC template (R2). */
export interface RoleRule {
  api_groups: string[]
  resources: string[]
  verbs: string[]
}

/** A row of GET /api/v1/admin/permissions/templates (TemplateOut). */
export interface RBACTemplate {
  id: number
  name: string
  description: string
  scope: 'namespace' | 'cluster'
  rules: RoleRule[]
  builtin: boolean
  created_by: string | null
  created_at: string | null
}

/**
 * A permission audit row — the documented shape of `audit_log` (AuditOut /
 * app/models/audit.py). GET /api/v1/audit still 501s (base-structure stub);
 * the Audit tab renders an empty state until the read route lands.
 */
export interface AuditEntry {
  id: number
  action: string
  actor_sub: string
  target: string
  cluster: string | null
  namespace: string | null
  template: string | null
  at: string
}
