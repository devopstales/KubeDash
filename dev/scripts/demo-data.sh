#!/usr/bin/env bash
# KubeDash dev-stack demo data — gives the dashboard something to show.
#
# Idempotent: safe to re-run. Seeds the demo namespace (kubedash-demo) with:
#
#   - demo-app: one healthy busybox pod — the target for the HPA, VPA and
#     PDB below. Its resources mirror the LimitRange defaults (injection
#     only happens at pod creation, so the stanza is explicit) and it is a
#     stable, low-churn workload for the VPA recommender to size.
#   - demo-broken: one pod with a nonexistent image — CrashLoops, emitting
#     Warning events (BackOff / ImagePullBackOff) so the Events panel
#     always has recent entries (k8s events expire after ~1h, so a stale
#     cluster shows "No events found" without the churn).
#   - demo-secret / demo-config / demo-limitrange / demo-quota / demo-pdb /
#     demo-hpa / demo-vpa / demo-netpol: one instance of each kind so the
#     list + data views render real data.
#   - demo-pvc + demo-pvc-consumer: a 100Mi RWO claim on the csi-hostpath
#     StorageClass (dev/csi-hostpath.yaml — the kubernetes-csi csi-hostpath
#     test driver, installed by the Taskfile's _kind-apps) + a busybox pod
#     that mounts it. WHY a CSI driver and not kind's default "standard"
#     class (local-path provisioner): those PVs are hostPath, and the
#     kubelet's hostPath volume plugin has NO GetStats on the kind dev
#     cluster (K8s 1.35) — the mounted volume never reaches the node's
#     /stats/summary, so the pvcRef stats backing the PVC/PV lists' Usage
#     column (/metrics/pvcs) are empty and it renders the honest '—'. The
#     csi-hostpath driver implements NodeGetVolumeStats (statfs), so the
#     claim's mounted volume IS reported with its pvcRef and the Usage
#     column shows real data. csi-hostpath's statfs measures the BACKING
#     filesystem (the node's root disk), not the 100Mi claim, so the Usage
#     figure tracks the node's disk usage, not the 8Mi seed. It is also
#     the demo-snap VolumeSnapshot's source claim.
#   - demo-runc: cluster-scoped RuntimeClass (handler "runc" = kind's
#     containerd runtime).
#   - demo-gp2: cluster-scoped StorageClass (provisioner
#     "rancher.local-path" = kind's default provisioner).
#   - configmaps.example.com: CRD fixture for the e2e deep-link scenario
#     (ui-smoke.spec.ts); without it the scenario is red for setup
#     reasons, not behavior (QA W012).
#   - volumesnapshotclasses.snapshot.storage.k8s.io + csi-default: the
#     SnapshotClass CRD (cluster-scoped) + one fixture, so the SnapshotClass
#     list + data views render real data (the CRD's presence is what makes
#     the read non-empty — absent -> []).
#   - volumesnapshots.snapshot.storage.k8s.io + demo-snap: the
#     VolumeSnapshot CRD (namespaced) + one fixture, so the VolumeSnapshot
#     list + data views render real data (the CRD's presence is what makes
#     the read non-empty — absent -> []).
#   - cert-manager.io/v1 (clusterissuers Cluster-scoped + issuers /
#     certificaterequests / certificates Namespaced) + four fixtures
#     (demo-cluster-issuer ACME, demo-issuer selfSigned, demo-cert ->
#     demo-cert-tls secret, demo-cert-request): the Cert-Manager view's four
#     tabs render real data (CRDs only, NO operator — fixtures carry their
#     own Ready status, which is the view's green badge tier).
#   - metallb.io/v1beta2 (ipaddresspools / l2advertisements / bgppeers /
#     bgpadvertisements, ALL Namespaced to match the backend's namespaced
#     read — a deliberate deviation from upstream cluster-scoped MetalLB) +
#     four fixtures (demo-pool, demo-l2, demo-bgp-peer, demo-bgp-adv): the
#     LoadBalancer view's four tabs render real data, tagged provider=metallb
#     by the server-side provider detection (CRDs only, NO operator).
#   - cilium.io (CiliumLoadBalancerIPPool / CiliumL2AnnouncementPolicy /
#     CiliumBGPPeeringPolicy, all Cluster-scoped) + three fixtures
#     (demo-cilium-pool, demo-cilium-l2, demo-cilium-bgp): the LoadBalancer
#     view's FALLBACK provider — invisible while the metallb.io CRDs are
#     present (MetalLB is primary); delete the four metallb.io CRDs to see
#     the view flip to these, tagged provider=cilium (CRDs only, NO
#     operator; the pinned Cilium 1.19.10 ships ippools+l2 CRDs, the BGP
#     peering CRD is applied if absent).
#
# The VPA OPERATOR (recommender + updater + admission-controller, kube-
# system) is installed first — marker-checked on the VPA CRD so re-runs
# skip it. Manifests are vendored at dev/vpa-1.7.3/ (pinned: the 1.7 line
# is the K8s 1.35-1.37 compatible release for the kind dev cluster). The
# demo VPA uses updateMode: Off — recommendations only, no pod mutation,
# so it coexists with the LimitRange's admission injection.
#
# The old load-generation pods (demo-busy busy-loops) are retired: they
# existed to keep the metrics pages busy, but the demo-app workload +
# cluster overhead are enough for the metrics to render, and the busy
# loops are gone.
#
# The cluster is registered in the app's registry by the Taskfile
# (_dev-register-cluster) AFTER this script, so the dashboard's admin
# lens reaches it.
set -euo pipefail

CTX="kind-kubedash-test"
NS="kubedash-demo"
VPA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../vpa-1.7.3" && pwd)"

k() { kubectl --context "$CTX" "$@"; }

# 1. Namespace (no events).
k get namespace "$NS" >/dev/null 2>&1 || k create namespace "$NS"

# 2. Retire the pre-change load-generation pods (fresh clusters: no-op).
k -n "$NS" delete deployment demo-busy --ignore-not-found >/dev/null

# 3. VPA operator (kube-system) — marker-checked: the CRD is applied in
#    the same step as the rest, so its presence means the operator is up.
if k get crd verticalpodautoscalers.autoscaling.k8s.io >/dev/null 2>&1; then
  echo "VPA operator already installed (CRD present) — skipping."
else
  # Webhook TLS: self-signed CA + server cert (SAN = the vpa-webhook
  # service DNS) uploaded as kube-system/vpa-tls-certs — the same
  # procedure as upstream's hack/vpa-up.sh (gencerts.sh). The admission
  # controller registers its own MutatingWebhookConfiguration at startup.
  if ! k -n kube-system get secret vpa-tls-certs >/dev/null 2>&1; then
    CERTS="$(mktemp -d)"
    trap 'rm -rf "$CERTS"' EXIT
    cat > "$CERTS/server.conf" <<'CONF'
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
subjectAltName = DNS:vpa-webhook.kube-system.svc
CONF
    openssl genrsa -out "$CERTS/caKey.pem" 2048 >/dev/null
    openssl req -x509 -new -nodes -key "$CERTS/caKey.pem" -days 100000 \
      -out "$CERTS/caCert.pem" -subj "/CN=vpa_webhook_ca" \
      -addext "subjectAltName = DNS:vpa_webhook_ca"
    openssl genrsa -out "$CERTS/serverKey.pem" 2048 >/dev/null
    openssl req -new -key "$CERTS/serverKey.pem" -out "$CERTS/server.csr" \
      -subj "/CN=vpa-webhook.kube-system.svc" -config "$CERTS/server.conf"
    openssl x509 -req -in "$CERTS/server.csr" -CA "$CERTS/caCert.pem" \
      -CAkey "$CERTS/caKey.pem" -CAcreateserial \
      -out "$CERTS/serverCert.pem" -days 100000 \
      -extfile "$CERTS/server.conf" -extensions v3_req
    k -n kube-system create secret generic vpa-tls-certs \
      --from-file="$CERTS/caKey.pem" --from-file="$CERTS/caCert.pem" \
      --from-file="$CERTS/serverKey.pem" --from-file="$CERTS/serverCert.pem"
  fi
  # CRDs + RBAC first (the deployments' ServiceAccounts need the RBAC,
  # and the CRDs must exist before any VPA object is created — including
  # the demo object below).
  k apply -f "$VPA_DIR/vpa-v1-crd-gen.yaml"
  k apply -f "$VPA_DIR/vpa-rbac.yaml"
  k apply -f "$VPA_DIR/admission-controller-service.yaml"
  k apply -f "$VPA_DIR/updater-deployment.yaml"
  k apply -f "$VPA_DIR/recommender-deployment.yaml"
  k apply -f "$VPA_DIR/admission-controller-deployment.yaml"
  for d in vpa-updater vpa-recommender vpa-admission-controller; do
    k -n kube-system rollout status deploy/$d --timeout=300s
  done
  echo "VPA operator 1.7.3 installed (kube-system)."
fi

# 4. demo-app — the healthy HPA/VPA/PDB target (see header for rationale).
#    The resources stanza mirrors the LimitRange defaults: injection only
#    happens at pod CREATION (admission), so relying on it would leave
#    pre-existing pods from an earlier run with no resources on re-runs.
#    `apply` (not `create`) so a re-run is a no-op.
k -n "$NS" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  labels: {app: demo-app}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo-app}}
  template:
    metadata: {labels: {app: demo-app}}
    spec:
      containers:
        - name: app
          image: busybox:1.36
          command: ["/bin/sh", "-c", "sleep infinity"]
          resources:
            requests: {cpu: 50m, memory: 128Mi}
            limits: {cpu: 200m, memory: 256Mi}
YAML

# 5. One broken pod — references a nonexistent image so it CrashLoops.
#    Each restart emits Warning events the Events panel surfaces.
k -n "$NS" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-broken
  labels: {app: demo-broken}
spec:
  replicas: 1
  selector: {matchLabels: {app: demo-broken}}
  template:
    metadata: {labels: {app: demo-broken}}
    spec:
      containers:
        - name: broken
          image: registry.k8s.io/does-not-exist/missing:latest
          command: ["/bin/true"]
YAML

# 6. One instance of each remaining kind — the list + data views' fixtures.
#    Limits/quota headroom is generous so the HPA (max 3) can never be
#    admission-blocked by the demo-quota.
#
#    6a. demo-pvc migration (one-time): pre-CSI dev clusters carry a
#    local-path hostPath PV (claimRef demo-pvc), which the CSI driver cannot
#    serve. Detected by the PVC's storageClassName, so post-migration re-runs
#    are no-ops. The apply below recreates the claim on csi-hostpath.
if [ "$(k -n "$NS" get pvc demo-pvc -o jsonpath='{.spec.storageClassName}' 2>/dev/null || true)" != "csi-hostpath" ]; then
  k -n "$NS" delete pod demo-pvc-consumer --ignore-not-found >/dev/null
  # The PVC goes FIRST: deleting the bound PV before its claim is gone waits
  # on the PV's kubernetes.io/pv-protection finalizer, which kubectl delete
  # (no default timeout) blocks on forever. The PVC's deletion releases that
  # finalizer, and the PV's reclaimPolicy Delete makes the local-path
  # provisioner retire the hostPath PV itself.
  k -n "$NS" delete pvc demo-pvc --ignore-not-found --timeout=60s >/dev/null
  OLD_PV="$(k get pv -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.claimRef.name}{"\n"}{end}' | awk -F'\t' '$2=="demo-pvc"{print $1}')"
  if [ -n "$OLD_PV" ]; then
    k delete pv "$OLD_PV" --ignore-not-found --timeout=60s >/dev/null
  fi
fi
k -n "$NS" apply -f - <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: demo-secret
type: Opaque
stringData:
  api_token: kubedash-demo-token
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: demo-config
data:
  log-level: info
  feature-flags: '{"beta": true}'
  app-config: |
    # multi-line value — exercises the data page's <pre><code> wrapping
    mode: demo
    workers: 2
    timeout_seconds: 30
---
apiVersion: v1
kind: LimitRange
metadata:
  name: demo-limitrange
spec:
  limits:
    - type: Container
      min: {cpu: 10m, memory: 32Mi}
      max: {cpu: 500m, memory: 512Mi}
      defaultRequest: {cpu: 50m, memory: 128Mi}
      default: {cpu: 200m, memory: 256Mi}
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: demo-quota
spec:
  hard:
    pods: "20"
    secrets: "10"
    configmaps: "10"
    requests.cpu: "4"
    requests.memory: 8Gi
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: demo-pdb
spec:
  minAvailable: 1
  selector: {matchLabels: {app: demo-app}}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: demo-hpa
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: demo-app}
  minReplicas: 1
  maxReplicas: 3
  metrics:
    - type: Resource
      resource:
        name: cpu
        target: {type: Utilization, averageUtilization: 50}
---
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: demo-vpa
spec:
  targetRef: {apiVersion: apps/v1, kind: Deployment, name: demo-app}
  updatePolicy:
    updateMode: "Off"  # quoted: unquoted Off is a YAML boolean
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: demo-netpol
spec:
  podSelector: {matchLabels: {app: demo-app}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: demo-pvc
spec:
  # csi-hostpath (dev/csi-hostpath.yaml): provisioned dynamically by the
  # driver's csi-provisioner sidecar — WaitForFirstConsumer, so the PV is
  # created for the consumer pod's node. A CSI volume: unlike local-path's
  # hostPath PVs, the driver answers the kubelet's GetVolumeStats, so the
  # claim's volume reaches /stats/summary as a pvcRef entry.
  storageClassName: csi-hostpath
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 100Mi
---
# demo-pvc consumer: mounts the CSI-backed claim and seeds 8Mi of data on
# start. The mounted volume is what the kubelet's /stats/summary reports as
# a pvcRef entry (the data /metrics/pvcs aggregates — the list view's Usage
# column; csi-hostpath's statfs reports the backing-disk usage, so the
# figure is the dev node's disk percentage, see header).
apiVersion: v1
kind: Pod
metadata:
  name: demo-pvc-consumer
  labels: {app: demo-pvc-consumer}
spec:
  containers:
    - name: consumer
      image: busybox:1.36
      command: ["sh", "-c", "echo demo > /data/consumer.txt; dd if=/dev/zero of=/data/usage-seed bs=1M count=8 2>/dev/null; sleep 3600"]
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: demo-pvc
YAML

# The csi-provisioner creates the PV only after the consumer pod is scheduled
# (WaitForFirstConsumer), and the kubelet's CSI mount retries until the driver
# answers — wait on both so a driver failure fails the dev-stack loudly, not
# as a volume that silently never mounts. PVC "Bound" is a PHASE
# (.status.phase), not a condition — a plain bound PVC has an empty
# .status.conditions, so --for=condition=Bound would time out forever.
k -n "$NS" wait --for=jsonpath='{.status.phase}'=Bound pvc/demo-pvc --timeout=120s >/dev/null
k -n "$NS" wait --for=condition=Ready pod/demo-pvc-consumer --timeout=180s >/dev/null

# 7. RuntimeClass — cluster-scoped (handler "runc" is kind's runtime).
k apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: demo-runc
handler: runc
YAML

# 8. StorageClass — cluster-scoped. provisioner "rancher.local-path" is
#    kind's default provisioner, so the object is valid on the dev cluster
#    without extra CSI setup. No is-default-class annotation: the
#    cluster's "standard" class already demonstrates the true case, and
#    this row renders the "—" Default cell.
k apply -f - <<'YAML'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: demo-gp2
provisioner: rancher.local-path
reclaimPolicy: Delete
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
parameters:
  pool: demo
YAML

# 9. CRD fixture — the e2e deep-link scenario (ui-smoke.spec.ts) opens the
#    CRD named `configmaps.example.com`; without it the scenario is red for
#    setup reasons, not behavior (QA W012).
k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: configmaps.example.com
spec:
  group: example.com
  names:
    kind: ConfigMap
    listKind: ConfigMapList
    plural: configmaps
    singular: configmap
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML

# 10. SnapshotClass CRD + fixture — the SnapshotClass list/data views read
#     volumesnapshotclasses.snapshot.storage.k8s.io (a CLUSTER-SCOPED CRD).
#     The CRD's presence is what turns the read non-empty (CRD absent -> []).
#     csi-default uses driver "rancher.local-path" (kind's default provisioner)
#     + deletionPolicy Delete. Two applies: snapshot.storage.k8s.io is a
#     PROTECTED group (K8s >= 1.35) — the CRD needs the api-approved
#     annotation, and the object's client-side mapping is not resolvable in
#     the same invocation that creates its CRD.
k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: volumesnapshotclasses.snapshot.storage.k8s.io
  annotations:
    api-approved.kubernetes.io: "https://github.com/kubernetes/kubernetes/pull/82592"
spec:
  group: snapshot.storage.k8s.io
  names:
    kind: VolumeSnapshotClass
    listKind: VolumeSnapshotClassList
    plural: volumesnapshotclasses
    singular: volumesnapshotclass
  scope: Cluster
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
k wait --for=condition=Established crd/volumesnapshotclasses.snapshot.storage.k8s.io --timeout=30s >/dev/null
k apply -f - <<'YAML'
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshotClass
metadata:
  name: csi-default
driver: rancher.local-path
deletionPolicy: Delete
YAML

# 11. VolumeSnapshot CRD + fixture — the VolumeSnapshot list/data views read
#     volumesnapshots.snapshot.storage.k8s.io (a NAMESPACE-SCOPED CRD, unlike
#     the cluster-scoped VolumeSnapshotClass). The CRD's presence is what
#     turns the read non-empty (CRD absent -> []). NO status subresource: the
#     fixture carries status via a plain apply. demo-snap targets demo-pvc via
#     csi-default and is readyToUse (the 4.1 Usable success-badge tier).
#     Two applies + api-approved annotation: same protected-group reason as
#     section 10.
k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: volumesnapshots.snapshot.storage.k8s.io
  annotations:
    api-approved.kubernetes.io: "https://github.com/kubernetes/kubernetes/pull/82592"
spec:
  group: snapshot.storage.k8s.io
  names:
    kind: VolumeSnapshot
    listKind: VolumeSnapshotList
    plural: volumesnapshots
    singular: volumesnapshot
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
k wait --for=condition=Established crd/volumesnapshots.snapshot.storage.k8s.io --timeout=30s >/dev/null
k apply -f - <<'YAML'
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: demo-snap
  namespace: kubedash-demo
spec:
  source:
    persistentVolumeClaimName: demo-pvc
  volumeSnapshotClassName: csi-default
status:
  readyToUse: true
  restoreSize: 100Mi
YAML

# 12. cert-manager CRDs + fixtures — the Cert-Manager view (4 tabs) reads the
#     cert-manager.io/v1 registry kinds (list + per-kind data views). The CRD's
#     presence is what turns the read non-empty (CRD absent -> []). Minimal
#     schemas (x-kubernetes-preserve-unknown-fields) so the FULL spec/status is
#     preserved intact for the full-custom-object read path. NO operator is
#     installed: each fixture carries its own status (a Ready condition — the
#     view's green Success badge tier). clusterissuers is CLUSTER-scoped; the
#     other three are namespaced (matches real cert-manager AND the backend's
#     scope-respecting dispatch: namespaced kinds are read via the selected
#     namespace). One coherent story: an ACME ClusterIssuer, a selfSigned
#     Issuer, a Certificate (uses the ClusterIssuer, lands in demo-cert-tls),
#     and a CertificateRequest (owned by that Certificate, issued by the
#     namespaced Issuer — the Certificates/Request tabs' Issuer + Owner cells
#     and the in-page goToTab switch all have real targets).
k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterissuers.cert-manager.io
spec:
  group: cert-manager.io
  names:
    kind: ClusterIssuer
    listKind: ClusterIssuerList
    plural: clusterissuers
    singular: clusterissuer
  scope: Cluster
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: issuers.cert-manager.io
spec:
  group: cert-manager.io
  names:
    kind: Issuer
    listKind: IssuerList
    plural: issuers
    singular: issuer
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: certificaterequests.cert-manager.io
spec:
  group: cert-manager.io
  names:
    kind: CertificateRequest
    listKind: CertificateRequestList
    plural: certificaterequests
    singular: certificaterequest
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: certificates.cert-manager.io
spec:
  group: cert-manager.io
  names:
    kind: Certificate
    listKind: CertificateList
    plural: certificates
    singular: certificate
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
k wait --for=condition=Established \
  crd/clusterissuers.cert-manager.io \
  crd/issuers.cert-manager.io \
  crd/certificaterequests.cert-manager.io \
  crd/certificates.cert-manager.io --timeout=30s >/dev/null
k -n "$NS" apply -f - <<'YAML'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: demo-cluster-issuer
spec:
  acme:
    email: demo@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: demo-cluster-issuer-key
    solvers:
      - http01:
          ingress:
            className: traefik
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Ready
      message: issuer is ready
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: demo-issuer
spec:
  selfSigned: {}
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Ready
      message: issuer is ready
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: demo-cert
spec:
  secretName: demo-cert-tls
  issuerRef:
    name: demo-cluster-issuer
    kind: ClusterIssuer
  commonName: demo.local
  dnsNames:
    - demo.local
    - www.demo.local
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Ready
      message: Certificate is up to date and has not expired
  notAfter: "2027-02-05T00:00:00Z"
  renewalTime: "2026-12-31T00:00:00Z"
  revision: 1
YAML
# 12a. demo-cert-tls — the landed Secret of the Certificate: the Certificates
#     tab's Secret cell deep-links to /security/secret/data?name=demo-cert-tls,
#     so the target must exist for the link to land on real data. A
#     kubernetes.io/tls secret carries base64 PEM, so a real self-signed
#     keypair is generated (the VPA section's openssl procedure; no trap — the
#     temp dir is removed explicitly so it never clobbers the VPA trap).
#     Marker-checked on the secret (re-runs are no-ops).
if ! k -n "$NS" get secret demo-cert-tls >/dev/null 2>&1; then
  TLSCERTS="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 100000 \
    -keyout "$TLSCERTS/tls.key" -out "$TLSCERTS/tls.crt" \
    -subj "/CN=demo.local/O=kubedash-demo" \
    -addext "subjectAltName = DNS:demo.local,DNS:www.demo.local" >/dev/null 2>&1
  k -n "$NS" create secret tls demo-cert-tls \
    --cert="$TLSCERTS/tls.crt" --key="$TLSCERTS/tls.key"
  rm -rf "$TLSCERTS"
fi
# 12b. demo-cert-request — owned by demo-cert (the Request tab's Owner cell
#     renders it; the Issuer cell's goToTab switch targets demo-issuer). Its
#     controller ownerReference MUST carry demo-cert's REAL uid: a made-up uid
#     makes GC treat the request as an orphan of a missing controller owner
#     and cascade-delete it within seconds of creation. Applied SEPARATELY
#     (after the Certificate in the batch above) so the uid can be fetched;
#     the unquoted heredoc is what expands $CERT_UID (no other $ in the doc).
CERT_UID="$(k -n "$NS" get certificate demo-cert -o jsonpath='{.metadata.uid}')"
k -n "$NS" apply -f - <<YAML
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: demo-cert-request
  ownerReferences:
    - apiVersion: cert-manager.io/v1
      kind: Certificate
      name: demo-cert
      uid: $CERT_UID
      controller: true
      blockOwnerDeletion: true
spec:
  # base64 PEM CSR (dummy — the list view never decodes it; the data view
  # shows it verbatim).
  request: "TUlJRHdBTUJBREFOQkJNUUV3RHdZRFZRUUtFd3hWYjNKcmFXSmhZbTlvWm1VeElUQWVGQXhNQ0lHQXc9PQ=="
  duration: 720h
  renewBefore: 360h
  isCA: false
  usages: [server auth, client auth]
  issuerRef:
    name: demo-issuer
    kind: Issuer
status:
  conditions:
    - type: Ready
      status: "True"
      reason: Ready
      message: request is ready
  certificate: "TUlJQ3p6V0RBREFOQkJNUUV3RHdZRFZRUUtFd3hWYjNKcmFXSmhZbTlvWm1VeElUQWVGQXhNQ0lHQXc9PQ=="
YAML

# 13. MetalLB CRDs + fixtures — the LoadBalancer view (4 tabs) reads the
#     metallb.io/v1beta2 registry kinds. Provider detection is server-side
#     (MetalLB primary, Cilium fallback); the MetalLB CRDs' presence turns the
#     read non-empty AND tags each item provider=metallb (the view's Type
#     column). NO operator installed: the fixtures carry their spec only (these
#     kinds have no status the view renders).
#     ALL FOUR CRDs are NAMESPACED — the backend reads every MetalLB kind via
#     the namespaced endpoint (list_namespaced_custom_object), so a cluster-
#     scoped CRD would 404 on that read. This deliberately deviates from
#     upstream MetalLB (IPAddressPool/BGPPeer/BGPAdvertisement are cluster-
#     scoped there) to match THIS codebase's namespaced read path. Minimal
#     schemas preserve the full spec for the full-custom-object read.
k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ipaddresspools.metallb.io
spec:
  group: metallb.io
  names:
    kind: IPAddressPool
    listKind: IPAddressPoolList
    plural: ipaddresspools
    singular: ipaddresspool
  scope: Namespaced
  versions:
    - name: v1beta2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: l2advertisements.metallb.io
spec:
  group: metallb.io
  names:
    kind: L2Advertisement
    listKind: L2AdvertisementList
    plural: l2advertisements
    singular: l2advertisement
  scope: Namespaced
  versions:
    - name: v1beta2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: bgppeers.metallb.io
spec:
  group: metallb.io
  names:
    kind: BGPPeer
    listKind: BGPPeerList
    plural: bgppeers
    singular: bgppeer
  scope: Namespaced
  versions:
    - name: v1beta2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: bgpadvertisements.metallb.io
spec:
  group: metallb.io
  names:
    kind: BGPAdvertisement
    listKind: BGPAdvertisementList
    plural: bgpadvertisements
    singular: bgpadvertisement
  scope: Namespaced
  versions:
    - name: v1beta2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
k wait --for=condition=Established \
  crd/ipaddresspools.metallb.io \
  crd/l2advertisements.metallb.io \
  crd/bgppeers.metallb.io \
  crd/bgpadvertisements.metallb.io --timeout=30s >/dev/null
k -n "$NS" apply -f - <<'YAML'
apiVersion: metallb.io/v1beta2
kind: IPAddressPool
metadata:
  name: demo-pool
spec:
  addresses:
    - 192.168.100.100-192.168.100.110
  autoAssign: true
---
apiVersion: metallb.io/v1beta2
kind: L2Advertisement
metadata:
  name: demo-l2
spec:
  ipAddressPools:
    - demo-pool
  interfaces:
    - eth0
---
apiVersion: metallb.io/v1beta2
kind: BGPPeer
metadata:
  name: demo-bgp-peer
spec:
  peerAddress: 192.168.100.1
  myASN: 64512
  peerASN: 64500
  holdTime: 90
  keepaliveTime: 30
---
apiVersion: metallb.io/v1beta2
kind: BGPAdvertisement
metadata:
  name: demo-bgp-adv
spec:
  ipAddressPools:
    - demo-pool
  localPref: 100
  communities:
    - "64512:100"
YAML

# 14. Cilium LB fixtures — the LoadBalancer view's FALLBACK provider.
#     MetalLB is primary: with the section-13 metallb.io CRDs present the
#     backend reads MetalLB and these are invisible. Delete the four
#     metallb.io CRDs to see the view flip to these (tagged
#     provider=cilium) — the certified 5.0 provider-detection deviation.
#
#     The pinned Cilium 1.19.10 (dev/cilium-traefik-up.sh) ships the
#     ippools + l2announcementpolicies CRDs but NOT ciliumbgppeeringpolicies
#     (Gateway-API BGP is a gated feature there), and its ippools schema
#     uses spec.blocks (start/stop), not the newer spec.cidrs — the demo
#     pool below matches that shape. Each CRD is applied ONLY when absent:
#     when Cilium provides one, its real Helm-managed schema wins (no
#     clobber); the apply-if-absent keeps the demo working across Cilium
#     versions.
apply_cilium_crd() { # <name.cilium.io> <Kind> <singular> (single v2alpha1 version)
  local name="$1" kind="$2" singular="$3"
  if k get crd "$name" >/dev/null 2>&1; then
    echo "  cilium CRD $name: present (Cilium-provided) — skipping."
    return
  fi
  k apply -f - <<YAML
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: $name
spec:
  group: cilium.io
  names:
    kind: $kind
    listKind: ${kind}List
    plural: ${name%.cilium.io}
    singular: $singular
  scope: Cluster
  versions:
    - name: v2alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
  echo "  cilium CRD $name: applied (minimal, cluster-scoped)."
}
# ippools is special: the pinned Cilium 1.19.10 serves v2 (storage) +
# v2alpha1 (deprecated) and its schema is strict (spec.allowFirstLastIPs
# is a "Yes"/"No" STRING, not a bool). The demo pool targets v2 — so the
# minimal fallback CRD defines BOTH versions and lists v2 first, keeping
# the fixture's apiVersion valid with or without a real Cilium install.
if k get crd ciliumloadbalancerippools.cilium.io >/dev/null 2>&1; then
  echo "  cilium CRD ciliumloadbalancerippools.cilium.io: present (Cilium-provided) — skipping."
else
  k apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: ciliumloadbalancerippools.cilium.io
spec:
  group: cilium.io
  names:
    kind: CiliumLoadBalancerIPPool
    listKind: CiliumLoadBalancerIPPoolList
    plural: ciliumloadbalancerippools
    singular: ciliumloadbalancerippool
  scope: Cluster
  versions:
    - name: v2
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
    - name: v2alpha1
      served: true
      storage: false
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
  echo "  cilium CRD ciliumloadbalancerippools.cilium.io: applied (minimal, cluster-scoped)."
fi
apply_cilium_crd ciliuml2announcementpolicies.cilium.io CiliumL2AnnouncementPolicy ciliuml2announcementpolicy
apply_cilium_crd ciliumbgppeeringpolicies.cilium.io CiliumBGPPeeringPolicy ciliumbgppeeringpolicy
k wait --for=condition=Established \
  crd/ciliumloadbalancerippools.cilium.io \
  crd/ciliuml2announcementpolicies.cilium.io \
  crd/ciliumbgppeeringpolicies.cilium.io --timeout=30s >/dev/null

# The Cilium LB objects are Cluster-scoped (the backend reads them via
# list_cluster_custom_object) — no -n "$NS", unlike the MetalLB fixtures.
k apply -f - <<'YAML'
apiVersion: cilium.io/v2
kind: CiliumLoadBalancerIPPool
metadata:
  name: demo-cilium-pool
spec:
  blocks:
    - start: 10.200.100.100
      stop: 10.200.100.110
  disabled: false
---
apiVersion: cilium.io/v2alpha1
kind: CiliumL2AnnouncementPolicy
metadata:
  name: demo-cilium-l2
spec:
  serviceSelector:
    matchLabels:
      app: demo-app
---
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPPeeringPolicy
metadata:
  name: demo-cilium-bgp
spec:
  virtualRouters:
    - localASN: 64512
      neighbors:
        - peerAddress: 10.200.100.1
          peerASN: 64500
YAML

echo "demo data ready: ns=$NS"
echo "  pods: demo-app x1 (healthy, HPA/VPA/PDB target) + demo-broken x1 (crashlooping, events)"
echo "  fixtures: Secret, ConfigMap, LimitRange, ResourceQuota, PDB, HPA, VPA (Off mode), NetworkPolicy, PVC (demo-pvc, csi-hostpath, bound; Usage = backing-disk statfs)"
echo "  cluster-scoped: RuntimeClass demo-runc, StorageClass demo-gp2, CRD configmaps.example.com (e2e deep-link target)"
echo "  cluster-scoped: CRD volumesnapshotclasses.snapshot.storage.k8s.io + csi-default (SnapshotClass view)"
echo "  namespaced: CRD volumesnapshots.snapshot.storage.k8s.io + demo-snap (VolumeSnapshot view)"
echo "  cert-manager: 4x CRD (cert-manager.io/v1) + demo-cluster-issuer (ACME), demo-issuer (selfSigned), demo-cert (+demo-cert-tls secret), demo-cert-request (Cert-Manager view)"
echo "  load-balancer: 4x CRD (metallb.io/v1beta2, namespaced) + demo-pool, demo-l2, demo-bgp-peer, demo-bgp-adv (LoadBalancer view)"
echo "  load-balancer (fallback): Cilium objects (cluster-scoped) demo-cilium-pool, demo-cilium-l2, demo-cilium-bgp — hidden while the metallb.io CRDs are present (MetalLB is primary); delete the 4x metallb.io CRDs to flip the view to Cilium"
echo "  VPA recommendations land in the demo-vpa status within a few minutes"
echo "  kubectl --context $CTX get pods,hpa,vpa,pdb,netpol -n $NS -w"
