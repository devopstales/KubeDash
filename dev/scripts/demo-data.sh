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
#   - demo-secret / demo-limitrange / demo-quota / demo-pdb / demo-hpa /
#     demo-vpa / demo-netpol: one instance of each kind so the list +
#     data views render real data.
#   - demo-runc: cluster-scoped RuntimeClass (handler "runc" = kind's
#     containerd runtime).
#   - configmaps.example.com: CRD fixture for the e2e deep-link scenario
#     (ui-smoke.spec.ts); without it the scenario is red for setup
#     reasons, not behavior (QA W012).
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
YAML

# 7. RuntimeClass — cluster-scoped (handler "runc" is kind's runtime).
k apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: demo-runc
handler: runc
YAML

# 8. CRD fixture — the e2e deep-link scenario (ui-smoke.spec.ts) opens the
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

echo "demo data ready: ns=$NS"
echo "  pods: demo-app x1 (healthy, HPA/VPA/PDB target) + demo-broken x1 (crashlooping, events)"
echo "  fixtures: Secret, LimitRange, ResourceQuota, PDB, HPA, VPA (Off mode), NetworkPolicy"
echo "  cluster-scoped: RuntimeClass demo-runc, CRD configmaps.example.com (e2e deep-link target)"
echo "  VPA recommendations land in the demo-vpa status within a few minutes"
echo "  kubectl --context $CTX get pods,hpa,vpa,pdb,netpol -n $NS -w"
