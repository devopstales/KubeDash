#!/usr/bin/env bash
# KubeDash dev-stack demo data — gives the dashboard something to show.
#
# Idempotent: safe to re-run. Brings up the local kind cluster (if absent),
# installs metrics-server (so the metrics/summary endpoint has data), creates
# a demo namespace with busy pods (so the Nodes/Dashboard metrics render), and
# one broken pod (so the Events panel has recent entries — k8s events expire
# after ~1h, so a stale cluster shows "No events found" without the churn).
#
# The cluster is registered in the app's registry by the Taskfile (kind-register)
# AFTER this script, so the dashboard's admin lens reaches it.
set -euo pipefail

CTX="kind-kubedash-test"
NS="kubedash-demo"

k() { kubectl --context "$CTX" "$@"; }

# 1. Namespace (no events).
k get namespace "$NS" >/dev/null 2>&1 || k create namespace "$NS"

# 2. Busy pods — consume CPU/memory so the metrics-server scrape has real
#    values. `kubectl top` / the summary endpoint degrade to empty without
#    running workloads, so these are what make the Dashboard metrics render.
# `apply` (not `create`) so a re-run is a no-op (create errors on existing).
k -n "$NS" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-busy
  labels: {app: demo-busy}
spec:
  replicas: 3
  selector: {matchLabels: {app: demo-busy}}
  template:
    metadata: {labels: {app: demo-busy}}
    spec:
      containers:
        - name: busy
          image: busybox:1.36
          command: ["/bin/sh", "-c", "while :; do :; done"]
YAML

# 3. One broken pod — references a nonexistent image so it CrashLoops. Each
#    restart emits Warning events (BackOff / ImagePullBackOff) that the Events
#    panel surfaces. This is the "events etc." part.
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

echo "demo data ready: ns=$NS  pods: demo-busy x3 (running) + demo-broken x1 (crashlooping)"
echo "  kubectl --context $CTX get pods -n $NS -w"
