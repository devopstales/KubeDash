#!/usr/bin/env bash
# dev-stack demo-data orchestrator (Taskfile _dev-kind-and-demo-data).
#
# Skips (with a notice) when kind/kubectl are absent so the plain-HTTP loop
# still works on a machine without the K8s toolchain. Each step is idempotent:
#   1. kind cluster (created only if absent) + metrics-server + Cilium/Traefik
#   2. demo namespace: 1 healthy pod (HPA/VPA/PDB target) + 1 broken pod
#      (events panel has recent entries — k8s events expire ~1h) + one
#      fixture per kind (Secret, LimitRange, Quota, PDB, HPA, VPA,
#      NetworkPolicy) + the VPA operator (kube-system) + RuntimeClass
#
# Cluster REGISTRATION is deliberately NOT here: it needs the backend's API
# (POST /api/v1/clusters), and this script runs BEFORE the backend (so the app
# boots against a live cluster). The Taskfile runs cluster-register.sh as a
# separate _dev-register-cluster step AFTER backend-stack-run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v kind >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
  echo "kind/kubectl not found — skipping demo data (dashboard will be empty)."
  echo "Install kind + kubectl and re-run 'task dev-stack' to seed it."
  exit 0
fi

# kind-up: cluster (if absent) + metrics-server + Cilium/Traefik, then the
# demo pods. (Registration is separate — see the header.) This script lives in
# dev/scripts/, so sibling scripts are $SCRIPT_DIR/<name>.sh.
(cd "$ROOT" && task kind-up)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/demo-data.sh"
