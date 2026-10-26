#!/usr/bin/env bash
# dev-stack demo-data orchestrator (Taskfile _dev-kind-and-demo-data).
#
# Skips (with a notice) when kind/kubectl are absent so the plain-HTTP loop
# still works on a machine without the K8s toolchain. Each step is idempotent:
#   1. kind cluster (created only if absent) + metrics-server
#   2. demo namespace: busy pods (metrics render) + 1 crashlooping pod
#      (events panel has recent entries — k8s events expire ~1h)
#   3. register the cluster in the registry (409 = already registered)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v kind >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
  echo "kind/kubectl not found — skipping demo data (dashboard will be empty)."
  echo "Install kind + kubectl and re-run 'task dev-stack' to seed it."
  exit 0
fi

# kind-up: cluster (if absent) + metrics-server, then the demo pods + register.
(cd "$ROOT" && task kind-up)
bash "$ROOT/dev/scripts/demo-data.sh"
bash "$ROOT/dev/scripts/cluster-register.sh"
