#!/usr/bin/env bash
# Register the local kind cluster in the KubeDash registry (dev-stack).
#
# Idempotent: a 409 CLUSTER_ALREADY_EXISTS (already registered) is a no-op
# success; any other error fails the run. Logs in as the bootstrap admin
# (admin@local/admin — the dev-stack defaults) and POSTs the kind cluster's
# own kubeconfig, so the dashboard's admin lens reaches the real K8s API
# (nodes, pods, metrics, events).
set -euo pipefail

BASE="${KUBEDASH_BASE_URL:-http://localhost:8080}"
CTX="kind-kubedash-test"
NAME="kubedash-test"
EMAIL="${KUBEDASH_ADMIN_EMAIL:-admin@local}"
PASSWORD="${KUBEDASH_ADMIN_PASSWORD:-admin}"

# The kind cluster's kubeconfig (valid YAML; the handler validates + encrypts).
KC="$(kubectl --context "$CTX" config view --raw)"
API_SERVER="$(kubectl --cluster "$CTX" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"

# Log in → kd_access cookie. The 302 parks the tokens in the Location; we only
# need the session cookie the API uses.
# Wait for the backend to accept connections (dev-stack starts it in the
# background; the boot — app factory + local-admin upsert + RQ — can take a
# few seconds, longer than the task's `sleep 2`).
for i in $(seq 1 30); do
  curl -sS -o /dev/null -w '' "$BASE/healthz" 2>/dev/null && break
  sleep 1
done

COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT
curl -sS -c "$COOKIE_JAR" -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/v1/auth/local" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null

# Build the JSON body in python (the kubeconfig is multi-line YAML; hand-quoting
# in bash is fragile).
BODY="$(KC_FILE=/tmp/kubedash-demo-kc.$$.yaml API_SERVER="$API_SERVER" python3 - "$KC" "$API_SERVER" <<'PY'
import json, os, sys
kc = sys.argv[1]
api_server = sys.argv[2]
open(os.environ['KC_FILE'], 'w').write(kc)
print(json.dumps({
    "name": "kubedash-test",
    "api_server": api_server,
    "kubeconfig": kc,
    "context": "kind-kubedash-test",
}))
PY
)"

CODE="$(curl -sS -b "$COOKIE_JAR" -o /tmp/kubedash-register-resp.$$.json -w '%{http_code}' \
  -X POST "$BASE/api/v1/clusters" \
  -H 'Content-Type: application/json' \
  -d "$BODY")"

case "$CODE" in
  201) echo "registered cluster '$NAME' (kind context $CTX)" ;;
  409) echo "cluster '$NAME' already registered (no-op)" ;;
  *) echo "cluster registration failed (HTTP $CODE):" >&2
     cat "/tmp/kubedash-register-resp.$$.json" >&2 || true
     rm -f "/tmp/kubedash-register-resp.$$.json"
     exit 1 ;;
esac
rm -f "/tmp/kubedash-register-resp.$$.json"
