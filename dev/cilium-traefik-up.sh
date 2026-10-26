#!/usr/bin/env bash
# dev-stack: install Cilium + Gateway API + Traefik into the local kind cluster.
#
# Called by `task kind-up` AFTER the cluster exists. Idempotent: each step
# checks for its own success marker and skips when already done.
#
#   1. Gateway API CRDs (standard channel v1.2.1) — the CRDs Cilium + Traefik
#      both watch (GatewayClass, Gateway, HTTPRoute, ReferenceGrant).
#   2. Cilium v1.19.10 (Helm, ipam.mode=kubernetes) — CNI (replaces kindnet
#      when created with kind-config.yaml disableDefaultCNI).
#   3. Traefik v3.4 (Helm, kubernetesGateway provider) — Gateway API
#      controller (auto-creates a GatewayClass named "traefik") + Ingress
#      provider (kind's loadbalancer IPs are reachable from the host).
#
# Skips (with a notice) when helm/kind/kubectl are absent, so the plain-HTTP
# loop still works on a machine without the full K8s toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTX="kind-kubedash-test"

CILIUM_VERSION="1.19.10"
CILIUM_IMAGE="quay.io/cilium/cilium:v${CILIUM_VERSION}"
GATEWAY_API_VERSION="1.2.1"
GATEWAY_API_URL="https://github.com/kubernetes-sigs/gateway-api/releases/download/v${GATEWAY_API_VERSION}"
TRAEFIK_CHART_VERSION="34.2.0"

k() { kubectl --context "$CTX" "$@"; }

if ! command -v helm >/dev/null 2>&1 || ! command -v kind >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
  echo "helm/kind/kubectl not found — skipping Cilium + Traefik install."
  echo "Install them and re-run 'task kind-up'."
  exit 0
fi

# --- 1. Gateway API CRDs (standard channel) ---------------------------------
# Both Cilium and Traefik watch these CRDs. The standard channel covers
# GatewayClass, Gateway, HTTPRoute, ReferenceGrant (the v1 channel).
if k get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  echo "gateway-api CRDs already present — skipping."
else
  echo "Installing Gateway API v${GATEWAY_API_VERSION} (standard channel)..."
  curl -sL "${GATEWAY_API_URL}/standard-install.yaml" | k apply -f -
fi

# --- 2. Cilium (CNI) ---------------------------------------------------------
# ipam.mode=kubernetes: use kind's pod CIDR (10.244.0.0/16) for IPAM.
# If the cluster was created with the default CNI (kindnet), Cilium installs
# as a second CNI — kindnet keeps working. The image is preloaded into the
# kind node so the agent pod starts fast.
if k -n kube-system get daemonset cilium >/dev/null 2>&1; then
  echo "Cilium already installed — skipping."
else
  echo "Installing Cilium v${CILIUM_VERSION} (Helm, ipam.mode=kubernetes)..."
  docker pull "$CILIUM_IMAGE" 2>/dev/null || true
  kind load docker-image "$CILIUM_IMAGE" --name kubedash-test 2>/dev/null || true

  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm repo update >/dev/null 2>&1 || true

  helm upgrade --install cilium cilium/cilium \
    --version "$CILIUM_VERSION" \
    --namespace kube-system \
    --set image.pullPolicy=IfNotPresent \
    --set ipam.mode=kubernetes \
    --wait --timeout 300s
fi

# Wait for the Cilium DaemonSet to be ready.
if k -n kube-system get daemonset cilium >/dev/null 2>&1; then
  k -n kube-system rollout status daemonset/cilium --timeout=300s
fi

# --- 3. Traefik (Gateway API + Ingress controller) ---------------------------
# kubernetesGateway.enabled=true enables the Gateway API provider — Traefik
# auto-creates a GatewayClass named "traefik" (controller: traefik.io/gateway-controller).
# The Ingress provider is enabled by default, so both Ingress and Gateway API
# objects are testable from the dashboard.
if k -n traefik get deployment traefik >/dev/null 2>&1; then
  echo "Traefik already installed — skipping."
else
  echo "Installing Traefik (Helm, kubernetesGateway provider)..."
  helm repo add traefik https://traefik.github.io/charts >/dev/null 2>&1 || true
  helm repo update >/dev/null 2>&1 || true

  helm upgrade --install traefik traefik/traefik \
    --version "$TRAEFIK_CHART_VERSION" \
    --namespace traefik \
    --create-namespace \
    --set "providers.kubernetesGateway.enabled=true" \
    --set service.type=NodePort \
    --wait --timeout 120s
fi

echo ""
echo "Cilium + Traefik ready:"
echo "  CNI:               Cilium (ipam.mode=kubernetes)"
echo "  GatewayClass:      traefik (traefik.io/gateway-controller)"
echo "  Ingress provider:  Traefik (default)"
echo ""
echo "Verify:"
echo "  kubectl --context $CTX get gatewayclass"
echo "  kubectl --context $CTX get ingress -A"
echo "  kubectl --context $CTX get gateway -A"
