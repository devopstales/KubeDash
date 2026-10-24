#!/usr/bin/env bash
# ADR-0026: local TLS for the dev stack. Idempotent: safe to re-run.
#   generate  leaf certs for kubedash.local (browser leg) + kubedash-backend
#             (internal leg, nginx -> backend), signed by the mkcert rootCA
#   verify    openssl chain check + curl check (needs the edge up)
#   hosts     append 127.0.0.1 kubedash.local to /etc/hosts (needs sudo)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="$ROOT/dev/certs"

case "${1:-}" in
  generate)
    mkdir -p "$CERTS"
    cp "$(mkcert -CAROOT)/rootCA.pem" "$CERTS/rootCA.pem"
    [ -f "$CERTS/kubedash.local.pem" ] || mkcert -cert-file "$CERTS/kubedash.local.pem" \
      -key-file "$CERTS/kubedash.local-key.pem" kubedash.local 127.0.0.1 localhost
    # Internal leg: a leaf for the backend. Subject is the backend's
    # internal name; nginx verifies it against rootCA.pem (not the browser
    # trust store), so SAN = kubedash-backend suffices.
    [ -f "$CERTS/backend.pem" ] || mkcert -cert-file "$CERTS/backend.pem" \
      -key-file "$CERTS/backend-key.pem" kubedash-backend
    echo "certs in $CERTS (gitignored)"
    ;;
  verify)
    openssl verify -CAfile "$CERTS/rootCA.pem" "$CERTS/kubedash.local.pem"
    openssl verify -CAfile "$CERTS/rootCA.pem" "$CERTS/backend.pem"
    # The browser-leg proof (needs the edge up + hosts entry):
    curl -sSfI https://kubedash.local:443/healthz | head -3
    ;;
  hosts)
    grep -qE '^\s*127\.0\.0\.1\s+kubedash\.local' /etc/hosts \
      || echo "127.0.0.1 kubedash.local" | sudo tee -a /etc/hosts
    ;;
  *) echo "usage: setup-tls.sh generate|verify|hosts" >&2; exit 2 ;;
esac
