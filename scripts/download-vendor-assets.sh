#!/usr/bin/env bash
# Download front-end vendor assets so the app works without CDNs (air-gapped).
# Run once from repo root when you have network, then commit the downloaded files.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATIC="$REPO_ROOT/src/kubedash/static/vendor"

echo "Downloading vendor assets to $STATIC ..."

mkdir -p "$STATIC/cytoscape@3.28.1"
curl -sSL -o "$STATIC/cytoscape@3.28.1/cytoscape.min.js" \
  "https://unpkg.com/cytoscape@3.28.1/dist/cytoscape.min.js"

mkdir -p "$STATIC/dagre@0.8.5/dist"
curl -sSL -o "$STATIC/dagre@0.8.5/dist/dagre.min.js" \
  "https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"

mkdir -p "$STATIC/cytoscape-dagre@2.5.0"
curl -sSL -o "$STATIC/cytoscape-dagre@2.5.0/cytoscape-dagre.js" \
  "https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"

mkdir -p "$STATIC/google/webfonts"
curl -sSL -o "$STATIC/google/webfonts/materialicons.woff2" \
  "https://fonts.gstatic.com/s/materialicons/v139/flUhRq6tzZclQEJ-Vdg-IuiaDsNcIhQ8tQ.woff2"

echo "Done. Commit the files under src/kubedash/static/vendor/ for air-gapped use."
