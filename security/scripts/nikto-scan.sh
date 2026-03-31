#!/usr/bin/env bash
# Run Nikto against KubeDash (hardcoded like zaproxy plan). Writes security/reports/nikto-report.json.
# Run from repo root. KubeDash must be at https://127.0.0.1:5000.
# Note: Nikto 2.6.0 has a known bug in the JSON plugin (Perl encoder) that can leave the file empty;
# upgrade Nikto (git pull) or use a newer build if the report is 0 bytes.

TARGET="https://127.0.0.1:5000"
REPORTS_DIR="${REPORTS_DIR:-security/reports}"

mkdir -p "$REPORTS_DIR"
OUTPUT_FILE="$(pwd)/$REPORTS_DIR/nikto-report.json"
echo "Running Nikto against $TARGET..."

nikto -h "$TARGET" -o "$OUTPUT_FILE" -Format json 2>/dev/null || true
