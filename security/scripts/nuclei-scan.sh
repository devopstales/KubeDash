#!/usr/bin/env bash
# Run Nuclei against KubeDash (hardcoded like zaproxy plan). Writes security/reports/nuclei-report.json.
# If no findings, writes [] for a valid JSON file. Run from repo root. KubeDash must be at https://localhost:5000.

TARGET="https://localhost:5000"
REPORTS_DIR="${REPORTS_DIR:-security/reports}"
REPORT="$REPORTS_DIR/nuclei-report.json"

mkdir -p "$REPORTS_DIR"
echo "Running Nuclei against $TARGET..."
nuclei -u "$TARGET" -je "$REPORT" -no-color 2>/dev/null || true

# Nuclei does not create the file (or leaves it empty) when there are no findings.
# Ensure a valid JSON file exists so DefectDojo can accept it.
if [ ! -s "$REPORT" ]; then
  echo '[]' > "$REPORT"
fi
