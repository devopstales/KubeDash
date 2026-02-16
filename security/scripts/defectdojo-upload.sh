#!/usr/bin/env bash
# Upload security reports to DefectDojo. Set DOJO_HOST and DOJO_API.
# Optional: DOJO_PRODUCT_NAME (default KubeDash), DOJO_ENGAGEMENT_NAME (default security-scan)
# Optional: DOJO_REIMPORT=1 to use reimport-scan instead of import-scan.
# Optional: DOJO_DEBUG=1 to print API error response body when upload returns 4xx/5xx.
# Uses auto_create_context so product/engagement are created if missing; scan_date, active, verified are set.

REPORTS_DIR="${REPORTS_DIR:-security/reports}"
HOST="${DOJO_HOST}"
TOKEN="${DOJO_API}"
PRODUCT="${DOJO_PRODUCT_NAME:-KubeDash}"
ENGAGEMENT="${DOJO_ENGAGEMENT_NAME:-security-scan}"

if [ -z "$HOST" ] || [ -z "$TOKEN" ]; then
  echo "❌ Set DOJO_HOST and DOJO_API (DefectDojo URL and API token)"
  echo "   Example: export DOJO_HOST=https://defectdojo.example.com DOJO_API=your-token && task defectdojo-upload"
  exit 1
fi

HOST="${HOST%/}"
ENDPOINT="import-scan"
[ "${DOJO_REIMPORT}" = "1" ] && ENDPOINT="reimport-scan"

echo "Uploading to DefectDojo: $HOST (product=$PRODUCT, engagement=$ENGAGEMENT)"
UPLOADED=0

# Optional: set DOJO_DEBUG=1 to print API error response body on failure
upload_one() {
  local f="$1" st="$2" title="$3"
  [ ! -f "$f" ] && return
  echo "  → $title"
  RESP=$(mktemp)
  CODE=$(curl -sS -w "%{http_code}" -o "$RESP" -X POST "$HOST/api/v2/$ENDPOINT/" \
    -H "Authorization: Token $TOKEN" \
    -F "file=@$f" \
    -F "scan_type=$st" \
    -F "product_name=$PRODUCT" \
    -F "engagement_name=$ENGAGEMENT" \
    -F "test_title=$title" \
    -F "scan_date=$(date +%Y-%m-%d)" \
    -F "auto_create_context=true" \
    -F "active=true" \
    -F "verified=false")
  if echo "$CODE" | grep -qE '^200|^201|^202'; then
    echo "     OK"
    UPLOADED=$((UPLOADED+1))
  else
    echo "     Failed (HTTP $CODE)"
    if [ "${DOJO_DEBUG}" = "1" ]; then
      echo "     Response:"
      sed 's/^/       /' < "$RESP"
    fi
  fi
  rm -f "$RESP"
}

upload_one "$REPORTS_DIR/semgrep-report.json" "Semgrep JSON Report" "Semgrep"
# ZAP Scan 
upload_one "$REPORTS_DIR/kubedashSarifReport.json" "SARIF" "ZAP SARIF"
upload_one "$REPORTS_DIR/trivy-fs-report.json" "Trivy Scan" "Trivy FS"
upload_one "$REPORTS_DIR/trivy-image-report.json" "Trivy Scan" "Trivy Image"
#upload_one "$REPORTS_DIR/nikto-report.json" "Nikto Scan" "Nikto"
upload_one "$REPORTS_DIR/nuclei-report.json" "Nuclei Scan" "Nuclei"

if [ "$UPLOADED" -eq 0 ]; then
  echo "No report files found in $REPORTS_DIR or all uploads failed. Run zap-scan, kubedash-semgrep, kubedash-scan, nikto-scan, nuclei-scan first."
  exit 1
fi

echo "✅ Uploaded $UPLOADED report(s) to DefectDojo"
