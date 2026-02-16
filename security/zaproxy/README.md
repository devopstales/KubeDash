# ZAP API Scan for KubeDash

API penetration testing using [OWASP ZAP](https://www.zaproxy.org/) and the [ZAP-APIScan-AutomationFramework](https://github.com/patidar-jaishree/ZAP-APIScan-AutomationFramework) approach.

The OpenAPI spec is **loaded directly from the running KubeDash app** at `/api/openapi.json`; no local spec file is required.

## Prerequisites

- Docker
- KubeDash running at `http://localhost:5000` (from the host; ZAP in Docker reaches it via `host.docker.internal:5000`)

## Quick start

1. Start KubeDash (e.g. on port 5000).
2. Run the scan:

   ```bash
   task zap-scan
   ```

3. Reports are written to `security/reports/` (HTML, XML, JSON, and SARIF).

## Taskfile tasks

| Task | Description |
|------|-------------|
| `task zap-pull` | Pull the ZAP Docker image |
| `task zap-scan` | Run ZAP API scan (loads OpenAPI from app at `/api/openapi.json`) |

## Configuration

- **ZAP_PLAN**: Plan file path relative to `security/zaproxy` (default: `plans/kubedash-plan.yaml`).
- The plan uses `https://host.docker.internal:5000` so ZAP in Docker can reach KubeDash on the host. To scan a different host/port, edit `plans/kubedash-plan.yaml` (context URLs and openapi job `apiUrl` / `targetUrl`).

## Authentication

The scan uses **admin / admin** to log in automatically. An HttpSender script (`scripts/GetToken_kubedash.js`) fetches the login page, extracts the Flask CSRF token, POSTs the credentials, and adds the session cookie to all requests. No manual login or cookie export is needed. To use different credentials, edit the `LOGIN_USER` and `LOGIN_PASS` constants at the top of `GetToken_kubedash.js`.

## Reports and DefectDojo

After `task zap-scan`, the following files are produced in **`security/reports/`** (shared with Semgrep):

| File | Format | Use |
|------|--------|-----|
| `kubedashHtmlReport.html` | HTML | Human-readable report |
| `kubedashXmlReport.xml` | XML | ZAP native; DefectDojo ZAP parser (XML) |
| `kubedashJsonReport.json` | JSON | ZAP traditional JSON; tooling / scripts |
| `kubedashSarifReport.json` | SARIF | **DefectDojo**: Import Scan → Scanner “SARIF” → upload this file |

To import into [DefectDojo](https://defectdojo.org/): use **Import Scan**, choose the **SARIF** parser, and upload `security/reports/kubedashSarifReport.json`. DefectDojo’s [SARIF parser](https://docs.defectdojo.com/supported_tools/parsers/file/sarif/) supports deduplication and normalizes findings.

**Automated upload:** from the repo root run `task defectdojo-upload` with `DOJO_HOST` and `DOJO_API` set. This uploads ZAP SARIF, Semgrep JSON, Trivy, Nikto, and Nuclei reports from `security/reports/` to DefectDojo ([Semgrep + DefectDojo](https://semgrep.dev/docs/kb/integrations/defect-dojo-integration)).

## Directory layout

```
security/zaproxy/
├── README.md
├── plans/
│   └── kubedash-plan.yaml   # Uses apiUrl to load spec from app
├── openapi-specs/           # Optional: not used when using apiUrl
└── scripts/
    └── GetToken_kubedash.js # Login script (admin/admin, handles CSRF)
```

**`security/reports/`** (at repo root) is the shared output folder for:

- **ZAP** (this scan): HTML, XML, JSON, SARIF
- **Semgrep** (`task kubedash-semgrep`): `semgrep-report.json`
- **Trivy** (`task kubedash-scan`, `task kubedash-prod-scan`, `task kdlogin-scan`): `trivy-fs-report.json`, `trivy-image-report.json`, `trivy-sbom.cdx.json`, `trivy-kdlogin-fs-report.json`
- **Nikto** (`task nikto-scan`): `nikto-report.json`
- **Nuclei** (`task nuclei-scan`): `nuclei-report.json`
