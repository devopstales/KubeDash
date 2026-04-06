---
description: Run Trivy security scanner for vulnerabilities, misconfigurations, and secrets
argument-hint: [fs | image <name> | config <path> | repo <url>] [--severity CRITICAL,HIGH]
---

# Trivy Security Scan

**Input**: $ARGUMENTS

---

## Phase 1 — DETECT

Check if trivy is available:

```bash
trivy --version
```

If not found, stop with error:
```
Trivy not found. Install with:
  brew install trivy
  trivy plugin install mcp
```

## Phase 2 — CONFIGURE

Parse `$ARGUMENTS` to determine scan target:

| Input | Mode | Target |
|---|---|---|
| (empty) | `fs` | Current directory (filesystem) |
| `fs` | `fs` | Filesystem scan |
| `image <name>` | `image` | Container image scan |
| `config <path>` | `config` | IaC misconfiguration scan |
| `repo <url>` | `repo` | Git repository scan |
| `--severity CRITICAL,HIGH` | filter | Filter by severity |

Default: `trivy fs --severity CRITICAL,HIGH --exit-code 1 .`

## Phase 3 — SCAN

### Filesystem Scan (default)

Scan project for vulnerabilities in dependencies, secrets, and misconfigurations:

```bash
# Default scan — critical and high severity
trivy fs \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  --format table \
  .

# JSON report for analysis
trivy fs \
  --severity CRITICAL,HIGH \
  --format json \
  --output trivy-report.json \
  .
```

### Container Image Scan

If `$ARGUMENTS` contains `image <name>`:

```bash
trivy image \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  <image-name>

# With JSON report
trivy image \
  --severity CRITICAL,HIGH \
  --format json \
  --output trivy-image-report.json \
  <image-name>
```

### IaC Configuration Scan

If `$ARGUMENTS` contains `config <path>`:

```bash
trivy config \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  <path>
```

### Git Repository Scan

If `$ARGUMENTS` contains `repo <url>`:

```bash
trivy repo \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  <url>
```

## Phase 4 — ANALYZE

Parse the JSON report and categorize findings:

```bash
# Count vulnerabilities by severity
jq '[.Results[] | .Vulnerabilities[]? | .Severity] | group_by(.) | map({severity: .[0], count: length})' trivy-report.json

# List unique packages with vulnerabilities
jq '[.Results[] | .Vulnerabilities[]? | {pkg: .PkgName, vuln: .VulnerabilityID, severity: .Severity}] | group_by(.pkg) | map({package: .[0].pkg, count: length, vulns: [.[].VulnerabilityID]})' trivy-report.json

# Misconfigurations
jq '[.Results[] | select(.Type == "") | .Misconfigurations[]?] | length' trivy-report.json

# Secrets detected
jq '[.Results[] | .Secrets[]?] | length' trivy-report.json
```

For each CRITICAL/HIGH finding:
1. Identify the vulnerable package or config
2. Explain the CVE or misconfiguration risk
3. Check if a fixed version exists
4. Suggest remediation

## Phase 5 — REPORT

Generate report at `trivy-results.md`:

```markdown
# Trivy Security Scan Results

**Date**: <date>
**Mode**: <fs|image|config|repo>
**Target**: <target>

## Summary

| Type | Count |
|---|---|
| Vulnerabilities | <count> |
| Misconfigurations | <count> |
| Secrets | <count> |

## Vulnerabilities by Severity

| Severity | Count |
|---|---|
| CRITICAL | <count> |
| HIGH | <count> |
| MEDIUM | <count> |
| LOW | <count> |

## CRITICAL Vulnerabilities

| Package | Version | CVE | Severity | Fixed Version |
|---|---|---|---|---|

## HIGH Vulnerabilities

| Package | Version | CVE | Severity | Fixed Version |
|---|---|---|---|---|

## Misconfigurations

| File | ID | Title | Severity | Resolution |
|---|---|---|---|---|

## Secrets Detected

| File | Rule | Severity |
|---|---|---|
```

## Phase 6 — RECOMMEND

Based on findings:

- **CRITICAL vulnerabilities**: Block deploy. Update packages immediately.
- **HIGH vulnerabilities**: Should fix before deploy. Document exceptions.
- **Misconfigurations**: Fix IaC files (Dockerfile, Terraform, K8s manifests).
- **Secrets exposed**: Rotate credentials immediately. Add to `.gitignore` or use vault.
- **Clean scan**: No issues found. Schedule regular scans.

Suggest follow-up actions:
- Add trivy to CI/CD pipeline
- Enable trivy MCP server for ongoing monitoring
- Set up SBOM generation: `trivy fs --format spdx-json --output sbom.json .`
- Schedule periodic image scans for production containers

---

## Quick Scans

### Fast dependency check
```bash
trivy fs --severity CRITICAL .
```

### Dockerfile scan
```bash
trivy config Dockerfile
```

### Kubernetes manifest scan
```bash
trivy config k8s/
```

### Terraform scan
```bash
trivy config terraform/
```

### Generate SBOM
```bash
trivy fs --format spdx-json --output sbom.json .
```
