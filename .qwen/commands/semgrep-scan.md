---
description: Run Semgrep security and code analysis scan on the project
argument-hint: [--config auto | --config p/owasp-top-ten | --config <path> | --severity <CRITICAL|HIGH|MEDIUM|LOW>]
---

# Semgrep Security Scan

**Input**: $ARGUMENTS

---

## Phase 1 — DETECT

Check if semgrep is available:

```bash
semgrep --version
```

If not found, stop with error:
```
Semgrep not found. Install with:
  brew install semgrep
  pip install semgrep
```

## Phase 2 — CONFIGURE

Parse `$ARGUMENTS` to determine scan configuration:

| Input | Config | Use Case |
|---|---|---|
| (empty) | `--config auto` | Default — comprehensive rules |
| `--config auto` | `--config auto` | Semgrep registry auto rules |
| `--config p/owasp-top-ten` | `--config p/owasp-top-ten` | OWASP Top 10 focus |
| `--config p/cwe-top-25` | `--config p/cwe-top-25` | CWE Top 25 focus |
| `--config p/r2c-security-audit` | `--config p/r2c-security-audit` | Security audit rules |
| `--config <path>` | `--config <path>` | Custom rules file |
| `--severity CRITICAL` | `--severity CRITICAL` | Filter by severity |

Default: `--config auto --severity CRITICAL --severity HIGH`

## Phase 3 — SCAN

Run semgrep with appropriate configuration:

```bash
# Default scan — critical and high severity only
semgrep scan \
  --config auto \
  --severity CRITICAL \
  --severity HIGH \
  --max-target-bytes 10M \
  --timeout 30 \
  --timeout-threshold 3 \
  --jobs 4 \
  --output semgrep-report.json \
  --json \
  .

# Human-readable output to stdout
semgrep scan \
  --config auto \
  --severity CRITICAL \
  --severity HIGH \
  --max-target-bytes 10M \
  --timeout 30 \
  --timeout-threshold 3 \
  --jobs 4 \
  .
```

If `$ARGUMENTS` specifies custom config:
```bash
semgrep scan $ARGUMENTS --output semgrep-report.json --json .
semgrep scan $ARGUMENTS
```

## Phase 4 — ANALYZE

Parse the JSON report and categorize findings:

```bash
# Count findings by severity
jq '[.results[] | .extra.severity] | group_by(.) | map({severity: .[0], count: length})' semgrep-report.json

# List unique rule IDs
jq '[.results[] | .check_id] | unique' semgrep-report.json

# Findings by file
jq '[.results[] | .path] | group_by(.) | map({file: .[0], count: length}) | sort_by(.count) | reverse' semgrep-report.json
```

For each CRITICAL/HIGH finding, read the affected file and:
1. Identify the vulnerable code pattern
2. Explain the security risk
3. Suggest a fix

## Phase 5 — REPORT

Generate report at `semgrep-results.md`:

```markdown
# Semgrep Security Scan Results

**Date**: <date>
**Config**: <config used>
**Files Scanned**: <count>

## Summary

| Severity | Count |
|---|---|
| CRITICAL | <count> |
| HIGH | <count> |
| MEDIUM | <count> |
| LOW | <count> |

## CRITICAL Findings

<each finding with file, line, rule, description, and suggested fix>

## HIGH Findings

<each finding with file, line, rule, description, and suggested fix>

## Top Rules Triggered

| Rule | Count | Description |
|---|---|---|

## Files with Most Issues

| File | Issues |
|---|---|
```

## Phase 6 — RECOMMEND

Based on findings:

- **CRITICAL found**: Block merge/deploy. Must fix before proceeding.
- **HIGH found**: Should fix before merge. Document exceptions.
- **Only MEDIUM/LOW**: Fix recommended. Can defer with tracking issue.
- **Clean scan**: No issues found. Consider expanding config for deeper scan.

Suggest follow-up actions:
- Add custom rules for project-specific patterns
- Integrate into CI/CD pipeline
- Set up Semgrep App for team dashboards
- Schedule regular scans

---

## Common Configs

| Config | Description |
|---|---|
| `--config auto` | All registry rules (default) |
| `--config p/owasp-top-ten` | OWASP Top 10 rules |
| `--config p/cwe-top-25` | CWE Top 25 rules |
| `--config p/r2c-security-audit` | R2C security audit rules |
| `--config p/javascript` | JavaScript-specific rules |
| `--config p/python` | Python-specific rules |
| `--config p/java` | Java-specific rules |
| `--config p/go` | Go-specific rules |
| `--config p/typescript` | TypeScript-specific rules |

## Quick Scan

For a fast check without full config:
```bash
semgrep scan --config auto --severity CRITICAL .
```
