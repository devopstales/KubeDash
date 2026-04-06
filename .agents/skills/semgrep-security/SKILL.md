---
name: semgrep-security
description: Semgrep static analysis for security vulnerabilities, code quality, and custom rules. Run scans, interpret results, and suggest fixes.
---

# Semgrep Security Skill

## When to Activate

- After writing new code that handles user input, auth, or sensitive data
- Before committing or merging feature branches
- Reviewing dependencies for known vulnerabilities
- Setting up CI/CD security gates
- Auditing legacy code for security debt

## Core Capabilities

### 1. Vulnerability Detection

Scan for common security issues:
- SQL injection
- XSS (Cross-site scripting)
- SSRF (Server-side request forgery)
- Path traversal
- Hardcoded secrets and API keys
- Insecure cryptography
- Command injection
- Deserialization vulnerabilities

### 2. Code Quality Rules

- Error handling gaps
- Resource leaks
- Race conditions
- Dead code
- Performance anti-patterns

### 3. Custom Rules

Write project-specific rules in YAML:

```yaml
rules:
  - id: no-hardcoded-api-key
    pattern: $KEY = "sk-..."
    message: "Hardcoded API key detected"
    severity: ERROR
    languages: [python, javascript, typescript]
```

## Scan Workflow

### Quick Scan
```bash
semgrep scan --config auto --severity CRITICAL .
```

### Full Scan
```bash
semgrep scan \
  --config auto \
  --severity CRITICAL \
  --severity HIGH \
  --max-target-bytes 10M \
  --timeout 30 \
  --jobs 4 \
  --output semgrep-report.json \
  --json \
  .
```

### Custom Rules
```bash
semgrep scan --config .semgrep/rules/ .
```

## Interpreting Results

### Severity Levels

| Level | Action |
|---|---|
| ERROR/CRITICAL | Must fix before merge |
| WARNING/HIGH | Should fix before merge |
| INFO/MEDIUM | Fix recommended |
| LOW | Optional improvement |

### False Positives

Suppress with comments:
```python
# semgrep: disable-next-line
api_key = "test-key-only"  # OK: test fixture
```

Or in config:
```yaml
# .semgrepignore
tests/**/*.py
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Semgrep Scan
  run: |
    semgrep ci --config auto --severity CRITICAL --severity HIGH
```

## Common Configs

| Config | Purpose |
|---|---|
| `--config auto` | All registry rules |
| `--config p/owasp-top-ten` | OWASP Top 10 |
| `--config p/cwe-top-25` | CWE Top 25 |
| `--config p/r2c-security-audit` | Security audit |
| `--config p/<lang>` | Language-specific |

## Best Practices

1. **Scan early** — run on every commit during development
2. **Focus on CRITICAL/HIGH** — don't drown in noise
3. **Write custom rules** — catch project-specific patterns
4. **Suppress intentionally** — document why a finding is safe
5. **Integrate into CI** — block merges on critical findings
