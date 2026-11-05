---
id: TASK-067
title: Implement task test-security (trivy) + task test-dast (authenticated wapiti)
status: Done
assignee: []
created_date: '2026-11-05 10:35'
labels:
  - security
  - testing
dependencies: []
references:
  - .skillgrid/specs/2026-10-17-test-observability-pipeline/blueprint.md
modified_files:
  - Taskfile.yaml
  - dev/testing/wapiti-login.py
  - scripts/collect-security.py
ordinal: 63000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Security test slice of spec 2026-10-17-test-observability-pipeline (T10/T11). test-security wraps scripts/collect-security.py (repo fs scan, or IMAGE=kubedash:ci) + Prometheus push, advisory locally. test-dast runs dev/testing/wapiti-login.py: bootstrap-admin login, preflight /auth/me 200, wapiti folder+swagger scan with kd_access cookie, findings summary, push, skipped when stack/wapiti missing. Remaining spec scope (push-gate helper, fixtures, test-all umbrella, other suites) still open.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Implemented + verified (commit 1c699722 on rebase). task test-security: 11 findings (2 critical, 4 high), exit 0 advisory. task test-dast: login+preflight+scan OK, 11 findings (CSP 4, cookie flags 7) + 2 500 anomalies (the known OIDC /auth/login Response.get bug). Skip paths verified (stack down, port probe). Push to :9091 best-effort (gateway not up in current dev stack -> reported, never fails). Artifact tmp/testing/security-wapiti.json. Gotchas encoded: wapiti 3.3.2 uses -x/--exclude URL (not --exclusion), 302 login cookies arrive via HTTPError headers when redirects are disabled, xxe module phones home to wapiti3.ovh.
<!-- SECTION:FINAL_SUMMARY:END -->
