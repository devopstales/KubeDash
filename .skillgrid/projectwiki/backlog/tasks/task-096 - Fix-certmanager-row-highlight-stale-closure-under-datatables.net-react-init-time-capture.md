---
id: TASK-096
title: >-
  Fix certmanager row-highlight: stale closure under datatables.net-react
  init-time capture
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 20:46'
labels: []
dependencies: []
priority: medium
ordinal: 92000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The CertManager row-highlight feature (goToIssuerTab, frontend/src/views/Network/CertManager.tsx:111-114, 287-289) does not work in the real app: datatables.net-react binds column render callbacks at init and re-draws only on data changes, so the Issuer-tab name cell render fn closes over the STALE highlight state (null) and never bolds. Surfaced 2026-11-07 by change D T05's faithful shared KubeDataTable test fake (init-time capture mirrors the real component; unmocked probe confirmed the real component's behaviour). tests/views/certmanager.test.tsx list-issuer-tab-switch now documents the quirk and omits the fw-bold assertion pending this fix. Fix direction (controller's choice, either works): make the highlight data-driven (join a highlighted flag into the row data so the redraw picks it up via the 3rd render-fn arg) or key the KubeDataTable on highlight to force re-init (re-init tradeoff: DT state reset). After the fix, re-assert fw-bold in list-issuer-tab-switch under the shared fake. Consider e2e coverage for the CR Issuer cell -> tab switch -> bold flow (no e2e covers it today).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 list-issuer-tab-switch re-asserts fw-bold on the target Issuer row and passes under the shared faithful fake
- [ ] #2 full frontend suite green; task fe-build + task fe-check green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
