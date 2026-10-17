---
id: TASK-012
title: 'TICKET-11: Go CLI skeleton'
status: To Do
assignee: []
created_date: '2026-10-17 13:00'
labels: []
milestone: m-0
dependencies: []
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: low
type: feature
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: cli/ Go module (1.22), cobra root + version (real, ldflags-overridable) + get-token/clean/setup (exit-2 stubs pointing at the in-flight kubectl-oidc-plugin blueprint), Makefile (build + 5-target cross), .krew.yaml. Current: no cli/. Expected: go vet/test/build green; version prints; get-token exits 2 with the pointer.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 cd cli && go vet ./... && go test ./... && make build && ./kubedash version -> kubedash 0.1.0; ./kubedash get-token exits 2 with pointer message, no panic
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R7 acceptance met; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. cli/go.mod + main.go + cmd/root.go (cobra)
2. cmd/version.go (ldflags version) + get_token/clean/setup exit-2 stubs
3. Makefile (build + cross 5 targets) + .krew.yaml
4. cmd/version_test.go; go vet/test/build green; commit
<!-- SECTION:PLAN:END -->
