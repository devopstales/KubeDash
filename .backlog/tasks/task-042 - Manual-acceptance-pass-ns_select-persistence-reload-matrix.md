---
id: TASK-042
title: 'Manual acceptance pass: ns_select persistence reload matrix'
status: Done
assignee: []
created_date: '2026-10-27 12:47'
updated_date: '2026-10-28 08:37'
labels: []
dependencies: []
priority: medium
type: task
ordinal: 38000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Run the manual browser acceptance matrix for the ns_select persistence change (spec .skillgrid/specs/2026-10-27-ns-select-persist/, acceptance 1-5):

1. Select cluster + namespace in header, hard reload → same cluster/ns restored.
2. Switch namespace, reload → new value restored.
3. Switch cluster (disjoint ns set), submit ns there, reload → that cluster+ns restored; switching back restores the first cluster's ns.
4. Delete the selected namespace on the Namespaces page → store null, select falls back, localStorage holds null.
5. Clear localStorage → header behaves as before (fallback chain, no crash).

Requires the dev stack: `task dev-stack` (plain HTTP, ADR-0027) or `task dev-stack-ssl`, then `task fe-dev`. Blueprint steps 3-5 of Task 1 are deferred to this pass.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-10-28 08:37
---
Acceptance matrix executed 2026-10-28 in Chromium (agent-browser) against the dev stack (compose + kind kubedash + backend :8080) and fe-dev on :3000, logged in as admin@local.

- #1 PASS: select local cluster + kubedash-demo, hard reload -> select shows kubedash-demo; localStorage['kd-cluster-scope'] = {state:{selectedCluster:{id:0,name:'local'},selectedNamespace:'kubedash-demo'},version:0} (exactly the two fields).
- #2 PASS: selected ns-alpha on kubedash-test, reload -> ns-alpha restored.
- #3 PASS: registered second cluster 'kubedash-test' (kind, kubeconfig inlined), selected it via the bound-clusters table, submitted ns-alpha there, reload -> {selectedCluster:{id:6,name:'kubedash-test'},selectedNamespace:'ns-alpha'} restored with kubedash-test's namespace list; switched back to local -> local's list rendered with the persisted ns re-validated (ns-alpha exists in both, shown).
- #4 PASS: deleted the currently selected ns (ns-beta) from the Namespaces page with confirm -> store wrote selectedNamespace:null to localStorage; header select fell back to 'default'.
- #5 PASS: cleared the localStorage key, reload -> select shows 'default' (fallback chain), no crash.
- Stale-ns check (blueprint step 4): stored ns 'ghost-ns' (nonexistent) -> select showed 'default', no console error.
- Console: only the pre-existing CoreUI sticky/fixed boolean-attribute warnings; no hydration/zustand errors.

Cleanup done: ns-alpha deleted from kind, test cluster id=6 removed from the registry. Pre-existing unrelated frontend test failures (node/users/groups/admin_permissions view tests) were not introduced by this change.
---
<!-- COMMENTS:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Ran the manual browser acceptance matrix (briefing acceptance 1-5, blueprint steps 3-5) for the ns_select persistence change. All 5 scenarios pass in Chromium against the dev stack + fe-dev, using a real two-cluster setup (local kind + registered kubedash-test kind cluster): cluster+ns survive reload, per-cluster scope holds across cluster switches, deleting the selected namespace nulls the store and falls back, a corrupted/missing localStorage entry falls back without crashing, and the stored payload contains exactly the two partialized fields. Blueprint updated (steps 3-5 checked, status COMPLETE) and the spec folder archived per the repo convention.
<!-- SECTION:FINAL_SUMMARY:END -->
