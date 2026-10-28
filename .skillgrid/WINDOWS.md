# Windows — cross-change defect register

Open WARNING / SUGGESTION findings that were not fixed before the QA gate. Each window
survives the archive move (project-level, not per-change). `qa-auto` = appended by the QA
gate without a human decision; a named human = explicitly accepted.

| ID | Change | Severity | Finding | Owner | Opened | Status |
|----|--------|----------|---------|-------|--------|--------|
| W001 | 2026-10-19-user-management | WARNING | `tests/test_health.py::test_readyz_names_failing_database` fails — test-infra defect (`monkeypatch.setattr(db, "engine", ...)` on a property with no setter); pre-existing at baseline a1f8298e, unrelated to user-management | qa-auto | 2026-10-20 | open |
| W002 | 2026-10-19-user-management | WARNING | 4 pre-existing red integration tests (`test_clusters_admin`, `test_worker_gate`, `test_resources` x2) — kind-env / fixture-scope (`ScopeMismatch: function-scoped fixture app with a session-scoped request`); files untouched by user-management | qa-auto | 2026-10-20 | open |
| W003 | 2026-10-19-user-management | WARNING | `tests/views/Cluster.test.tsx` vitest flake — cross-file mock pollution, fails with the user-management change stashed | qa-auto | 2026-10-20 | open |
| W004 | 2026-10-19-user-management | WARNING | Task 7 admin view — 6 minor findings (audit-query swallows non-501 errors; unbind handler ignores r.error; AdminRoute blank-while-me-inflight; namespace hidden-not-disabled; type named AdminUser not User; dead `.c-tabs` selector) | qa-auto | 2026-10-20 | open |
| W005 | 2026-10-19-user-management | SUGGESTION | Kubeconfig context-name collision — a user bound to the same cluster in two namespaces gets two same-named `kubedash-<cluster>` contexts; a follow-up should make context names unique per binding | qa-auto | 2026-10-20 | open |
| W006 | 2026-10-27-priority-class | WARNING | Rollback unit split: the list route's App.tsx hunk landed in fcc40567 (concurrent network-policy Task 4 committed the shared working tree during Task 2's window); Task 2's clean rollback is fcc40567..1bd5afab + one hunk — ship/archive both changes together (no route gap at any boundary) | qa-auto | 2026-10-28 | open |
| W007 | 2026-10-27-priority-class | WARNING | 13 pre-existing frontend test failures (users 7, groups 4, node 1, admin_permissions 1) at the QA run — owned by the in-flight users/groups/node pages + network-policy close-out, not this change; the set shrank 17→13 during the run | qa-auto | 2026-10-28 | open |
