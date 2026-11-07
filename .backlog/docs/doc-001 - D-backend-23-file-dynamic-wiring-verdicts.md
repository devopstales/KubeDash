---
id: doc-001
title: D backend 23-file dynamic-wiring verdicts
type: other
created_date: '2026-11-07 19:56'
updated_date: '2026-11-07 20:04'
---
# D backend 23-file dynamic-wiring verdicts

- **Ticket:** TICKET-06 (TASK-094) — Dead-Code Cleanup (Change D), 2026-11-07.
- **Verdict scope:** the 23 `backend/` `unused-file` findings from the 2026-11-07 jscpd dead-code run (`report/basta-report.json`), module paths verbatim confirmed by blueprint Task 6.
- **Verdict classes:** `live-dynamic` · `stub-by-design` · `string-pinned`.
- **Posture:** verification ONLY (R4). No backend source file is deleted or modified in this change.

## Per-file verdicts

| # | Backend file | Verdict | Dynamic-wiring evidence | String-pin (`tests/test_file_map.py` `EXPECTED`) | Proposed deletion |
|---|---|---|---|---|---|
| 1 | `backend/app/aggregated/project.py` | stub-by-design | Never imported anywhere; raises `NotImplementedError_` from `app.core.errors` | yes | no |
| 2 | `backend/app/aggregated/sso_group.py` | stub-by-design | Never imported anywhere; raises `NotImplementedError_` | yes | no |
| 3 | `backend/app/aggregated/sso_user.py` | stub-by-design | Never imported anywhere; raises `NotImplementedError_` | yes | no |
| 4 | `backend/app/models/access_request.py` | stub-by-design | Deliberately NOT imported in `app/models/__init__.py` (`STUB = True`); owning change adds import + migration | yes | no |
| 5 | `backend/app/models/namespace_request.py` | stub-by-design | Deliberately NOT imported in `app/models/__init__.py` (`STUB = True`); owning change adds import + migration | yes | no |
| 6 | `backend/app/models/scim_map.py` | stub-by-design | Deliberately NOT imported in `app/models/__init__.py` (`STUB = True`); owning change adds import + migration | yes | no |
| 7 | `backend/app/schemas/kubectl_auth.py` | stub-by-design | Frozen wire shape for the in-flight kubectl-oidc-plugin change; resolution logic lands with that change; API route returns 501 | yes | no |
| 8 | `backend/app/services/access.py` | stub-by-design | Raises `NotImplementedError_`; PAM change lands | yes | no |
| 9 | `backend/app/services/grafana.py` | stub-by-design | Raises `NotImplementedError_`; observability change lands | yes | no |
| 10 | `backend/app/services/loki.py` | stub-by-design | Raises `NotImplementedError_`; observability change lands | yes | no |
| 11 | `backend/app/services/namespace.py` | stub-by-design | Raises `NotImplementedError_`; NaaS change lands | yes | no |
| 12 | `backend/app/services/prometheus.py` | stub-by-design | Raises `NotImplementedError_`; observability change lands | yes | no |
| 13 | `backend/app/services/provisioning.py` | stub-by-design | Raises `NotImplementedError_`; JIT provisioning change lands | yes | no |
| 14 | `backend/app/services/scim.py` | stub-by-design | Raises `NotImplementedError_`; SCIM change lands | yes | no |
| 15 | `backend/app/services/tempo.py` | stub-by-design | Raises `NotImplementedError_`; observability change lands | yes | no |
| 16 | `backend/app/sockets/events.py` | stub-by-design | `SocketIO(` never instantiated in `backend/` (grep hit: none); docstring: handlers wired by the events/timeline change | yes | no |
| 17 | `backend/app/sockets/logs.py` | stub-by-design | `SocketIO(` never instantiated in `backend/` (grep hit: none); docstring: handlers wired by the observability change | yes | no |
| 18 | `backend/app/tasks/access_expiry.py` | stub-by-design | Not in `wsgi.INTERVALS`; RQ-callable no-op that logs; PAM change lands | yes | no |
| 19 | `backend/app/tasks/alerts.py` | stub-by-design | Not in `wsgi.INTERVALS`; RQ-callable no-op that logs; observability change lands | yes | no |
| 20 | `backend/app/tasks/cluster_sync.py` | live-dynamic | `wsgi.py:72` `INTERVALS["app.tasks.cluster_sync.run"] = 300`; `wsgi.py:194` enqueue loop; `wsgi.py:179` spawn string → RQ worker queue `kubedash`; imports live code (`app.models.cluster.Cluster`, `app.services.k8s_client.pool`) | yes | no |
| 21 | `backend/app/tasks/health.py` | live-dynamic | `wsgi.py:71` `INTERVALS["app.tasks.health.run"] = 60`; `wsgi.py:194` enqueue loop; `wsgi.py:179` spawn string → RQ worker queue `kubedash`; imports live code (`app.models.cluster.Cluster`, `app.services.k8s_client.pool`) | yes | no |
| 22 | `backend/app/tasks/ns_request_expiry.py` | stub-by-design | Not in `wsgi.INTERVALS`; RQ-callable no-op that logs; NaaS change lands | yes | no |
| 23 | `backend/app/tasks/rbac_drift.py` | stub-by-design | Not in `wsgi.INTERVALS`; RQ-callable no-op that logs; permission-management change lands | yes | no |

## Verdict summary

- **live-dynamic (2):** `backend/app/tasks/health.py`, `backend/app/tasks/cluster_sync.py` — the only two of the 23 that import live code. Wired by the wsgi leader-gated scheduler (`INTERVALS` + enqueue loop at `backend/wsgi.py:70-73` / `backend/wsgi.py:194`) and the spawn string at `backend/wsgi.py:179` (`import wsgi; wsgi._rq_worker_main()` → RQ worker queue `kubedash`). Driven by `backend/tests/tasks/test_health.py` and the scheduler-gate tests in `backend/tests/test_worker_gate.py`.
- **stub-by-design (21):** the remaining 21 — no production import (module-path grep over `backend/`), no `INTERVALS` entry, no `SocketIO(` registration, no `app/models/__init__.py` import, no service call; the owning change (PAM / NaaS / SCIM / observability / aggregated-API / exec) lands each.

## String-pin + proposed-deletion note

All 23 files are string-pinned: `backend/tests/test_file_map.py` `EXPECTED` lists all 23 module paths verbatim and `test_path_exists` asserts each exists on disk. No finding is un-pinned, so no proposed-deletion flag is open on the strength of this verification alone.

Any future proposed deletion of a stub-by-design file must name the `backend/tests/test_file_map.py` `EXPECTED` update AND the `.skillgrid/ARCHITECTURE.md` §2 update it implies.

## Acceptance mapping (TICKET-06 / TASK-094)

- Backlog note carries a verdict for all 23 files with the `test_file_map.py` string-pin recorded; any proposed-deletion flag names the `test_file_map.py` + `ARCHITECTURE.md` §2 updates it implies; no source file modified.
- `SATISFIES:` `backend-files-verified`
- `Fails-when:` the note lacks a verdict for any of the 23 files, or a backend source file is deleted.
