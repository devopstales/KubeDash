# KubeDash — Knowledge Reverse Index

> Path → concept map: which code paths are pinned by which concept. Concepts
> without anchors (reports, retrospectives) do not appear here — they load,
> they just don't arm the pin check.

| Concept | Anchored paths |
|---|---|
| [invariants/session-cookie-transport.md](invariants/session-cookie-transport.md) | `backend/app/core/security.py`, `backend/tests/api/test_auth.py` |
| [invariants/leader-only-rq-worker.md](invariants/leader-only-rq-worker.md) | `backend/wsgi.py`, `backend/app/core/leader.py`, `backend/tests/test_leader.py` |
| [invariants/config-fail-fast.md](invariants/config-fail-fast.md) | `backend/app/core/ini_config.py`, `backend/tests/test_ini_config.py` |
| [invariants/services-integration-boundary.md](invariants/services-integration-boundary.md) | `backend/app/services/__init__.py`, `backend/app/services/k8s_client.py` |
| [invariants/sar-verdict-cache-key.md](invariants/sar-verdict-cache-key.md) | `backend/app/services/rbac.py`, `backend/tests/services/test_rbac.py` |
| [invariants/air-gap-bundle.md](invariants/air-gap-bundle.md) | `tests/fe-airgap-check.mjs`, `backend/tests/test_fe_airgap_check.py`, `backend/tests/api/test_apidocs.py` |
| [invariants/object-nav-no-url-identity.md](invariants/object-nav-no-url-identity.md) | `frontend/src/lib/objectRef.ts`, `backend/app/core/object_handoff.py`, `frontend/tests/lib/objectRef.test.ts` |
| [invariants/security-header-layer.md](invariants/security-header-layer.md) | `backend/app/core/security_headers.py`, `backend/tests/test_security_headers.py` |
| [invariants/object-view-annotation-trim.md](invariants/object-view-annotation-trim.md) | `frontend/src/views/Storage/PvData.tsx`, `frontend/src/views/Network/IngressData.tsx`, `frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx` |
| [gotchas/datatables-react-stale-render-closure.md](gotchas/datatables-react-stale-render-closure.md) | `frontend/src/views/Storage/Pv.tsx`, `frontend/src/components/KubeDataTable.tsx` |
| [gotchas/kube-pvc-bounded-phase-not-condition.md](gotchas/kube-pvc-bounded-phase-not-condition.md) | `dev/scripts/demo-data.sh` |
| [workflows/oidc-login-session.md](workflows/oidc-login-session.md) | `backend/app/api/auth.py`, `backend/app/core/security.py`, `frontend/src/lib/api.ts` |
| [workflows/object-deep-link.md](workflows/object-deep-link.md) | `frontend/src/lib/objectRef.ts`, `backend/app/core/object_handoff.py`, `frontend/src/components/ObjectRoute.tsx` |
| [workflows/leader-task-execution.md](workflows/leader-task-execution.md) | `backend/wsgi.py`, `backend/app/core/leader.py`, `charts/kubedash/templates/deployment.yaml` |
| [workflows/frontend-build-serve.md](workflows/frontend-build-serve.md) | `Taskfile.yaml`, `backend/Dockerfile`, `tests/fe-airgap-check.mjs` |
| [reference/live-architecture.md](reference/live-architecture.md) | `.skillgrid/ARCHITECTURE.md` |
| [reference/feature-roadmap.md](reference/feature-roadmap.md) | `.skillgrid/ARCHITECTURE.md` |

Unpinned concepts (no anchors): all of `decisions/` (ADRs are the why;
their validation sections name the tests) and `glossary/` (vocabulary).
