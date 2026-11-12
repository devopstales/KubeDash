---
type: Reference
title: "Technical terms — machinery vocabulary"
status: stable
---

# Technical terms

Machinery vocabulary, reverse-engineered from the code (onboarding,
2026-11-12). One definition per term; keep under ~200 lines or split.

- **pgqueue** — the Postgres task queue: a `tasks` table claimed with
  `SELECT ... FOR UPDATE SKIP LOCKED`, plus a reaper that re-queues stale
  claims (120 s stale window) and expires jtis/kv rows (ADR-0029).
  `backend/app/core/pgqueue.py`, `backend/app/models/task.py`.
- **Leader gate** — enqueue/scheduling only while this replica leads: PG
  advisory lock + a `leader_lease` row carrying a strict fencing token
  (ADR-0031 supersedes ADR-0008). `backend/app/core/leader.py`.
- **Worker thread** — the in-process pgqueue poll loop in the Gunicorn master:
  schedule (leader-gated) + claim + run + reap on a 5 s cadence
  (`backend/wsgi.py`, `_worker_loop`). Since ADR-0029 there is no RQ child
  process.
- **SAR gate** — `rbac.can(user, cluster, verb, resource, namespace, name)`
  asks the target cluster via SelfSubjectAccessReview; deny → 403
  `RBAC_DENIED`. Verdicts cached in the Postgres `kv` table (moved off Redis
  by ADR-0030). `backend/app/services/rbac.py`.
- **K8sClientPool** — per-cluster cached K8s clients keyed by `Cluster.id`;
  kubeconfig decrypted with AES-256-GCM under `KUBEDASH_SECRET_KEY`. The
  documented seam where the ADR-0010 informer cache will interpose.
  `backend/app/services/k8s_client.py`.
- **Object handoff** — ADR-0040: no object identity in the URL; a tab-private
  `sessionStorage` object ref + same-origin form-POST deep link.
  `backend/app/core/object_handoff.py`.
- **Kind catalog** — ADR-0041: resource kinds declared in a typed catalog
  (backend kind catalog + frontend views); one route per kind, no `/data`
  suffix.
- **Error envelope** — the stable machine-readable error code envelope
  (`CLUSTER_NOT_FOUND`, `RBAC_DENIED`, `NOT_IMPLEMENTED`, …); the exception
  repr never leaks. `backend/app/core/errors.py`.
- **First-paint backstop** — the `first_paint_backstop` config timeout (dev:
  5 m) bounding the initial render path.
- **Config chain** — `kubedash.ini` → `KUBEDASH_*` env override → fail-fast
  `ConfigError` at boot; no hard-coded identity/credential defaults
  (ADR-0028). `backend/app/core/ini_config.py`.

## Related

- [[glossary/01-business-terms]] — the product vocabulary
- [[decisions/04-adr-0029-queue-on-postgres]] — the pgqueue design record
