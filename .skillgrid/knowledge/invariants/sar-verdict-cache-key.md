---
type: InvariantContract
title: "The SAR verdict cache key carries every SAR attribute"
description: "SubjectAccessReview verdicts are cached in Redis under sar:<cluster>:<sub>:<verb>:<resource>:<group>:<namespace>:<name> (empty segment = unset), TTL 30 s; a verdict for one namespace or object never answers for another. (ADR-0004, amended 2026-10-21.)"
tags: [rbac, sar, cache, adr-0004]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/services/rbac.py
      all_of: ["sar:{cluster_id}:{sub}:{verb}:{resource}:{group}:{namespace or ''}:{name or ''}", 'SAR_TTL = 30']
    - path: backend/tests/services/test_rbac.py
      all_of: ['sar:1:u-1:list:pods:::']
claims:
  - subject: cache key format
    literal: "sar:{cluster_id}:{sub}:{verb}:{resource}:{group}:{namespace or ''}:{name or ''}"
  - subject: verdict TTL
    literal: 'SAR_TTL = 30'
---

# SAR verdict cache key carries every SAR attribute

The API lists with the **registry's** credentials, so the
SubjectAccessReview is the only authorization gate between the UI and
cluster data. A cached verdict is therefore only valid for the exact SAR
it answered.

**The contract.**

- `rbac.can(user, cluster, verb, resource, group, namespace, name)`
  checks the Redis cache first; the key is
  `sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>`
  with an **empty segment for unset** namespace/name
  (`backend/app/services/rbac.py:36`).
- Verdicts are stored as `"1"`/`"0"` with `ex=SAR_TTL` (30 s,
  `rbac.py:24`).
- A verdict for one namespace or object must never answer for another —
  if any attribute drops out of the key, the invariant is broken.
- Denial surfaces as 403 with the stable code `RBAC_DENIED`
  (fail-closed: an unverifiable answer denies).

**Why.** The 2026-10-21 amendment to ADR-0004 exists because the
original key shape under-scoped: reads share the registry's credentials,
so the *subject* is effectively fixed per cluster — making
namespace/name the differentiators that must remain in the key.

**Pinned by.** `backend/tests/services/test_rbac.py` — asserts the exact
key written (e.g. `("sar:1:u-1:list:pods:::", "1")`) and per-namespace /
per-name separation of verdicts.

**Related.** ADR-0004 (decision + amendment), ADR-0002 (registry
credentials), `invariants/services-integration-boundary.md` (the module
lives in the Flask-free boundary).
