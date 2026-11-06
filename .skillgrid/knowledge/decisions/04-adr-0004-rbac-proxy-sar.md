# RBAC proxy via SubjectAccessReview (not local role mapping)

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
amended: 2026-10-21
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

Every request that touches a cluster's resources needs an answer to
"may *this user* do *this verb* on *this resource* in *this
namespace*?" KubeDash 4.1 mapped local roles to K8s roles. With N
clusters of arbitrary RBAC shape, a local mapping either lies or lags.
The question: does KubeDash maintain its own role→permission mapping, or
ask the cluster?

#### Decision Drivers

- **The cluster is the source of truth** for RBAC; a local mapping
  duplicates it and drifts the moment an admin edits a Role.
- **Fail-closed.** An unverifiable answer must deny (403
  `RBAC_DENIED`), never allow.
- **Cheap enough for the hot path.** Per-request SAR calls are
  acceptable only with a short verdict cache.
- **UI must hide what it can't do.** Buttons (Delete, Scale, …) are
  hidden when the user lacks the verb.

#### Considered Options

- **Local role mapping** (KubeDash role ↔ K8s verbs table). Rejected:
  drift, and it can't express cluster-specific RBAC (custom roles,
  aggregated ClusterRoles).
- **SubjectAccessReview proxy (CHOSEN).** Every mutating (and gated
  read) request runs `rbac.can(user, verb, resource, name, namespace)`
  via a SAR issued with the registry's credentials on the target
  cluster; the verdict is cached briefly in Redis.

#### Decision Outcome

**Chosen option: SAR proxy with a TTL'd verdict cache.**

- `backend/app/services/rbac.py` — `can(...)` builds a
  `SubjectAccessReview` against the cluster; verdicts cached in Redis for
  `SAR_TTL` seconds.
- Denial returns 403 with the stable code `RBAC_DENIED` (the error-shape
  contract, ARCHITECTURE.md §10).
- The UI calls `/auth/me/permissions` on mount and hides verbs the user
  lacks — display only; the API re-checks per request.

##### Consequences

- Good: no drift; arbitrary cluster RBAC is honored as-is; fail-closed.
- Bad: a SAR round-trip per uncached verdict (mitigated by the TTL cache).
- Confirmation: `backend/tests/services/test_rbac.py`; the `RBAC_DENIED`
  assertions across `backend/tests/api/`.

#### Amendments

- **2026-10-21 — verdict cache key carries every SAR attribute.** The
  key is
  `sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>`
  (empty segment = unset, `backend/app/services/rbac.py:36`). The API
  lists with the registry's credentials, so the SAR is the only gate —
  a verdict for one namespace or object must never answer for another.

#### Linking Decisions and Constraints

- ADR-0002 — SARs are issued with the registry cluster's credentials.
- ADR-0013 — bindings grant access to the cluster; the SAR grants the
  verb on the object.
- ADR-0040 — a session object ref is a pointer, not a privilege; the
  object read stays SAR-gated.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §3.5; the 2026-10-21
addendum is recorded from the `ASSUMPTIONS.md` § LOCKED row; the cache-key
literal was verified in `backend/app/services/rbac.py` on 2026-11-06.
