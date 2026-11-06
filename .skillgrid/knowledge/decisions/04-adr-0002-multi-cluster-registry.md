# Multi-cluster via encrypted kubeconfig registry (one-way-door)

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash 4.1 managed a single static cluster (`[k8s]` section of
`kubedash.ini`). 5.0 targets many clusters per installation. The
question: how are clusters represented, and how are their credentials
stored?

#### Decision Drivers

- **Clusters are first-class entities**, not config: users are bound to
  clusters, the UI switches between them, health is tracked per cluster.
- **Credentials at rest.** Each cluster is reached with its kubeconfig;
  kubeconfigs contain secrets. They must be encrypted in the database.
- **One-way-door.** The registry schema is the backbone of multi-tenancy;
  changing it means migrating every stored credential. It is
  ADR-gated + migration-gated, and `KUBEDASH_SECRET_KEY` (the
  kubeconfig-encryption key) is a one-way-door key distinct from the JWT
  signing key.
- **4.1 INI continuity** is preserved without forcing a single cluster:
  the 4.1 `[k8s]` section is retired, not ported (ADR-0028) — the admin
  cluster comes from the admin kubeconfig, member clusters from the
  registry.

#### Considered Options

- **Static single-cluster config (4.1).** Rejected: no multi-tenancy, no
  per-user cluster bindings, no health tracking.
- **Per-user kubeconfig uploads.** Rejected: credentials would be
  per-user rows with no shared cluster identity for health/binding.
- **Registry table + encrypted kubeconfig (CHOSEN).** One `clusters` row
  per cluster: name, endpoint, **AES-256-GCM encrypted kubeconfig**,
  context, health status. Users see only clusters they are bound to
  (`cluster_bindings`). Each cluster owns an independent client in the
  pool; cross-cluster operations fan out concurrently with per-cluster
  timeouts and partial-result semantics.

#### Decision Outcome

**Chosen option: cluster registry with AES-256-GCM encrypted
kubeconfigs.**

- `clusters` table (SQLAlchemy 2.0 model `backend/app/models/cluster.py`);
  kubeconfig ciphertext keyed by `KUBEDASH_SECRET_KEY` (AES-256-GCM;
  `backend/tests/test_encryption.py` pins the cipher).
- `cluster_bindings` rows grant users access (user × cluster ×
  namespace × template — ADR-0013).
- Schema changes require an Alembic migration and pass the ADR gate
  (one-way-door).
- The encryption key and the JWT key are distinct operator values;
  neither has an in-code default (ADR-0028 fail-fast).

##### Consequences

- Good: clean multi-tenancy; credentials encrypted at rest; per-cluster
  health and bindings; cross-cluster fan-out with partial results.
- Bad: rotating `KUBEDASH_SECRET_KEY` requires re-encrypting every stored
  kubeconfig (one-way-door cost, accepted).
- Confirmation: `backend/tests/test_encryption.py`,
  `backend/tests/api/test_clusters.py`, `test_clusters_admin.py`.

#### Linking Decisions and Constraints

- ADR-0004 — per-cluster RBAC is enforced with the registry's
  credentials.
- ADR-0010 — the read path is per-cluster (informer cache target).
- ADR-0013 — bindings are the unit of access on the registry.
- ADR-0028 — the 4.1 `[k8s]` section is retired; the registry is the
  multi-cluster surface.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §5; verified against
`backend/app/models/cluster.py` and `backend/tests/test_encryption.py`
on 2026-11-06.
