---
id: decision-012
title: "ADR-0012 Aggregated API server for Project + SSOUser + SSOGroup"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0012-aggregated-api.md`

# Aggregated API server for Project + SSOUser + SSOGroup

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

KubeDash computes things the cluster doesn't store: which namespaces a
user can read (RBAC-filtered), a user's effective permissions, a group's
effective permissions. Exposing those only as REST endpoints makes them
invisible to `kubectl`. The question: register KubeDash as a K8s
aggregated API server so these become real API objects?

#### Decision Drivers

- **kubectl-native.** `kubectl get projects` should list the namespaces
  the caller can read — no separate client.
- **Read-only, no data in etcd.** The objects are computed on the fly
  from the cluster's RBAC + KubeDash's bindings; nothing is persisted
  in the target cluster's etcd.
- **Trust boundary.** The aggregated API sits behind the API server's
  own auth (mTLS, API token), so KubeDash's own auth applies on top.

#### Considered Options

- **REST endpoints only** (`/api/v1/...`). Rejected: invisible to
  kubectl and to other API-server-native tooling.
- **CustomResourceDefinitions.** Rejected: CRDs store data in etcd and
  imply a write lifecycle the computed objects don't have.
- **kube-aggregator pattern (CHOSEN).** Register
  `APIService` objects; KubeDash serves two groups over mTLS on port
  8443.

#### Decision Outcome

**Chosen option: aggregated API server, two read-only groups.**

- `projects.kubedash.io/v1` — `Project`: a 1:1 read-only projection of
  a Namespace, **filtered by the requesting user's RBAC** (a user lists
  only what they can read).
- `auth.kubedash.io/v1` — `SSOUser` / `SSOGroup` (cluster-admin only):
  effective permissions computed on the fly from RBAC objects.
- Registration: `apiregistration.k8s.io/v1` `APIService` objects (chart
  templates); the service is mTLS on 8443.
- Backend: `backend/app/aggregated/` (`project.py`, `sso_user.py`,
  `sso_group.py`) + `backend/app/api/aggregated/` (the Smorest surface).

##### Consequences

- Good: kubectl-native read views; no etcd storage; the RBAC filter
  applies at the API-server trust boundary.
- Bad: one more service + mTLS pair to operate; aggregation adds a hop
  to those reads.
- Confirmation: `backend/app/aggregated/`, `backend/app/api/aggregated/`.

#### Linking Decisions and Constraints

- ADR-0002 — Project filtering rides the cluster registry's RBAC.
- ADR-0004 — SSOUser/SSOGroup are the read-only visibility surface of
  the SAR proxy (`effective_permissions`, `my_permissions`).

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §5A; verified against
`backend/app/aggregated/` on 2026-11-06.
