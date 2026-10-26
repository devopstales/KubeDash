# Network Policies — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-26-network-policy`
**Date:** 2026-10-26

**Tier:** T2 — multi-file backend + frontend change; touches the cluster
resource-read contract (SAR gating) but adds no new trust boundary, no
migration, no new dependency.

## Intent

Replace the `/security/network-policy` stub (ADR-0022 parity row, `stub`
column) with the 4.1 feature: a **Network Policies** list page under Security
that shows every network policy in the header-selected namespace — vanilla
Kubernetes `NetworkPolicy` **and** Cilium policies — plus a **detail page**
for a single policy. 4.1 is the behavioral reference (what to show); the
current architecture (R4 resource table, `K8sClientPool` seam, SAR gating)
is the structural authority (how to get the data).

Two deliberate deltas from 4.1 (ratified in planning, 2026-10-26):

1. **SAR gating.** 4.1's only gate was the app-level role. This build gates
   on a SubjectAccessReview BEFORE the read (ADR-0004) — a user without
   `list networkpolicies` on `networking.k8s.io` gets 403, not an empty list.
2. **Cilium via the R4 table with auto-detected served version.** 4.1
   hardcoded `cilium.io/v2` in three fetch functions; a cluster on
   `v2alpha1` (or a newer version) silently shows no Cilium policies. This
   build resolves the CRD's served version from the CRD itself, so any
   Cilium version works, and Cilium absence (CRD 404) degrades to an empty
   section — never an error (certainty rule: absence of a feature is not an
   error, but a read KubeDash cannot make renders *unknown*, never `0` or
   empty-by-misfortune).

## Reference

4.1 branch (pre-rewrite, session + Jinja):

- `4.1:src/kubedash/blueprint/api/security.py` — `GET /api/v1/security/network-policies[?namespace]`
  and `…/network-policies/<name>[?namespace&kind]`. The detail endpoint is
  list-then-filter in Python (one list call, loop for the name).
- `4.1:src/kubedash/lib/k8s/security.py` — `k8sPolicyListGet` merges three
  sources: `NetworkingV1Api.list_namespaced_network_policy` + `cilium.io/v2`
  `ciliumnetworkpolicies` (namespaced CRD) + `ciliumclusterwidenetworkpolicies`
  (cluster-scoped CRD, appended to every namespace view). Each item carries
  `pod_selector`, `policy_types`, `ingress_rules`, `egress_rules`,
  `annotations`, `labels`, `created`.
- `4.1:src/kubedash/blueprint/security/security.py` +
  `templates/security/network-policy[-data].html.j2` — the two pages: list
  (name links to detail) and detail (metadata + rules, with a `kind` param
  disambiguating `NetworkPolicy` / `CiliumNetworkPolicy` /
  `CiliumClusterwideNetworkPolicy`).

Deliberately NOT carried over from 4.1:

- the `"imgress_rules"` typo (kept in 4.1 "for backward compat" — the React
  SPA has no legacy consumers);
- the per-namespace session state (`session['ns_select']`) — the namespace
  comes from the header selector via the Zustand cluster store, as every
  other current view does (see `frontend/src/views/Security/Secret.tsx`);
- `@cache.memoize` on the read — ADR-0010's informer cache interposes at the
  pool seam later; per-function memoization keyed on user_token is 4.1's
  shape, not this codebase's.

## Requirements

### R1 — NetworkPolicy list (vanilla K8s)

`GET /api/v1/clusters/<id>/resources/networkpolicies?namespace=` returns the
namespace's `NetworkPolicy` objects in the standard kubernetes `to_dict`
shape, through the R4 resource table:

- Binding gate: 404 `CLUSTER_NOT_FOUND` (unbound user or unknown cluster id).
- SAR gate BEFORE the read: `list` on `networkpolicies` / `networking.k8s.io`
  → 403 `RBAC_DENIED` naming the denied resource (ADR-0004; the cache key
  carries namespace, per the 2026-10-21 addendum).
- `?name=` lookup: SAR `get` on that object; items holds zero or one entry
  (`[]` when the policy does not exist — the `get_secret` contract).
- No namespace → all namespaces (the kind is namespaced; cluster-wide list).

### R2 — Cilium policies

`GET /api/v1/clusters/<id>/resources/ciliumnetworkpolicies?namespace=` and
`…/resources/ciliumclusterwidenetworkpolicies` return the full CRD items
(`to_dict`, `spec` intact — the condition-projection of
`list_crd_instances` is NOT this path), group `cilium.io`, with:

- **Served-version autodetection:** the CRD's own `spec.versions[].served`
  is the authority (reuse the `_crd_served` logic). No hardcoded version.
- **CRD absent → `[]`** (a 404/404-group CRD read is the *expected* state
  when Cilium is not installed — the UI hides the section, mirroring how
  metrics-absence degrades). Any other API failure → 502
  `CLUSTER_UNREACHABLE`.
- SAR gates: `list`/`get` on `ciliumnetworkpolicies` and
  `ciliumclusterwidenetworkpolicies` in group `cilium.io` — the resource the
  user must actually be able to read (4.1 had no per-resource gate here).
- `?name=` on the namespaced kind only (clusterwide is list-only).

### R3 — List view

`/security/network-policy` renders a `KubeDataTable` of the selected
namespace's policies: columns **Name** (link to detail), **Policy Types**
(`spec.policy_types`, the `to_dict` form), **Ingress rules**,
**Egress rules**, **Created** (the timestamp rendered in the browser's
local time — user decision 2026-10-26, not a UTC/ISO string).

- A **Cilium section** (separate table, distinct headers) lists
  `ciliumnetworkpolicies` for the namespace and `ciliumclusterwidenetworkpolicies`
  (4.1 appends clusterwide policies to every namespace view — parity kept).
  The section is **hidden when both lists are empty** (Cilium not installed,
  or no policies — indistinguishable and equivalent for the user).
- No cluster selected → "No cluster selected." (the `Secret.tsx` pattern).
- Errors surface as the standard error line (query.error.message), never a
  blank page.

### R4 — Detail view

`/security/network-policy/data?name=&kind=` shows one policy. `kind` is a
closed enum: `NetworkPolicy` | `CiliumNetworkPolicy` |
`CiliumClusterwideNetworkPolicy`; anything else → 400-style client error
before any fetch.

- Data via the matching `?name=` endpoint (single K8s read — NOT 4.1's
  list-then-filter).
- Content: metadata block (name, namespace, created, labels, annotations) +
  the full object rendered as syntax-highlighted YAML (reuse the
  `SecretData.tsx` highlighter wiring).
- `items` empty (404 upstream) → "not found" state, not an error.

### R5 — Stub removal

`/security/network-policy` leaves `views/Stub/routes.ts`; the e2e smoke path
(`frontend/e2e/ui-smoke.spec.ts:45`) keeps working against the real view.

## Success criteria

- A cluster with vanilla NetworkPolicies and no Cilium: list shows only the
  vanilla section.
- A cluster with Cilium (any served version): the Cilium section appears
  with real rules.
- A user denied `list networkpolicies` by SAR: 403 with the resource named;
  no policy data in the response.
- The detail page shows the exact object the list row links to, for all
  three kinds.
