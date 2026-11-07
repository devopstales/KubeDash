# Resource kinds are declared in a typed catalog (backend kind catalog + frontend kind registry)

---
status: "accepted"
date: 2026-11-07
supersedes: none
---

**Decision-makers.** paladm (project owner)
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash reads ~41 resource kinds. Each kind is currently *coded*:
`K8sClient` carries ~80 per-kind `list_X`/`get_X` methods (each ~10
lines of try/except + namespace branching + `to_dict`), `ResourceApi`
dispatches through two string tables (`_KINDS`, `_GETTERS`) holding
method names, and the frontend re-codes every kind as a list View, a
data View, an import + route block in `App.tsx`, and a test pair.
Adding one kind touches 9–10 files across two languages; 8 of the last
10 commits were exactly that.

Three concrete frictions:

- The CRD-absent degrade rule (glossary: *CRD-absent degrade*) has no
  single home — it is restated in ~30 per-method docstrings, and the
  cluster-reachability mapping is scattered across `k8s_client.py`,
  `clusters.py`, `metrics.py`, and `permission.py`.
- The test doubles imitate the interface by copying method names.
  `FakeK8s` (1,145 lines) already drifted: it lacks
  `list_ingresses`/`get_ingress` and all eight Gateway API methods, and
  those kinds have **no API-tier tests at all**.
- ADR-0010's informer cache "interposes later" at the `K8sClientPool`
  seam — the interface that adapter would satisfy is the 88-method one.

#### Decision Drivers

- Adding a kind must be one registry row per language, not 9–10 files
- The CRD-absent degrade and reachability mapping need one home (locality)
- The interface the informer-cache adapter will face (ADR-0010) must be
  small
- Test doubles should be data, not interface copies
- Behavior stays unchanged: SAR gating (ADR-0004), object navigation
  (ADR-0040), e2e-asserted exact card titles, observed-tier degrade

#### Considered Options

- Typed kind catalog + generic read engine; per-kind methods only as
  named overrides (chosen)
- Keep the per-kind methods, add a `ResourceReader` protocol behind
  `ResourceApi`
- Facade: per-kind methods become thin delegates to the engine, deleted
  later
- Status quo; extract only the try/except helper

#### Decision Outcome

Chosen option: "typed kind catalog + generic read engine", because it
shrinks the interface every caller, every double, and the future
informer cache face, and gives the degrade rule one home.

**Backend.** A kind catalog registry (per kind: API plural, group,
version, scope, CRD flag, row projector) + one generic
`list(kind, ns)` / `get(kind, ns, name)` engine on `K8sClient`, at the
existing `K8sClientPool.factory` seam — no new protocol. `ResourceApi`
derives its dispatch from the registry; the `_KINDS`/`_GETTERS` string
tables are deleted. Per-kind methods survive only as named overrides
where behaviour genuinely differs (pods `labelSelector`, PV
claim-namespace filter, CRD-instance projection, metrics). One shared
`FakeK8s` + one fixture module (`tests/fixtures/k8s_data.py`) replace
the eight doubles; the drifted kinds' missing API-tier tests (ingress,
Gateway API) are recovered in the same change.

**Frontend.** A `src/lib/kinds.ts` registry (kind, plural, scope, route,
section, exact title, row spec) drives shared list-View and data-View
modules; `App.tsx` generates its resource route blocks — including the
paired legacy `/data` redirects — from the same rows. Kinds whose
rendering genuinely differs (Gateway API tabs, Ingress tabs, PV
claim-filter) keep hand-rolled Views and are flagged `custom` in the
registry.

The seam stays where it is today (`K8sClientPool.factory`): a typed
`ResourceReader` protocol is a hypothetical seam until the second
adapter (the informer cache, ADR-0010) arrives.

**Cutover** is kind-by-kind with no facade: each commit lands a batch of
catalog rows, deletes that batch's methods, converts the doubles' data
+ tests, and keeps the suite green.

##### Consequences

- Good, because adding a kind is one registry row + one fixture per
  language, not 9–10 files
- Good, because the CRD-absent degrade and reachability mapping
  concentrate in the engine; the ~30 docstring restatements are deleted
- Good, because `FakeK8s` can no longer drift silently — a catalog kind
  with no fixture data fails its own parametrized test
- Good, because the informer-cache adapter (ADR-0010) faces a handful of
  methods instead of ~88
- Bad, because generic dispatch adds one indirection: per-kind reads are
  no longer a grep for one method name away
- Bad, because the engine must encode the corner cases (CRD
  served-version resolution, 404→`[]`, cluster-scoped vs namespaced)
  that today are per-method explicit — they survive as named overrides,
  visible from the catalog row
- Neutral, because behaviour is unchanged: the SAR gate is still asked
  before the read (ADR-0004), identity still never enters the URL
  (ADR-0040), e2e exact titles survive as per-kind registry data

##### Confirmation

- `k8s_client.py` defines no per-kind `list_*`/`get_*` methods beyond
  the named overrides
- `resources.py` carries no `_KINDS`/`_GETTERS` string tables; dispatch
  derives from the catalog
- `uv run pytest -m "not integration"` green, with an API-tier test for
  every catalog kind (incl. ingresses + Gateway API kinds)
- `frontend/src/lib/kinds.ts` is the single source of per-kind
  route/title/row data; `App.tsx` renders resource routes from it
- `corepack pnpm test` green; e2e exact-title assertions unchanged

#### Pros and Cons of the Options

##### Typed kind catalog + generic engine (chosen)

- Good, because the interface shrinks at every consumer (API, doubles,
  future cache) and the degrade rule gets a home
- Good, because "one row per kind" is reviewable
- Bad, because engine + overrides is more machinery than status quo
- Bad, because per-kind method names disappear from the surface

##### `ResourceReader` protocol without the catalog

- Good, because the seam is explicit and typed
- Bad, because it does not shrink the 88-method interface it would sit
  over, and with one adapter it is a hypothetical seam
- Bad, because per-kind methods + string tables stay

##### Facade (delegate, delete later)

- Good, because per-commit risk is lower
- Bad, because an 88-method pass-through is a shallow module that the
  deletion test says just moves complexity; facades tend to survive

##### Status quo + helper extraction

- Good, because minimal diff
- Bad, because new-kind cost (9–10 files) and double drift stay; the
  ADR-0010 seam stays 88 wide

#### More Information

- Architecture review 2026-11-07 (jscpd health 32/E; duplication 17.2%,
  dead code 16.6%; `k8s_client.py` 2,487 lines / cx 393; 8 of the last
  10 commits are new-kind work touching 9–10 files)
- ADR-0010 (informer cache — the future second adapter at this seam)
- ADR-0004 (SAR gate — unchanged, still asked before the read)
- ADR-0040 (object navigation — unchanged; one route per kind, no
  `/data` suffix)
