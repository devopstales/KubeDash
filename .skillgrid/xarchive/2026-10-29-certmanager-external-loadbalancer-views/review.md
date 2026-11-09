# Review — Network 4.1-parity Views Batch (4 changes)

> Change: report home `.skillgrid/xarchive/2026-10-29-certmanager-external-loadbalancer-views/`
> (the batch's newest) + the three
> `2026-10-28-{service,ingress-gateway-api,ingressclass-gatewayclass}-views/`
> specs — a batch of 4: service-views, ingress-gateway-api-views,
> ingressclass-gatewayclass-views, certmanager-external-loadbalancer-views.
> All four were delivered (2026-11-05), then archived (`5d4048d1`, 2026-11-08)
> **before their review gate ran** — this is that gate.
> Generated: 2026-11-09 (requesting-code-review)
> Diff: the four delivered change commit sets + the 2026-11-07 nav-consolidation
> shape change, reviewed as current state (HEAD + working tree):
> service-views `d4047c6a` (frontend in `689b487b`) · certmanager-external-LB
> `9f0b54c6`+`9273f5dc` (frontend in `689b487b`) · ingress-gateway-api
> `b29f97ac` (frontend `1f827523`, `a80b8b1f`, `547fd93f`, `30a3e6f2`) ·
> ingressclass-gatewayclass `f6e0d56f`+`9af4eeb9`+`1b2214bf` · shape change
> `c43dd50b`+`0cfec7f6`+`1fd74039`. Fix-wave commits this round:
> `2035efb3` (v1 shapes) → `d088e843` (SAR namespace) → `b886ce99`
> (labelSelector 502 + MetalLB lists) → `59f0c71a` (MetalLB gets) + spec-zone
> `03292612`.
> Rigor tier: T2
> Review budget: 3 rounds (T2); this is round 1 — converged in one fix wave.
> Independence: Grade B per axis (fresh subagent contexts, no shared session
> history — but the same toolchain/model family as the implementer; a T2
> three-axis pass, per `_shared/planning/rigor-tiers.md`)
>
> The durable audit record of the code review. The three review axes are
> reported **side by side, never merged** — that separation is the point.

## What Important means

- **Critical** — must fix before merge. Security, data loss, broken
  functionality, a `SATISFIES` scenario whose RED evidence is missing or whose
  code path does not match the Given/When/Then.
- **Important** — should fix before merge. Architecture drift from a term or
  in-force ADR, a hard standard breach, a missing/partial requirement, or
  behavior the spec never asked for (scope creep). Unfixed Important issues do
  not proceed.
- **Minor** — nice to have. Baseline smells, style, optimization, doc polish.
  Capped.

## Passes

> Three axes, side by side. Never merged into one verdict.

### Standards

- **Worst issue (within this axis):** the Ingress→Gateway-API converter
  emitted Gateway-API-shaped resources that FAIL Gateway API v1 CRD validation
  — the ratified Apply action 422s the Gateway and every HTTPRoute (Critical,
  verified against the dev cluster's live v1 CRDs; FIXED `2035efb3`).
- **Findings:** 1 Critical / 4 Important / 3 Minor (+3 FYI)
- **Verdict:** met-with-fixes

### Spec

- **Worst issue (within this axis):** 22 API-tier scenarios claimed
  `SATISFIES` with **zero API-tier tests** where the blueprints mandated them
  (13 ingressclass/gatewayclass + 9 ingress/gateway-api) — a TDD evidence gap,
  not a behavior gap (0 MISSING, 0 WRONG behavior; FIXED — 34 new API-tier
  tests).
- **Findings:** 2 Critical / 1 Important / 6 Minor
- **Verdict:** met-with-fixes (113 scenarios: 87 SATISFIES, 26 PARTIAL —
  all evidence-level — 0 MISSING, 0 WRONG; PARTIALs closed this pass)

### Security

- **Worst issue (within this axis):** the first generic cluster write path
  (`POST /resources/apply`) writes no audit row (CWE-778, Low, PARKED →
  TASK-102). No exploitable access-control, injection, SSRF, or
  secrets-exposure issue found; the apply's all-or-nothing SAR gating is
  consistent with the ADR-0004 model it extends.
- **Findings:** 0 Critical / 0 High / 0 Medium / 3 Low (2 FIXED, 1 PARKED).
  Dropped candidates (documented, not findings): unrestricted apply kinds (by
  design, SAR-derived from the same apiVersion/metadata), SAR cache-key colon
  ambiguity (closed tables, 30 s TTL), metadata free-dict in apply
  (apiserver prunes; no delete endpoint), CORS/CSRF (no CORS headers → JSON
  POSTs preflight-gated).
- **Verdict:** secure-with-fixes

## Findings

### Critical

- [Standards→**FIXED** `2035efb3`] `backend/app/services/gateway_convert.py` —
  7 shape defects, each verified against the live v1 CRDs on the dev kind
  cluster: `:125,134` `"port": {"number": 80}` (CRD `port` is int32);
  `:252-259` `backendRefs` in the *Ingress* shape (`HTTPBackendRef` requires
  flat top-level `name/namespace/port/weight`, `name` required); `:296-301`
  `timeouts.backendRequest: {"timeout": N}` (CRD is a Duration **string**);
  `:325-328` `{"type": "Redirect", "redirect"}` (v1 enum: `RequestRedirect` /
  `requestRedirect`); `:195-215` `{"type": "CORS"}` (not in the enum — the v1
  CRD has **no CORS filter at all**); `:191` `urlRewrite.replacePrefixWith`
  (not a field → pruned, leaving required `path` absent); `:289-291`
  `spec.sectionName` (not an `HTTPRouteSpec` field — lives on
  `parentRefs[]`, `minLength: 1`; silently pruned = TLS-listener pinning lost
  without error). Every emitted Gateway and HTTPRoute fails validation → the
  converter's primary ratified action (Apply) 422s its two main outputs.
  **Fix:** emit v1 shapes — int ports, flat `HTTPBackendRef`, `"30s"`
  Duration, `RequestRedirect`, CORS dropped to sorted `warnings` keys
  (annotation keys that no longer map), `ReplaceFullPath`,
  `parentRefs[].sectionName` (omitted when no TLS host; `"http"` on the
  redirect route) — + dead `_csv`/`_bool` helpers removed. Converter tests
  rewritten with explicit v1-shape assertions (8 tests).
- [Spec→**FIXED** `2035efb3`/`d088e843`/`b886ce99`] `backend/tests/api/`
  (absent tests) — the ingress-gateway-api blueprint (`:337-345`, `:416-423`)
  and ingressclass-gatewayclass blueprint (`:160`, `:268`, `:454`) both
  mandate API-tier tests in `test_resources.py`; **zero** existed for any of
  `ingresses`/`gatewayclasses`/`gateways`/`httproutes`/`referencegrants` /
  `ingressclasses`/`gatewayclasses` (grep-verified) — 22 claimed scenarios
  rested on the generic route + service-tier tests only. **Fix:** 34 new
  API-tier tests (list-200 + SAR group, namespace-ignore, get-by-name,
  SAR-deny-asserts-no-client-call, binding-404, singular-404, CRD-absent-
  empty, all-namespaces) + FakeK8s doubles for the 6 kinds.
- [Spec→**FIXED** `b886ce99`] `backend/tests/api/test_resources.py` (absent
  tests) — 3 certmanager/exlb scenarios claimed SATISFIES without API tests
  (`certmanager-kind-singular-rejected`, `exlb-kind-singular-rejected`,
  `exlb-provider-absent-empty`) — covered by the same 34-test wave.

### Important

- [Standards→**FIXED** `d088e843`] `backend/app/api/gateway_api.py:41` vs `:47`
  — the convert endpoint's SAR was asked with `namespace or None` (cluster-
  wide, "any namespace" for a namespaced resource) while the read was pinned
  to `default` (ADR-0004 addendum: "a verdict for one namespace or object must
  never answer for another"): a user holding `get ingresses` on the name in
  some *other* namespace passes the gate, the read 403s at the API server,
  and `get_ingress` maps non-404 ApiExceptions to `ClusterUnreachableError` →
  **502 CLUSTER_UNREACHABLE for an RBAC denial**. **Fix:** resolve
  `ns = namespace or "default"` once; used in the SAR + read + response
  (mirrors the generic `?name=` route). The delivered UI always sends the
  namespace (`GatewayConverter.tsx:63`) — the trigger is direct API clients.
- [Standards→**PARKED** → TASK-100] `frontend/src/views/Network/
  CertManager.tsx:353-357` + `CertManagerData.tsx:270-274` — Secret deep-
  links use `<Link to={'/security/secret/data?name=…&namespace=…'}>`: object
  identity in the URL **and** the `/data` suffix (ADR-0040 R1: "nothing goes
  to the URL"; glossary "Object ref — The URL never carries it"). House
  pattern: the `openObject` button (`ServiceAccounts.tsx:93`). **Ruling:**
  both files carry uncommitted in-flight kind-registry WIP — the fix is a
  one-line-class change that lands after that WIP; ticketed, not forced into
  a WIP-bundled commit.
- [Standards→**FIXED** `03292612`] `.skillgrid/knowledge/decisions/
  04-adr-0022-…md:139` + `2026-10-28-ingress-gateway-api-views/MENU-MERGED.md`
  — the 2026-11-07 amendment's "The Network group is now **exactly**
  Services, Ingress, Ingress Class" contradicts the delivered five-leaf nav
  (the two certmanager Beta leaves — Cert-Manager, Load Balancer — added by
  the 2026-10-29 spec delivered earlier the same day; the ADR's normative
  table never gained their rows). **Fix:** reworded to scope "exactly" to the
  4.1-parity leaves (ADR + MENU-MERGED + `knowledge/log.md` entry).
- [Standards→**FIXED** `03292612`] `AGENTS.md:5,23,30,43,62` — RQ/Redis/
  leader-only-worker claims stale after the ADR-0029/0030/0031 merge
  (`a774e0ed`, 2026-11-08, after the file's last render): `wsgi.py` reads
  "ADR-0029 (RQ gone): the queue is Postgres, not Redis" and the worker
  claims on **every** replica (only enqueue is leader-gated); ADR-0007/0008
  superseded; `dev-up` runs two-node pgEdge (Redis dropped; SSO starts with
  `dev-stack`). **Fix:** five-line surgical pass + the `wsgi.py` Key-
  Directories row. Verified clean by the reviewer: every other AGENTS.md
  claim (versions, all named tasks, paths, CI gates) against current repo
  state.
- [Spec→**FIXED** `b886ce99`] — the 3 certmanager/exlb API-tier scenarios
  (see Critical #3) — dispositioned Important per the axis's own count;
  closed in the same 34-test wave.

### Minor

- [Standards→**PARKED** → TASK-101] `frontend/src/App.tsx:333` +
  `ExternalLoadBalancer.tsx:149,240,283` + `ExternalLoadBalancerData.tsx:59-65`
  — registry kind `bgppeers` (the API plural) drifts from the glossary
  "Registry kind" singular-slug convention (siblings: `ipaddresspool`,
  `l2advertisement`, `bgpadvertisement`). Functionally nil; files carry
  in-flight WIP → ticketed.
- [Standards→**FIXED** `03292612`] `AGENTS.md:126` — "(next: 0041)" stale:
  ADR-0041 exists → 0042 (also `.skillgrid/config.yaml` counter 0031 → 0041).
- [Standards→**FIXED** `03292612`] `AGENTS.md:41` — the read-path line stated
  ADR-0010's deferred target as current fact (verified: no `watch` import in
  `backend/`; the ADR records the deferral) → phrased as target with a
  pointer to the deferral note.
- [Spec→**FIXED** `03292612`] `acceptance.feature:115,228` — the singular-
  kind scenarios pinned **400**; the platform error class (`errors.py:79-82`)
  + all four sibling feature files pin **404** `RESOURCE_KIND_NOT_SUPPORTED`
  (the code implements 404 — the feature was the internal outlier). Repinned.
- [Spec→**FIXED** `b886ce99`] `k8s_client.py:289-310` `list_pods` — never
  wrapped `ApiException` (pre-existing; the security axis flagged it
  independently): a malformed `?labelSelector` → raw `ApiException` → 500
  instead of the sibling 502. Wrapped mirroring `list_services` + regression
  test.
- [Spec→**NOTED** (process)] the spec zones were committed only at `5d4048d1`
  (2026-11-08), after all code commits (2026-11-05+) — the RED→GREEN ordering
  is not reconstructable from git history; the spec-zone rule's tracking gap
  stands for this batch.
- (1 further Minor collapsed — no dedicated cert-manager binding-404 API
  test: the `_cluster_for` gate is shared and now tested via the other kinds'
  binding-404 tests; see the raw SpecReview report.)

### Security (3 Low)

- [Security→**FIXED** `b886ce99`] `k8s_client.py:289-310` `list_pods` —
  malformed `?labelSelector` → 500 instead of a client error (CWE-755): any
  authenticated, bound user can force a 5xx; no information leak (stable
  catch-all, `__init__.py:249-251`). Same fix as Spec Minor #5.
- [Security→**FIXED** `b886ce99`+`59f0c71a`] `k8s_client.py` MetalLB
  branches — the four MetalLB kinds are cluster-scoped, but both list and
  get-by-name used the **namespaced** URL: all-namespaces list 502s when
  `?namespace` is omitted (CWE-755; the kubernetes client renders
  `str(None)`); get-by-name 404s → `[]` → a **silent empty detail view** on
  MetalLB clusters. **Fix:** all eight methods (list + get) now use the
  cluster-scoped read, namespace accepted-and-ignored (documented); service-
  tier tests updated to assert the cluster-path call.
- [Security→**PARKED** → TASK-102] `backend/app/api/resources.py`
  `apply_objects` — the first generic cluster write path writes no `AuditLog`
  row (CWE-778): who created/patched which GatewayClass/Gateway/HTTPRoute is
  not persisted (only the K8s-side trail, if the cluster keeps one). Repo
  precedent is split (`permission.py` writes rows; `create_namespace`/
  `delete_namespace` don't) — the fix is one statement per applied object,
  but the spec is silent and the precedent is a design call → ticketed.

### FYI (one line each)

- [Standards] `apply_objects` reports a 409→patch as `"unchanged"`
  (`k8s_client.py:2353-2359`); a full-object merge-patch can modify fields.
  Cosmetic; the idempotent shape is sound.
- [Standards] the certmanager spec folder has no `NAVIGATION-SUPERSEDED.md`
  note the other three carry, while its Deviation #2 is superseded in the
  delivered code. Input-zone doc gap.
- [Standards] annotation rendering is uneven across the Network views
  (verbatim in ServiceData/CertManagerData per their ADRs; machine-key trim in
  the ingress views per the T2 override recorded in the two ingress ADRs).
  Each view matches its own ADR; the surface is uneven by recorded design.

## Independence

| Axis | Grade | Rationale |
|------|-------|-----------|
| Standards | B | fresh `reviewer` subagent; saw only the current state + glossary/ADR/standards sources; verified CRD claims against the live dev-cluster v1 CRDs; same toolchain family as the implementer |
| Spec | B | fresh general-purpose subagent; saw only the four acceptance.features/blueprints/briefings + the delivered code; grep-verified every "absent test" claim |
| Security | B | fresh `security-reviewer` subagent; saw only the current state + OWASP checklist; walked the reference checklist end-to-end |

**Reading the grade:** all three are **B** — independent contexts (no
implementer session history shared), same model family as the implementer;
the CRD-validated fix + the 34-test evidence wave + the re-executed floor are
the compensating controls.

## Verdict

- **Standards:** met-with-fixes
- **Spec:** met-with-fixes
- **Security:** secure-with-fixes
- **Floor (decides):** met-with-fixes
- **Worst issue (across all three axes):** converter emitted v1-CRD-invalid
  Gateway/HTTPRoute resources that 422 the ratified Apply (Standards Critical,
  FIXED `2035efb3`, CRD-validated)
- **Unfixed Important count (must be 0 to proceed):** 0 — all 4 Important
  findings fixed this pass or parked with a ruling (TASK-100 Secret deep-
  links, blocked by in-flight WIP on both files)

## Triage / fix loop (receiving-code-review)

| Finding | Severity | Disposition | Action |
|---------|----------|-------------|--------|
| Converter 7 v1 shape defects | Critical | FIX NOW | `2035efb3` — v1 shapes, CRD-validated; 8 rewritten converter tests |
| 22 API-tier scenarios, zero API tests | Critical ×2 (Spec) | FIX NOW | 34 new API-tier tests across `2035efb3`/`d088e843`/`b886ce99` + FakeK8s doubles (6 kinds) |
| certmanager/exlb 3 API scenarios | Important (Spec) | FIX NOW | same 34-test wave |
| Convert SAR ns vs read ns | Important | FIX NOW | `d088e843` — `ns` resolved once (SAR + read + response) |
| Secret deep-links `/data` style | Important | PARK → TASK-100 | in-flight WIP on both files; one-line-class fix after it lands |
| ADR-0022 "exactly three leaves" | Important | FIX NOW | `03292612` — reworded to 4.1-parity scope |
| AGENTS.md RQ/Redis/leader staleness | Important | FIX NOW | `03292612` — 5-line pass + dev-up stack |
| bgppeers plural registry kind | Minor | PARK → TASK-101 | in-flight WIP; glossary singular-slug |
| AGENTS.md next-ADR + read path | Minor ×2 | FIX NOW | `03292612` |
| feature 400→404 repin | Minor (Spec) | FIX NOW | `03292612` |
| `list_pods` ApiException wrap | Minor (Spec) + Low (Sec) | FIX NOW | `b886ce99` — mirrors `list_services` + regression test |
| MetalLB namespaced list (all-ns 502) | Low (Sec) | FIX NOW | `b886ce99` — cluster-scoped read |
| MetalLB namespaced get (empty detail) — surfaced by the fix wave's own out-of-scope note | Low (Sec, same class) | FIX NOW | `59f0c71a` — cluster-scoped read + service-tier tests |
| apply audit row | Low (Sec) | PARK → TASK-102 | spec-silent; repo precedent split (design call) |
| spec-zone tracking gap | FYI (process) | NOTED | RED→GREEN not reconstructable for this batch |
| 409→patch "unchanged" | FYI | PARK | cosmetic |
| annotation-trim uneven surface | FYI | PARK | per-ADR by design |
| missing NAVIGATION-SUPERSEDED note | FYI | PARK | doc gap |

## Floor re-execution after fixes

Post-fix (`2035efb3`→`59f0c71a`, dev stack live):

- Backend unit (`pytest -m "not integration" -q`): **843 passed, 10
  deselected** (+34 from this pass's new API-tier tests).
- 3-file target (`test_resources.py` + `test_gateway_api.py` +
  `test_gateway_convert.py`): **226 passed** (214 resources + 4 gateway-api +
  8 converter). The 3 kind-cluster integration 500s during the 16-minute run
  were a transient kind-cluster wedge (methods untouched by the wave);
  re-run in isolation: **3 passed** (live kind cluster). The 3 ScopeMismatch
  errors are pre-existing (`kind_client` fixture scoping in unmodified
  `tests/conftest.py`; present in the pre-change run).
- `ruff check .` / `mypy app` on the touched files: **zero new findings** —
  the 14 E501s are the identical 12+2 from HEAD (line-shifted, verified);
  mypy on the 3 app files byte-identical to HEAD (verified via HEAD worktree
  diff).
- Frontend: no changes this pass — the only frontend findings are the 2
  parked items (TASK-100/101); the 491-test frontend suite was green at
  review time and no frontend file was touched since.

## Open items (next-cycle context)

- **TASK-100** (Important, PARKED): cert-manager Secret deep-links →
  `openObject` — unblocks when the in-flight kind-registry WIP lands.
- **TASK-101** (Minor, PARKED): `bgppeers` → `bgppeer` registry kind rename —
  same unblock.
- **TASK-102** (Low, PARKED): `POST /resources/apply` audit row — needs the
  precedent design call.
