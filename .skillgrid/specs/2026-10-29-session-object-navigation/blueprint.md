# Session Object Navigation — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T2 — wide frontend refactor (~40 view files + new lib module +
routes + ~16 test files); no migration, no new dependency, no backend
change, no public-API break.

**Classification:** `medium-risk` (the blast radius is wide but the change
is mechanical per view; the novel seams are the two small ones —
`objectRef.ts` and the form-POST handoff — and they are de-risked first by
the template-kind ticket).

**Build shape:** Expand → migrate → contract (wide-refactor exception):
Ticket T1 adds the new contract ALONGSIDE the query-param shape (one
template kind runs both); T2–T7 migrate kinds in batches; T8 removes the
old shape (contract).

## The contract (single seam)

### 1. `frontend/src/lib/objectRef.ts` (new, ~150 LOC)

```ts
export interface ObjectRef {
  kind: string            // e.g. 'secret', 'priorityclass'
  name: string
  namespace?: string      // namespaced kinds only
  ts: number              // Date.now() when set (client time; 15-min expiry)
  origin: 'click' | 'link' | 'post'
}

const REGISTRY_KEY = 'kd_object_refs'   // sessionStorage: token -> ObjectRef
const ACTIVE_KEY = 'kd_object_active'   // sessionStorage: active token
const RELAY_PREFIX = 'kd_ref_'          // localStorage: 60s cross-tab handoff
const EXPIRY_MS = 15 * 60 * 1000

// Registry access (sessionStorage; per-tab):
export function readRegistry(): Record<string, ObjectRef>
export function writeRegistry(reg: Record<string, ObjectRef>): void

// Token:
export function mintToken(): string            // crypto.getRandomValues, 32-bit hex

// Active pointer (lazy expiry: > 15 min → null + cleared):
export function getActiveRef(): ObjectRef | null
export function setActiveRef(token: string): void
export function clearActiveRef(): void

// In-tab open (list row click): registry entry + active pointer + history push:
export function openObject(kind: string, name: string, namespace?: string): void
//   → mintToken, registry write, setActiveRef, navigate(listRoute) via a
//     registered navigate fn (set once by ObjectRoute; keeps this module
//     router-free for unit tests)

// Cross-tab deep link (share action):
export function postObjectToTab(kind, name, namespace?, routePath: string): void
//   1. token = mintToken(); ref = {..., origin: 'post'}
//   2. localStorage.setItem(`kd_ref_${token}`, JSON.stringify(ref))  // relay
//   3. localStorage.setItem(`kd_ref_${token}_exp`, String(Date.now() + 60_000))
//   4. hidden form: method=POST, action=routePath, target=_blank,
//      hidden input name="o" value=token  (the TOKEN only — the ref body
//      stays in the relay; the URL and the form body carry no identity)
//   5. form.submit()
//
//   NOTE (R5 mechanism): a form POST opens a FRESH document whose
//   sessionStorage is empty — so the relay rides localStorage (shared
//   across tabs of the origin) for exactly the handoff window, then
//   self-deletes on consumption. The form body carries the token (an
//   opaque 32-bit id), NOT the identity JSON.

// New-tab mount consumption (called once by ObjectRoute on mount):
export function consumeIncoming(): ObjectRef | null
//   1. token = new URLSearchParams(window.location.search).get('o')
//      — after the SPA fallback serves the POST, the token arrives as a
//      query param on the new document ONLY in dev/prod SPA-fallback; the
//      primary path is: the POST's action is the route and the token rides
//      `document.referrer === ''` + a one-shot `kd_object_incoming`
//      sessionStorage key the SPA writes before re-mounting. See step 5
//      below.
//   2. relay read: localStorage.getItem(`kd_ref_${token}`); expiry check
//      against `_exp`; if stale/absent → null
//   3. hydrate: registry write + setActiveRef(token)
//   4. self-delete: both relay keys removed
//   5. history.replaceState → strip `?o=` (R1)

// Sweep: expired relay keys (called on App mount, idempotent):
export function sweepRelay(): void
```

**Handoff mechanism, precisely (R5).** A same-origin form POST with
`target="_blank"` opens a new tab whose document is `routePath`. That tab's
`sessionStorage` is empty (per-tab), so the ref cannot ride it. The relay
therefore uses `localStorage` (shared per-origin) under a **token-scoped**
key with a **60-second expiry** and **self-delete on consumption** — it is a
relay bus, not storage: nothing persists, and the form body / URL carry
only the opaque token. The new tab's `ObjectRoute` mount calls
`consumeIncoming()`: resolves the token (from the POST-derived location or
the `kd_object_incoming` one-shot key), reads + validates + deletes the
relay, hydrates its own `sessionStorage` registry. A plain GET never calls
the POST path, so it never consumes a relay key — and even if a token were
guessed, a miss is a list render, never a wrong object (the registry is
token-keyed).

### 2. `frontend/src/components/ObjectRoute.tsx` (new, ~80 LOC)

```tsx
// One wrapper per kind: renders the LIST when the active ref is absent or
// its kind mismatches; renders the DETAIL when it matches (R6).
//   - mount: consumeIncoming() → if it returns a ref for THIS kind, the
//     detail renders immediately (R4 deep link).
//   - the active ref's namespace is authoritative for the detail (R8):
//     detail receives { name, namespace } from the ref, never from
//     useSearchParams.
//   - history: list→detail is a navigate() (push); detail→list (back, or
//     "back to list" breadcrumb) is history.back() / clearActiveRef().
//   - on mount, registers the navigate fn with objectRef (openObject's
//     seam) and runs sweepRelay() once.
// Props: kind, listRoute, list: ReactNode, detail: ({name, namespace}) => ReactNode
```

### 3. Share affordance (new, small)

`frontend/src/components/ShareObjectButton.tsx` (~30 LOC): the ⧉ icon
button; `onClick={() => postObjectToTab(kind, name, ns, listRoute)}`.
Placed in list-row name cells (new column or in-cell icon) and in each
data-page header.

### 4. Route merge (`frontend/src/App.tsx`)

Every `<Route path="/x/y">` + `<Route path="/x/y/data">` pair becomes ONE
`<Route path="/x/y">` whose element is
`<ObjectRoute kind="y" listRoute="/x/y" ...>`. The old `/x/y/data` route is
kept as a **redirect route** (R7): `<OldDataRedirect>` reads the legacy
`?name=`/`?namespace=` (and `?kind=`/`?type=` where applicable), calls
`openObject(...)` with `origin: 'link'` (via a one-shot registry write with
`ts = Date.now()`), and `<Navigate to="/x/y" replace />`. The redirect
routes stay for the life of the app (they are the bookmark-compat layer) —
or drop them after one release cycle; decision recorded in tasks T8.

### 5. Migration map per view (mechanical)

For each kind (the 18 link producers + 21 data consumers):

- **List view:** replace the `<Link to="/.../data?name=...">` name cell with
  a clickable cell: `onClick={() => openObject(kind, name, ns)}` (keep the
  `KubeDataTable` column API — the cell becomes a button, not a Link). Add
  the `ShareObjectButton`. Drop `useSearchParams` where it existed ONLY for
  the identity (keep it for genuine filters, e.g. `?labelSelector=` on pods).
- **Data view:** delete `const [params] = useSearchParams()` + the
  `params.get('name')`/`params.get('namespace')` reads; receive
  `{name, namespace}` as props from `ObjectRoute`. Delete the
  `|| selectedNamespace || 'default'` fallback (R8). The query itself is
  unchanged (backend `?name=` filtering, R10).
- **`?selected=` hint** (`Security/Secret.tsx` + the `ServiceAccounts.tsx`
  producer): deleted (R9) — the active ref tells the list what is open; the
  bolding reads `getActiveRef()`.

### 6. Kind inventory (migration batches)

| Batch | Kinds (route) | Scoping | Views |
|---|---|---|---|
| T1 template | priorityclass (`/other-resource/priorityclass`) | cluster | 2 |
| T2 | secret, network-policy (`/security/...`) | namespaced (+`?kind=`/`?type=` filter on network-policy — stays a filter, R9) | 4 |
| T3 | service-account, role, cluster-role (+ binding cross-links) (`/cluster-permission/...`) | mixed | 8 |
| T4 | namespace, node, crd (`/cluster/...`) | mixed | 6 |
| T5 | hpa, vpa, pdb, resource-quota, limit-range (`/other-resource/...`) | namespaced | 10 |
| T6 | runtimeclass (cluster) + route-merge pass over all of the above in `App.tsx` | — | — |
| T7 | in-flight spec views: statefulsets/daemonsets/replicasets (execute to NEW contract per its `NAVIGATION-SUPERSEDED.md` note) | namespaced | 6 |
| T8 | contract: delete all `useSearchParams` identity reads, drop `?selected=`, remove or keep redirect layer (decision), ADR flip to accepted, docs | — | — |

Kinds whose VIEWS are still stubs (configmap, pvc, volumesnapshot,
storageclass, snapshotclass, service, ingress, ingressclass/gatewayclass —
see `views/Stub/routes.ts`) are NOT migrated here: their specs'
`NAVIGATION-SUPERSEDED.md` tells their executors to build to this contract
directly.

### 7. Test map

- `frontend/tests/lib/objectRef.test.ts` (new): registry round-trip, token
  mint uniqueness, 15-min lazy expiry (backdated `ts`), one-shot relay
  consume + self-delete, stale relay (expired) → null, `sweepRelay` idempotent.
- `frontend/tests/components/object_route.test.tsx` (new): kind-match render
  (detail vs list), mismatch → list, `consumeIncoming` on mount, navigate
  seam registration.
- The 16 existing view test files under `frontend/tests/views/` that use
  `useSearchParams`/`/data?name=` URLs (hpa ×2, limit-range ×2,
  network-policy ×2, pdb ×2, priorityclass, resource-quota ×2,
  role-bindings, roles, runtime-class, secrets, service-accounts, vpa,
  crds, namespaces, namespace-data, node): re-pointed — link assertions
  become click → detail-render assertions; every data-view test asserts
  `window.location.search === ''` (R1); the R8 test (header `default`,
  ref `team-a`) lives in `secrets.test.tsx`.
- `frontend/e2e/ui-smoke.spec.ts`: the route list drops the 14 `/data`
  entries; add a deep-link scenario (share button → new tab renders the
  object, `location.search === ''`) and an old-URL redirect scenario
  (`/security/secret/data?name=...&namespace=...` → clean data page).
- `task fe-check` (air-gap) + `task fe-build` unchanged gates.

## Verification floor (per ticket)

`cd backend && uv run pytest -m "not integration"` (green, unchanged —
R10), `cd frontend && corepack pnpm test` (targeted files per ticket),
`task fe-build`, `task fe-check`.

## Open decisions (resolve in T8)

1. **Redirect layer lifetime:** keep the `/.../data` redirect routes
   permanently (bookmark-compat) or drop after one release. Default: keep
   (they are ~40 lines of declarative routes).
2. **Share affordance placement:** in-cell icon per row vs. data-page-header
   only. Default: both (rows get the icon only when the row is the open
   object's source; header always).
