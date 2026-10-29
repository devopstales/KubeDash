# SPA object navigation: tab-private `sessionStorage` object ref + same-origin form-POST deep link; no object identity in the URL

---
status: "proposed"
date: 2026-10-29
supersedes: the "`?name=` + `?namespace=` query-param navigation" deviations clause ratified across the 2026-10-28 view specs (recorded per spec via `NAVIGATION-SUPERSEDED.md` in `.skillgrid/specs/`)
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

Every resource **data page** in the SPA is reached by query-string
navigation: 18 list views emit
`<Link to="/.../data?name=...&namespace=...">` and 21 data views consume
the identity with `useSearchParams()`. The contract — "`?name=` +
`?namespace=` query-param navigation; no 4.1 hidden form / POST /
`session['ns_select']`" — was ratified in 2026-10-28 to avoid 4.1's
Flask-session round-trip. It works, but it makes the URL a state channel:

1. **Object identity rides everywhere a URL does.** Referer headers,
   JS-error reporters, proxy/CDN access logs, browser history, copy-paste.
   K8s object names + namespaces are internal identifiers — fine to name,
   but they do not need to be shareable state.
2. **Two sources of truth for the namespace.** `?namespace=` duplicates
   the header namespace selector (the cluster store). `SecretData`
   resolves it as
   `params.get('namespace') || selectedNamespace || 'default'` — a stale
   URL can silently resolve to the wrong-namespace object.
3. **The `/data` route suffix** is a second route per kind whose entire
   purpose is to carry the identity in the query string.

The user requirement (ratified in conversation, 2026-10-29): (1) nothing
goes to the URL; (2) storage is the browser session, not the server
(`sessionStorage`, no Redis key, no TTL endpoint); (3) deep links must
still land on the object — the identity travels as a same-origin form
**POST** body, never in a link.

#### Decision Drivers

- Object identity is UI state, not a credential (ADR-0025
  hint-not-credential pattern applies: a forged/stale ref renders a list or
  a 404, never a privilege escalation — the read stays SAR-gated at the
  API, ADR-0004).
- No backend change (R10): no endpoint, no migration, no Redis key.
- No new dependency (ADR-0020 air-gap): `sessionStorage` + a hidden form
  are platform APIs.
- Migration must not break existing bookmarks or in-flight e2e (one-shot
  redirect, R7).

#### Considered Options

1. **Keep query-param navigation (status quo).** Rejected: the identity
   stays in the URL — the stated problem is not addressed.
2. **Path params (`/security/secret/:namespace/:name`).** Rejected by
   user requirement: identity is still in the URL (shareable, logged,
   history-bearing). Would be the choice if cross-machine object deep
   links were required.
3. **Server-side pointer (`POST /api/v1/session/object` + Redis TTL).**
   Rejected by user requirement ("use session for storage instead of
   server-side with TTL"): adds an endpoint + a key for pure UI state, and
   re-introduces server round-trips the 2026-10-28 contract was chosen to
   avoid.
4. **`sessionStorage` object ref + form-POST deep link (CHOSEN).**
   Identity lives in tab-private `sessionStorage`; refresh survives in-tab;
   cross-tab deep links deliver the identity as a POST body to the object's
   route. Nothing durable in any URL.

#### Decision Outcome

**Chosen option: `sessionStorage` object ref + form-POST deep link.**

The contract (requirements R1–R10 in `briefing.md`):

- **Registry shape.** `sessionStorage` key `kd_object_refs` holds a
  token-keyed map `{ <token>: { kind, name, namespace?, ts, origin } }`;
  key `kd_object_active` holds the active token. Tokens are
  `crypto.getRandomValues` 32-bit hex. Entries self-expire at 15 minutes
  of age (checked lazily on render — no timer); an expired active ref
  renders the list and clears the pointer.
- **In-tab navigation.** List rows call `setObjectRef(kind, name,
  ns?)` → the route (one per kind, `/data` suffix dropped) renders the
  detail when the active ref's kind matches, the list otherwise. Back/
  forward moves list↔detail via normal history entries.
- **Cross-tab deep link.** The share affordance submits a hidden same-origin
  form (`method="POST"`, `action="<route>"`, hidden input `name="o"`
  carrying the JSON ref) with `target="_blank"`. The new document's SPA
  mount consumes a one-shot `sessionStorage` handoff key
  (`kd_object_incoming` + monotonic counter, R5), hydrates its own
  registry, renders the object; `history.replaceState` guarantees
  `location.search === ''` (R1).
- **Namespace authority (R8).** The detail view reads the namespace from
  the ref, authoritatively; the `|| selectedNamespace || 'default'`
  fallback is deleted. The header selector drives list views only.
- **One-shot migration redirect (R7).** Old URLs
  (`/x/y/data?name=...&namespace=...`) redirect `replace` to `/x/y` with
  the ref hydrated from the query string (`origin: 'link'`).
- **Filters stay query params (R9).** Genuine filters (e.g.
  `?labelSelector=`) remain; the `?selected=` bolding hint on
  `/security/secret` is dropped — the active ref itself tells the list
  what is open.

**Positive consequences:**

- No object identity in any URL (R1) — Referer, history, error reports,
  and access logs carry route paths only.
- One source of truth for the namespace (the ref) — the silent
  wrong-namespace fallback is gone (R8).
- Zero backend diff (R10); zero new dependencies (ADR-0020).
- Refresh survives the open object in-tab (R3); cross-tab share lands on
  the object with a clean address bar (R4).

**Negative consequences / accepted costs:**

- **No cross-machine object deep links.** The POST handoff is
  same-origin; another machine (or a fresh profile) lands on the list.
  That is the honest boundary of "identity never durable in a URL."
  Cross-machine object links require path-param routes — a separate
  decision, out of scope here.
- **15-minute client-time ref lifetime** — an abandoned tab stops
  resolving its last object after that; client clock only (no server
  clock), checked lazily.
- **The form-POST handoff is a deliberate 4.1 echo, scoped to identity.**
  2026-10-28 rejected 4.1's form-POST round-trip for the *read*; this
  change re-uses the POST shape only for *delivering the ref across tabs*
  — the read is still a SAR-gated GET.

#### Linking Decisions and Constraints

- ADR-0004 — SAR gating unchanged: a ref is a pointer, not a privilege;
  the object read is still denied with 403 `RBAC_DENIED` on SAR fail.
- ADR-0006 — single-container, same-origin SPA + API: the form POST lands
  on the same origin that serves the SPA; no CORS, no new route in the
  backend (Flask's SPA fallback serves the route, the SPA consumes the
  handoff key).
- ADR-0010 — read path unchanged (per-request REST on the generic
  resource route for these views).
- ADR-0020 — no new dependency: `sessionStorage`, `crypto.getRandomValues`,
  and a hidden `<form>` are platform APIs.
- ADR-0025 — hint-not-credential pattern: the ref is not a credential;
  it grants nothing the list page does not already show.
- ADR-0022 — nav structure unchanged (leaf paths keep their list-route
  identity; only the `/data` suffixes disappear).

#### Validation

- `frontend/tests/lib/objectRef.test.ts` — registry, active pointer,
  15-min lazy expiry, one-shot counter semantics.
- `frontend/tests/views/*` — the 16 existing view test files re-pointed
  from `useSearchParams`-driven URLs to the ref contract (link assertions
  become click → route-render assertions; `location.search === ''`).
- `frontend/e2e/` — deep-link scenario: share action opens a new tab on
  the object with `location.search === ''`; old-URL redirect scenario:
  `/security/secret/data?name=...&namespace=...` lands clean on the data
  page.
- `task fe-build` + `task fe-check` green; `git diff backend/` empty.

#### Implementation Notes

- New module: `frontend/src/lib/objectRef.ts` (~150 LOC) — the single
  seam; views never touch `sessionStorage` directly.
- New wrapper: `ObjectRoute` component (kind-matched list/detail render).
- `App.tsx` — route merge (one route per kind) + the old-URL redirect
  middleware.
- The backend REST `?name=`/`?namespace=` filtering params on
  `/api/v1/clusters/:id/resources/<kind>` are unchanged (GET filtering,
  not navigation).
- Wide refactor sequencing (expand → migrate batches → contract) per
  `tasks.md`.
