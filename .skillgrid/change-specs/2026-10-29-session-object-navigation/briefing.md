# Session Object Navigation — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-29-session-object-navigation`
**Date:** 2026-10-29
**Backlog:** TBD (created with the spec commit)
**ADR:** ADR-0040 (proposed by this change — see `adr.md`)

## Intent

Every resource **data page** in the SPA is currently reached by query-string
navigation: 18 list views emit `<Link to="/.../data?name=...&namespace=...">`
and 21 data views consume the identity with `useSearchParams()`. The ratified
contract ("`?name=` + `?namespace=` query-param navigation; no 4.1 hidden
form / POST / `session['ns_select']`") was chosen in 2026-10-28 to avoid 4.1's
Flask-session round-trip — but it makes the URL a state channel: object
identity rides in Referer headers, JS-error reports, proxy/CDN access logs,
browser history, and copy-paste, and `?namespace=` duplicates the header
namespace selector (two sources of truth per object; `SecretData` silently
falls back to the store namespace, so a stale URL can resolve to the wrong
object).

The user requirement (ratified in conversation, 2026-10-29):

1. **Nothing goes to the URL.** Object identity (kind, name, namespace) must
   never appear in the address bar, browser history, or any link the SPA
   produces for navigation.
2. **Storage is the browser session, not the server.** Tab-private
   `sessionStorage`, no Redis key, no TTL endpoint, no backend state.
3. **Deep links must land on the object.** A share/copy action must open the
   object in a new tab; the identity travels as a same-origin form **POST**
   body, not a URL.

## Requirements (falsifiable)

- **R1 (no identity in URL).** After opening any object from any list, the
  address bar shows the object's *route path only* (e.g. `/security/secret`)
  — no `?name=`, `?namespace=`, or any other identity-bearing param. Checkable:
  `window.location.search === ''` on every data view.
- **R2 (session storage).** The open-object ref is persisted in
  `sessionStorage` under `kd_object_refs` (a token-keyed registry) with the
  active token under `kd_object_active`. It is NOT in `localStorage`, NOT in
  a cookie the SPA writes, NOT in a server store. Checkable: devtools
  inspection; no new API endpoint in the diff.
- **R3 (refresh survives).** Refreshing the tab on an open object re-renders
  the object (same tab → same `sessionStorage`). The ref self-expires at
  15 minutes of age (checked lazily on render; no timer): an expired ref
  renders the list and clears the active pointer. Checkable: refresh test +
  a test with `ts` backdated > 15 min.
- **R4 (cross-tab deep link via POST).** A "copy/open" action on a list row
  or data page opens the object in a NEW tab at the object's route, with the
  identity delivered as a hidden-form POST (`name="o"`, JSON body) to the
  same origin. The new tab hydrates the ref on mount, renders the object, and
  its address bar is the clean route. Checkable: e2e opens the link, asserts
  the data page renders and `location.search === ''`.
- **R5 (one-shot POST handoff).** The POST handoff uses a one-shot
  `sessionStorage` key (`kd_object_incoming`, with a monotonic counter) set
  before the form submits — see blueprint for the exact mechanism (same-origin
  form POST opens a fresh document in the new tab; the handoff key is written
  to `localStorage` under a token-scoped key `kd_ref_<token>` with a 60-second
  self-delete, because `sessionStorage` is per-tab and the new tab has an
  empty one). A plain GET to the route never consumes a stale incoming ref.
  Checkable: GET with a leftover incoming key from a *different* token renders
  the list; the relay key is gone after consumption.
- **R6 (route merge).** Each kind has ONE route (list and detail are the same
  path; the `/data` suffix is dropped). The route renders the list when the
  active ref is absent or its kind mismatches, and the detail when it
  matches. Back/forward still moves list↔detail (history entry per
  transition). Checkable: routes table has no `/.../data` entry; a ref for
  kind A on kind B's route renders B's list.
- **R7 (one-shot migration redirect).** Old URLs
  (`/x/y/data?name=...&namespace=...`) redirect (`replace`) to `/x/y` with
  the ref hydrated from the query string (`origin: 'link'`). The query string
  is not retained in the final URL. Covers existing bookmarks and in-flight
  e2e. Checkable: e2e asserts the final URL is clean and the data page
  renders.
- **R8 (namespace authority).** The detail view's namespace comes from the
  ref (authoritatively), not from the header store; the
  `params.get('namespace') || selectedNamespace || 'default'` fallback is
  gone. The header selector still drives LIST views. Checkable: with the
  header on `default`, a ref for namespace `team-a` renders the `team-a`
  object.
- **R9 (filters stay query params).** Genuine *filter* params (e.g.
  `?labelSelector=` on the pods list, `?type=` on the certmanager ELB view)
  may remain query params — they are not object identity. The `?selected=`
  bolding hint on `/security/secret` is dropped in favor of "the ref itself
  tells the list what is open" (no param at all).
- **R10 (no backend change).** No new endpoint, no migration, no Redis key.
  The backend REST `?name=`/`?namespace=` filtering params on
  `/api/v1/clusters/:id/resources/<kind>` are unchanged (GET filtering, not
  navigation). Checkable: `git diff backend/` empty for this change.

## Accepted costs (stated for the ADR)

- **Cross-machine object links do not exist.** A POST deep link works across
  *tabs of the same origin*; another machine (or a fresh profile) lands on
  the list. That is the honest boundary of "identity never durable in a
  URL." If cross-machine object deep links are ever required, that is a
  separate decision (path-param routes), not this one.
- **The 15-minute ref lifetime** bounds how long an abandoned tab keeps
  resolving its last object; after that the list renders. No server clock is
  involved — it is client time, checked lazily.

## Out of scope

- Backend routing, API shape, SAR, informer cache (unchanged).
- Pod exec/logs (the ADR-0009 bidirectional channel — its own spec).
- The OIDC login flow (already clean: `302 /` + HttpOnly cookies, ADR-0025).
- Row-expansion (Lens-style) UI — this change keeps the separate-detail-view
  layout, just on a merged route.

## Fast-track classification

**Class:** `standard` (multi-file frontend refactor, ~40 view files + new
lib module + routes + tests; no migration, no new dependency, no
trust-boundary change). No fast-track waiver; full `tasks.md`.

## Supersedes

The "`?name=` + `?namespace=` query-param navigation" deviations clause in
every 2026-10-28 view spec (recorded per spec via `NAVIGATION-SUPERSEDED.md`)
and the same clause in `2026-10-29-statefulsets-daemonsets-replicasets-views`
(which executes to this contract directly — see that spec's
`NAVIGATION-SUPERSEDED.md` execution note).
