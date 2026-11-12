# Session Object Navigation — ADR

## Decision Summary

Replace the SPA's query-string object navigation ("`?name=` + `?namespace=`
query-param navigation; no 4.1 hidden form / POST / `session['ns_select']`",
ratified across the 2026-10-28 view specs) with **tab-private
`sessionStorage` object refs + same-origin form-POST deep links**: object
identity (kind, name, namespace) never appears in the URL, refresh
survives in-tab via `sessionStorage` (15-min lazy self-expiry), and a
share action opens the object in a new tab by POSTing an opaque token —
the identity itself rides a 60-second self-deleting `localStorage` relay.
One route per kind (the `/data` suffix is dropped); old `/.../data?name=`
URLs redirect one-shot to the clean route. No new API endpoint, no
migration, no new dependency (R10, amended 2026-11-04 — see Amendments
below). **ADR-0040** (proposed 2026-10-29, amended 2026-11-04) is the full
decision record.

## Decision Context

- **The URL was a state channel.** 18 list views emit
  `<Link to="/.../data?name=...&namespace=...">`; 21 data views consume the
  identity via `useSearchParams()`. Object identity therefore rode in
  Referer headers, JS-error reports, proxy/CDN access logs, browser
  history, and copy-paste.
- **Two sources of truth for the namespace.** `?namespace=` duplicated the
  header selector; `SecretData` resolved
  `params.get('namespace') || selectedNamespace || 'default'`, so a stale
  URL could silently resolve to the wrong-namespace object.
- **The requirement (ratified 2026-10-29, conversation).** (1) Nothing goes
  to the URL. (2) Storage is the browser session (`sessionStorage`), not
  server-side with a TTL. (3) Deep links must still land on the object —
  identity travels as a form POST, never in a link.
- **Why not the alternatives.** Path params keep identity in the URL
  (rejected by requirement 1). A server-side pointer
  (`POST /api/v1/session/object` + Redis TTL) adds an endpoint + key for
  pure UI state and re-introduces the round-trips the 2026-10-28 contract
  was chosen to avoid (rejected by requirement 2). The form-POST shape is a
  deliberate, scoped 4.1 echo: 2026-10-28 rejected the form round-trip for
  the *read*; this change uses the POST only to *deliver the ref across
  tabs* — the read is still a SAR-gated GET (per ADR-0004).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | SAR gating unchanged: the ref is a pointer, not a privilege — a forged/stale ref renders a list or a 404, never a privilege escalation. The object read stays `list`/`get`-SAR-gated at the API. |
| 0006 | Single-container, same-origin SPA + API: the form POST lands on the same origin that serves the SPA (Flask's SPA fallback serves the route); no CORS, no backend route. |
| 0010 | Read path unchanged: these views are per-request REST on the generic resource route; the informer cache is not involved (as today). |
| 0020 | Air-gap: `sessionStorage`, `localStorage`, `crypto.getRandomValues`, and a hidden `<form>` are platform APIs — no new npm/Python dependency. |
| 0022 | Nav structure unchanged: leaf paths keep their list-route identity; only the `/data` suffixes disappear from `App.tsx`. |
| 0025 | Hint-not-credential pattern, extended: the object ref is not a credential (the `kd_session` hint grants nothing; the ref likewise grants nothing the list page does not already show). The relay key is an opaque 32-bit token, not identity. |

## Deviations (from the superseded 2026-10-28 contract)

1. **`sessionStorage` object ref replaces `?name=`/`?namespace=` query
   params** for all object navigation (list → detail, deep link,
   back-compat redirect). The identity is in tab-private storage, not the
   URL.
2. **The `/.../data` route suffix is dropped** — one route per kind;
   `ObjectRoute` renders list vs detail from the active ref (R6).
3. **Cross-tab deep links use a same-origin form POST** (hidden form,
   `target="_blank"`, body = opaque token) — the scoped 4.1 echo; the
   identity rides a 60-second self-deleting `localStorage` relay
   (`kd_ref_<token>`), not the URL (R4/R5).
4. **Namespace authority moves to the ref** — the detail view reads the
   namespace from the ref, authoritatively; the
   `|| selectedNamespace || 'default'` fallback is deleted (R8). The header
   selector drives list views only.
5. **The `?selected=` bolding hint on `/security/secret` is dropped** — the
   active ref tells the list what is open (R9). Genuine filter params
   (`?labelSelector=`, `?kind=`, `?type=`) remain query params.
6. **Refs self-expire at 15 minutes** (client time, checked lazily on
   render; no timer, no server clock) — an expired active ref renders the
   list and clears the pointer (R3).
7. **Accepted cost: no cross-machine object deep links** — the POST handoff
   is same-origin; another machine/fresh profile lands on the list.
   Cross-machine object links would require path-param routes (a separate
   decision).

## Amendments

- **2026-11-04 — token delivery via the server session (user decision after
  the QA gate FAIL).** The original cross-tab design delivered the token to
  the fresh tab via `?o=` in the document URL. The QA gate (2026-11-03,
  FAIL) proved this non-functional in a real browser (a form POST body
  never enters the new document's URL; the Flask dev server 405s the POST;
  a static nginx fallback serves the index without `?o=`). Approved
  mechanism: the SPA fallback accepts the POST, stashes the token in Redis
  under `obj_incoming:<sub>` (the `kd_access` JWT subject; TTL 60 s = the
  relay window), bounces 303 to the same path, and the first subsequent GET
  injects the token as a one-shot `<meta name="kd-object-incoming">`
  (GETDEL; injected document no-store). `consumeIncoming()` reads the meta
  instead of the URL. No new cookie, no URL change, no new API endpoint —
  R10's checkable is carved to "no new API endpoint / migration / cookie;
  the backend diff is the SPA-fallback handoff plumbing"
  (`app/core/object_handoff.py` + the catch-all methods). Token entropy
  raised 32 → 64 bits (QA finding S-1). Deviations item 3 (form POST body =
  opaque token) is unchanged; only the token's delivery channel moved.
