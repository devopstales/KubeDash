---
type: InvariantContract
title: "No object identity in any SPA URL (session-ref navigation)"
description: "The open object is a token-keyed sessionStorage ref (kd_object_refs + kd_object_active, 15-min lazy expiry); cross-tab deep links ride a form-POST + 303 bounce + one-shot meta (obj_incoming:<sub>, Redis TTL 60 s); the URL stays the clean route. (ADR-0040.)"
tags: [object-navigation, deep-link, session-storage, adr-0040]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: frontend/src/lib/objectRef.ts
      all_of: ["REGISTRY_KEY = 'kd_object_refs'", "ACTIVE_KEY = 'kd_object_active'", "INCOMING_META = 'kd-object-incoming'"]
    - path: backend/app/core/object_handoff.py
      all_of: ['obj_incoming:', 'kd-object-incoming', 'STASH_TTL_SECONDS = 60', 'status=303']
    - path: frontend/tests/lib/objectRef.test.ts
      all_of: ['postObjectToTab']
claims:
  - subject: tab-private ref registry key
    literal: "export const REGISTRY_KEY = 'kd_object_refs'"
  - subject: active-ref pointer key
    literal: "export const ACTIVE_KEY = 'kd_object_active'"
  - subject: one-shot incoming meta name
    literal: "export const INCOMING_META = 'kd-object-incoming'"
  - subject: server-side stash key prefix
    literal: 'return f"obj_incoming:{sub}"'
---

# No object identity in any SPA URL

Object identity (kind/name/namespace) is UI state, not a shareable
credential: it never appears in a URL — not query, not path — so Referer
headers, browser history, error reporters, and proxy logs carry route
paths only. (ADR-0040; supersedes the 2026-10-28 `?name=` +
`?namespace=` navigation.)

**The contract.**

- **In-tab:** the open object is a token-keyed entry in
  `sessionStorage` (`kd_object_refs` registry + `kd_object_active`
  pointer; tokens are 64-bit hex via `crypto.getRandomValues`; entries
  self-expire at 15 min, checked lazily). `src/lib/objectRef.ts` is the
  single seam — views never touch sessionStorage. One route per kind;
  `ObjectRoute` renders the DETAIL only when the active ref's kind
  matches the route's registered kind, the list otherwise.
- **Cross-tab deep link:** the share affordance submits a hidden
  same-origin form **POST** (`name="o"`, token only) to the clean route
  in a new tab; the SPA fallback bounces the POST as a **303**, stashes
  the token in Redis under `obj_incoming:<sub>` (TTL 60 s), and the
  fresh tab's document load receives it as a one-shot
  `<meta name="kd-object-incoming">` (GETDEL — consumed by exactly one
  load; the injected document is `no-store`). The identity payload rides
  a 60 s self-deleting `localStorage` relay (`kd_ref_<token>` + `_exp`);
  the fresh tab lands with `location.search === ''`.
- **Legacy:** old `/.../data?name=...&namespace=...` URLs one-shot
  redirect to the clean route with the ref hydrated (`origin: 'link'`).
- **Filters stay query params** (`?labelSelector=`, `?tab=`) — genuine
  filters, not identity.
- The ref is a **pointer, not a privilege**: a forged or stale ref
  renders a list or a 404; the object read stays SAR-gated (ADR-0004).

**Why.** The 2026-11-04 amendment moved token delivery off the URL
(`?o=` was proven non-functional by the QA gate — a form POST's body
never enters the new document's URL): delivery now rides the server
session.

**Verification (2026-11-06).** Grepped `frontend/src`: no credential or
object identity in URL construction; the only localStorage keys are the
relay plus `kd_notifications` and `kd-cluster-scope` (non-identity
state). `App.tsx` routes: one clean route per kind, `/data` routes
redirect-only.

**Pinned by.** `frontend/tests/lib/objectRef.test.ts` (registry, 15-min
expiry, relay + token-only POST), `frontend/tests/App.test.tsx`
(R7 redirect), `backend/tests/api/test_object_handoff.py` (9 tests: 303
bounce, one-shot meta, every miss path), e2e `ui-smoke.spec.ts`.

**Related.** ADR-0040 (decision + amendment),
`invariants/session-cookie-transport.md` (the `<sub>` is the `kd_access`
JWT subject), `workflows/object-deep-link.md`.
