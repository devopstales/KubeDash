---
type: BusinessWorkflow
title: "Object deep link: in-tab open and cross-tab share (form-POST + 303 + one-shot meta)"
description: "How a K8s object is opened in the SPA (sessionStorage ref) and shared across tabs (hidden form POST, SPA-fallback 303 bounce, obj_incoming Redis stash, one-shot kd-object-incoming meta, localStorage relay adoption) with the URL staying clean. (ADR-0040.)"
tags: [object-navigation, deep-link, workflow, adr-0040]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: frontend/src/lib/objectRef.ts
      all_of: ['openObject', 'postObjectToTab', 'consumeIncoming']
    - path: backend/app/core/object_handoff.py
      all_of: ['obj_incoming:', 'getdel', 'status=303']
    - path: frontend/src/components/ObjectRoute.tsx
      all_of: ['ref.kind === kind', 'consumeIncoming']
---

# Object deep link (in-tab + cross-tab)

K8s object identity never rides a URL (ADR-0040). This is how an object
gets opened and shared under that constraint.

## In-tab open

1. A list-row name link calls `openObject(kind, name, ns?)`
   (`frontend/src/lib/objectRef.ts`): mints a 64-bit hex token, writes
   the ref into the `kd_object_refs` registry, sets `kd_object_active`,
   navigates to the **clean** list route (no query string).
2. `ObjectRoute` (one route per kind) renders: the active ref's kind
   matches the route's registered kind → DETAIL with the ref's identity
   (namespace authoritative — the `|| selectedNamespace || 'default'`
   fallback is gone); otherwise the list.
3. Refs self-expire at 15 min (lazy check on render); an expired active
   ref renders the list and clears the pointer.

## Cross-tab share (amended 2026-11-04)

1. The share button (`postObjectToTab`) writes a token-scoped one-shot
   relay into `localStorage` (`kd_ref_<token>` + `_exp`, 60 s) and
   submits a hidden same-origin **form POST** (`name="o"`, token only)
   to the clean route with `target="_blank"`.
2. **Server** (`backend/app/core/object_handoff.py`): the SPA fallback
   bounces the POST as **303** to the same path and stashes the token in
   Redis under `obj_incoming:<sub>` (the `kd_access` JWT subject; TTL
   60 s = the relay window).
3. **Fresh tab**: its first document GET gets the token back as a
   one-shot `<meta name="kd-object-incoming">` injected before
   `</head>` (`GETDEL` — exactly one load consumes it; the injected
   document is `no-store`).
4. **SPA mount**: `ObjectRoute` calls `consumeIncoming()` once and
   sweeps the relay; the registry hydrates, the object renders, and
   `location.search === ''`.

## Failure behavior (every miss path renders the list, never a wrong
object)

Anonymous session, malformed token, expired relay, or second GET → the
meta is absent → the list renders. The token is a pointer, not a
privilege: the object read stays SAR-gated at the API.

## Verification (2026-11-06)

Anchors confirmed in all three sites. Pinned by
`frontend/tests/lib/objectRef.test.ts` (relay write, token-only POST,
15-min expiry), `backend/tests/api/test_object_handoff.py` (303 + stash,
one-shot meta + pop, no-store/no-cache, every miss path — 9 tests), and
the e2e deep-link scenario in `frontend/e2e/ui-smoke.spec.ts`.

**Related.** ADR-0040 (decision + amendment),
`invariants/object-nav-no-url-identity.md`,
`invariants/session-cookie-transport.md` (`<sub>` is the JWT subject).
