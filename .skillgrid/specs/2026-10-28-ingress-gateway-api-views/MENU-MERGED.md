# Menu Merge — Standalone Page Superseded (2026-11-07)

**Status:** SUPERSEDED (route/nav shape) — ADR-0022 amendment, 2026-11-07
(owner decision).

This spec's standalone `/network/gateway-api` page is no longer a standalone
route: the three Gateway API kinds (Gateway, HTTPRoute, ReferenceGrant) are
now TABS of the Ingress page at `/network/ingress` (Ingresses | Gateways |
HTTPRoutes | ReferenceGrants) — 4.1's `network/ingress.html.j2` tab pattern.
The old URL redirects one-shot to `/network/ingress`.

The gateway-kind detail views (GatewayApiData) render on `/network/ingress`
via the active-ref dispatcher (App.tsx `IngressRoute`). The ADR-0040 object
navigation contract is unchanged: session-scoped ref, clean URL, same-route
re-render.

Where this spec's artifacts name the standalone route, the tabbed standalone
page, or the `Gateway API` nav leaf, treat them as describing the pre-merge
shape; the merged layout follows ADR-0022 (amendment 2026-11-07) and
`frontend/src/_nav.tsx` (Network group: Services, Ingress, Ingress Class).
