# Menu Merge — Standalone Page Superseded (2026-11-07)

**Status:** SUPERSEDED (route/nav shape) — ADR-0022 amendment, 2026-11-07
(owner decision).

This spec's standalone `/network/gateway-class` page is no longer a
standalone route: GatewayClasses is now a TAB of the Ingress Class page at
`/network/ingress-class` (IngressClasses | GatewayClasses) — 4.1's
`network/ingress-class.html.j2` tab pattern. The old URL redirects one-shot
to `/network/ingress-class`.

The gatewayclass detail view (GatewayClassData) renders on
`/network/ingress-class` via the active-ref dispatcher (App.tsx
`IngressClassRoute`). The ADR-0040 object navigation contract is unchanged:
session-scoped ref, clean URL, same-route re-render.

Where this spec's artifacts name the standalone route or the `Gateway Class`
nav leaf, treat them as describing the pre-merge shape; the merged layout
follows ADR-0022 (amendment 2026-11-07) and `frontend/src/_nav.tsx` (Network
group: Services, Ingress, Ingress Class).
