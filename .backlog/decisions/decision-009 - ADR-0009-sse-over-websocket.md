---
id: decision-009
title: "ADR-0009 SSE over WebSocket for server→client push"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0009-sse-over-websocket.md`

# SSE over WebSocket for server→client push

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

The UI needs server→client push: K8s event timelines, topology
updates, live log tail, cluster health changes, exec/terminal. The
question: one transport for everything (WebSocket), or a split?

#### Decision Drivers

- **Stateless + load-balancer-friendly.** N replicas behind an LB; a
  sticky-session-free push channel keeps the deployment boring.
- **HTTP-native.** SSE rides plain HTTP/1.1 — no upgrade handshake,
  works through every proxy the product has to meet (air-gapped
  environments are full of them).
- **Bidirectional only where it must be.** Exec/terminal needs client
  stdin — that is the one genuinely bidirectional case.

#### Considered Options

- **All-WebSocket.** Rejected: upgrade handshakes are the failure mode
  at proxies; sticky sessions at the LB; one transport for streams that
  are 95% server→client.
- **All-polling.** Rejected: latency + API load on live log tail.
- **SSE primary, WebSocket for exec only (CHOSEN).**

#### Decision Outcome

**Chosen option: SSE for every server→client stream; WebSocket only
for bidirectional exec.**

- SSE endpoints are plain Flask routes (not Smorest) returning
  `text/event-stream` with `Cache-Control: no-cache`; the client uses
  native `EventSource` (auto-reconnect built in). Streams:
  `/events/timeline`, `/events/topology`, `/events/logs`,
  `/events/health`.
- Backpressure: each stream buffers (bounded); a lagging client gets a
  `reconnect` event and re-issues with a fresh `since` cursor.
- Exec/terminal is Flask-SocketIO on `/ws/exec` (gated by the exec
  feature); no long-polling fallback.

##### Consequences

- Good: push survives plain-HTTP LBs; no sticky sessions; the client
  reconnect story is the browser's; one WS path to maintain.
- Bad: SSE is one-way — anything needing stdin is WebSocket; SSE
  streams hold a worker thread for their lifetime (thread-pool sized).
- Confirmation: `backend/tests/api/test_events.py`;
  `backend/app/sockets/` (WS side).

#### Linking Decisions and Constraints

- ADR-0006 — LB-friendliness is a single-container consequence.
- ADR-0001 — SSE routes sit beside Smorest in the same Flask app.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §3.6; verified
against `backend/app/sockets/events.py` and `backend/tests/api/test_events.py`
on 2026-11-06.
