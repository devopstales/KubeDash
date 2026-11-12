# Pod Exec (WebSocket) + Log Tail (SSE) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-29-pod-exec-logs-views`
**Date:** 2026-10-29
**Backlog:** TBD (created with the spec commit)
**ADR:** ADR-0009 already mandates the transports (SSE primary / WebSocket
for bidirectional exec) and ARCHITECTURE.md §3.6 fixes the endpoint shapes —
this change IMPLEMENTS them for pods; no new ADR, no new assumption. (The
exec/transport decision is recorded in `adr.md` as an in-force reference, not
a new decision.)

## Intent

The 5.0 pod data page (the `pods-deployments-views` change) deliberately
deferred the two action buttons 4.1 has at the top-right of the pod data page —
**Exec** (terminal) and **Logs** (log tail) — as "the ADR-0009
bidirectional-channel change, its own spec." **This spec is that change.**

4.1 has a working-but-buggy solution:
- **4.1 exec** (`workload/pod-exec.html.j2` + `blueprint/workload.py`
  `/exec` Socket.IO namespace + `lib/k8s/workload.py:571`
  `k8sPodExecSocket`/`k8sPodExecStream`): a Socket.IO websocket to the K8s
  API server via `stream(...connect_get_namespaced_pod_exec, tty=True,
  _preload_content=False)`, polled in a Socket.IO background task
  (`socketio.sleep(0.01)` + `wsclient.update(timeout=5)` +
  `wsclient.read_all()`), xterm.js in the browser, `socket.emit("exec-input",
  {input: e.key})` on every keydown.
- **4.1 logs** (`workload/pod-log.html.j2` + `/log` Socket.IO namespace +
  `k8sPodLogsStream` at `workload.py:547`): a Socket.IO stream of
  `watch.Watch().stream(read_namespaced_pod_log, tail_lines=100,
  _request_timeout=1)`.

**The bugs the user reports (and why 5.0 does it differently):**
1. **Buggy through the proxy.** The k8s exec websocket is a long-lived
   `websocket-client` connection polled with a fixed `update(timeout=5)` loop
   inside a Socket.IO background task. Behind a reverse proxy / LB the
   polling cadence + the Socket.IO→K8s hop drops, misorders, or stalls bytes;
   the 1-second `_request_timeout` on a long-lived stream is a latent
   disconnect.
2. **The UI just dumps data to scroll.** **No terminal resize**: 4.1's xterm
   FitAddon computes the local grid but NEVER sends `resize` events to the
   pty (no `term.onResize` → `socket.emit("resize", ...)`), so the remote
   shell believes it's a tiny fixed-width terminal. Output is emitted in
   narrow, non-wrapping columns → the "dump to scroll" feel. There is also no
   backpressure: every `read_all()` chunk is emitted as a whole blob.
3. **No Ctrl+C, no normal copy/paste.** 4.1 emits `e.key` on every keydown —
   a real Ctrl+C (SIGINT, `\x03`) is flaky because the browser/devtools eat
   the combo; copy/paste was hacked to **Ctrl+Shift+C / Ctrl+Shift+V** because
   the browser takes Ctrl+C and devtools take Ctrl+Shift+C. There is no
   xterm-native clipboard integration and no proper key-sequence encoding.

**5.0 does it per the ratified architecture** (ADR-0009 / ARCHITECTURE §3.6):
- **Log tail = SSE** — `GET /api/v1/events/logs?cluster=&ns=&pod=&container=&since=`
  (a plain Flask route, `text/event-stream`, `Cache-Control: no-cache`, the
  client uses the native `EventSource` with built-in auto-reconnect). The
  server streams `CoreV1Api().read_namespaced_pod_log(..., follow=True)` in
  **≤ 8 KB chunks** (the §3.6 backpressure contract). This is one-way
  server→client — no bidirectional channel, no websocket, no proxy-tunnel
  problem (SSE is HTTP-native and LB-friendly — the whole reason ADR-0009 made
  it primary).
- **Exec = WebSocket** — a Socket.IO namespace `/ws/exec` (Flask-SocketIO over
  Gunicorn `gthread` + `async_mode="threading"`; **ratified 2026-10-29** —
  keep the threaded worker, no eventlet monkey-patching). Gated by
  `KUBEDASH_EXEC_ENABLED` (the §3.6 `features.exec` flag). The browser uses
  **xterm.js** (`@xterm/xterm`, **ratified 2026-10-29** — bundled npm dep,
  air-gap, ADR-0020) with **FitAddon + WebLinksAddon + SearchAddon** (4.1's
  same addon set, now properly integrated). This fixes all three 4.1 bugs:
  - **Resize**: `term.onResize` → emit a `resize` event → the server calls
    the k8s websocket's `resize_pty(rows, cols)`, so the pty tracks the local
    terminal grid (no more narrow-column dump).
  - **Ctrl+C / key sequences**: a proper key handler emits **encoded
    key-sequences** (Ctrl+C → `\x03`, Enter → `\r`, arrows → escape codes,
    plain chars → their UTF-8), not raw `e.key`. Copy/paste is xterm-native
    (mouse selection + the platform's normal Ctrl+C/Cmd+C copy,
    Ctrl+Shift+V/Cmd+V paste) — no Ctrl+Shift hack.
  - **No dump-to-scroll**: xterm's own grid + scrollback (a real terminal
    buffer with line wrapping at the live pty width), not a raw append-only
    div.

The pod data page GAINS the two action buttons (Exec, Logs) — Exec opens the
terminal, Logs opens the tail — both wired to the transports above.

Deliver: a working, non-buggy pod **exec terminal** (WebSocket, xterm,
resize + proper key/copy/paste) and a **log tail** (SSE, `follow=True`, ≤8KB
chunks), so the pod data page's Exec/Logs buttons resolve to first-class
surfaces instead of 4.1's buggy proxy path.

## Requirements

### R1 — A Socket.IO instance wired into the app (threading async)

The app factory (`create_app`) MUST create a `flask_socketio.SocketIO`
instance with `async_mode="threading"` and `init_app(app)` it (ratified
2026-10-29 — keep Gunicorn's threaded `gthread` worker; NO eventlet/gevent
monkey-patching). The instance MUST be a module-level singleton in
`app/sockets/__init__.py` (importable by the exec namespace handlers and the
wsgi entrypoint, which calls `socketio.run` in place of bare `app.run` for the
dev path; the Gunicorn `wsgi` app is served by the SocketIO-wrapped ASGI/WSGI
adapter). The exec namespace is registered on it. The instance is created
AFTER `register_apis` and BEFORE `register_static` (so the SPA catch-all never
sees `/socket.io/*`). No new Python dependency (`flask-socketio` is already a
declared dep).

### R2 — An exec gate: `KUBEDASH_EXEC_ENABLED`

A new `Settings.exec_enabled: bool` (env `KUBEDASH_EXEC_ENABLED`, INI
`exec_enabled` per ADR-0028, default `true` in dev, `false` unless set in
prod — the §3.6 `features.exec` gate). When **disabled**: the exec Socket.IO
namespace is NOT registered (connect → a `{"type": "error", "message": "exec
disabled"}` close event), the pod data page's **Exec button is HIDDEN**, and
the exec endpoint answers 503 `EXEC_DISABLED` on a direct GET probe. When
**enabled**, the namespace is registered and the button shows.

### R3 — The exec WebSocket namespace (`/ws/exec`)

A Socket.IO namespace `/ws/exec` MUST serve a bidirectional pod shell:
- **Connect**: the client connects with `cluster`, `namespace`, `pod`,
  `container` (query or auth-token-verified session). The server (a) verifies
  the cluster binding (unbound → 404-equivalent close) and (b) runs a SAR on
  `create` + `get` for `pods/<pod>` in the namespace (the exec verb — k8s
  models exec as `pods/exec` subresource; the SAR asks `create` on `pods`
  with subresource `exec`, group `""`). On deny → a `{"type": "error",
  "code": "RBAC_DENIED"}` event + disconnect (the SAR is asked BEFORE the
  K8s exec socket opens, per ADR-0004). On success the server opens the k8s
  exec websocket: `kubernetes.stream.stream(CoreV1Api().connect_get_namespaced_pod_exec,
  pod, namespace, container=container, command=["/bin/sh"], stdin=True,
  stdout=True, stderr=True, tty=True, _preload_content=False)` — held open for
  the session.
- **Input (client → server)**: an `input` event `{chars}` → the server writes
  the encoded bytes to the k8s websocket's stdin (`wsclient.write_stdin`).
- **Resize (client → server)**: a `resize` event `{cols, rows}` → the server
  calls `wsclient.resize_pty(rows, cols)` on the k8s websocket (the 4.1-missing
  capability that fixed the narrow-column dump).
- **Output (server → client)**: a dedicated reader thread (per session) pumps
  the k8s websocket's stdout/stderr → emits an `output` event `{data}` per
  chunk (≤ 8 KB per event, the §3.6 chunk bound) to the connected client. This
  replaces 4.1's polled `socketio.sleep(0.01)` + `read_all()` loop with a
  thread that reads as data arrives (no fixed poll cadence, no 5s update
  timeout — the proxy-drop failure mode).
- **Disconnect / EOF**: on client disconnect or k8s stream EOF the server
  closes the k8s websocket and stops the reader thread (no leaked threads /
  sockets). A k8s transport failure → an `{"type": "error", "code":
  "CLUSTER_UNREACHABLE"}` event + disconnect (not a silent hang).

### R4 — The exec terminal view (xterm.js)

`/workload/pods/exec?name=<pod>&namespace=<ns>` MUST render an xterm.js
terminal wired to the `/ws/exec` namespace:
- **Addons**: FitAddon (fit to the container + `onResize` → emit `resize`),
  WebLinksAddon, SearchAddon (4.1's set, now integrated).
- **Key handling**: a key handler that emits ENCODED sequences to the server
  (Ctrl+C → `\x03`, Enter → `\r`, Tab → `\t`, arrows/escape → ANSI escape
  codes, printable → the UTF-8 char) — NOT raw `e.key`.
- **Copy/paste**: xterm-native — mouse selection + the platform's normal copy
  (Ctrl+C / Cmd+C) and paste (Ctrl+Shift+V / Cmd+V). NO 4.1 Ctrl+Shift hack.
- **Container picker**: a dropdown of the pod's containers (from the pod's
  `spec.containers` / `init_containers`) — connecting to a different container
  reopens the exec socket.
- **Status line**: connecting / connected / disconnected (4.1's status span,
  kept).
- The terminal is a REAL grid with scrollback (not an append-only div) — the
  "dump to scroll" bug is gone by construction (xterm's own buffer at the live
  pty width).

### R5 — The log tail SSE endpoint

`GET /api/v1/events/logs?cluster=<id>&namespace=<ns>&pod=<name>&container=<c>&since=<n>`
MUST be a plain Flask route (NOT Smorest — the §3.6 contract) returning
`text/event-stream` with `Cache-Control: no-cache`. The server:
- verifies the cluster binding (unbound → a `{"type": "error"}` SSE event +
  close) and SARs `get` on `pods/<pod>` with subresource `log` (group `""`);
  on deny → a `{"type": "error", "code": "RBAC_DENIED"}` event + close (SAR
  before the read, ADR-0004).
- streams `CoreV1Api().read_namespaced_pod_log(pod, ns, container=c,
  follow=True, tail_lines=<since or 100>)` line-by-line, emitting each line as
  an SSE event, **buffered in ≤ 8 KB chunks** (the §3.6 backpressure bound).
- on stream EOF / container exit → a `{"type": "done"}` event + close; on a
  k8s transport failure → a `{"type": "error", "code":
  "CLUSTER_UNREACHABLE"}` event + close.
- `since` = a `tail_lines` value (default 100, as in 4.1); the §3.6 `since`
  cursor re-issue contract is honored for the follow stream.

### R6 — The log tail view

`/workload/pods/logs?name=<pod>&namespace=<ns>` MUST render the log tail
wired to the SSE endpoint:
- the native `EventSource` (auto-reconnect built-in) against
  `/api/v1/events/logs?cluster=&namespace=&pod=&container=`.
- a container picker (the pod's containers + init containers, as in 4.1's log
  page — init containers listed above the regular ones with a separator).
- the tail rendered in a monospace, read-only, scrollable panel (a `<pre>`
  with the `log`/`text` hljs grammar or a plain `<pre>`; xterm is NOT used for
  logs — it's a one-way tail, not a terminal). A "Live" indicator (the SSE
  connection state) + a Stop button (closes the `EventSource`).
- **Copy**: a copy-to-clipboard button for the visible tail (read-only, no
  terminal editing needed).

### R7 — The pod data page buttons

The pod data page (`/workload/pods/data`) MUST gain the two 4.1 action
buttons (top-right of the page header, as in 4.1's `pod-data.html.j2`):
- **Exec** (the terminal icon) → navigates to
  `/workload/pods/exec?name=<pod>&namespace=<ns>`. **Shown ONLY when
  `KUBEDASH_EXEC_ENABLED` is true** (the client reads the gate from a
  capability flag the pod data fetch exposes, or a `/api/v1/features` probe);
  hidden when exec is disabled.
- **Logs** (the list icon) → navigates to
  `/workload/pods/logs?name=<pod>&namespace=<ns>`. Shown whenever the pod has
  containers.
- Both buttons appear only when the pod has containers (4.1's
  `{% if pod_data.containers %}` guard).

### R8 — Routing + the exec gate flag exposure

- `App.tsx` wires the two new routes (`/workload/pods/exec`,
  `/workload/pods/logs`) as `ProtectedRoute` views.
- The exec gate (`KUBEDASH_EXEC_ENABLED`) MUST be exposed to the client (the
  pod data page's pod object carries an `exec_enabled` field, or a
  `GET /api/v1/features` returns `{exec: bool}`) so the Exec button can hide
  itself when the gate is off.
- No nav leaves (the exec/logs pages are reached from the pod data page, not
  the nav — as in 4.1). No stub removal (neither path is in
  `views/Stub/routes.ts`).

## Non-goals

- No exec/logs for any kind other than pods (deployments/containers get exec
  later via their pod; the pod is the unit).
- No multi-terminal / split panes / session persistence (one exec session per
  pod data page visit; reconnect opens a fresh shell — 4.1's behavior).
- No `kubectl attach`-style attach-to-running-process (this is a fresh
  `/bin/sh` exec, as in 4.1 — not attaching to PID 1).
- No port-forward (the k8s `stream.portforward` is out of scope; exec + logs
  only).
- No auth-token rotation mid-session (the session authenticates at connect; a
  JWT expiry mid-session closes the socket, the client re-auths and
  reconnects).
- No e2e smoke addition beyond the existing UI smoke conventions; the exec /
  logs pages are interactive (smoke asserts the routes resolve + the terminal
  / log panel mount, not a live shell session).

## Ratified decisions (2026-10-29; recorded; see `adr.md`)

1. **xterm.js (`@xterm/xterm`) as the terminal lib** — bundled npm dep
   (air-gap, ADR-0020), with FitAddon + WebLinksAddon + SearchAddon (4.1's
   addon set, properly integrated). NOT a CDN global (4.1's approach).
2. **Gunicorn `gthread` + `SocketIO(async_mode="threading")`** — keep the
   threaded worker, NO eventlet/gevent. Each exec session's k8s reader runs in
   a per-session thread. (The ADR's literal "eventlet/gevent" is superseded
   for the worker-class choice by this; the transport — WebSocket/Socket.IO —
   is unchanged.)
3. **Both exec (WebSocket) + log tail (SSE) in this change** — the full
   "exec + logs buttons" surface (the log tail is NOT deferred to the
   observability change, despite ARCHITECTURE.md listing it there — the pod
   data page needs it now, and it's the same K8s `read_namespaced_pod_log`
   primitive).

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. **Log tail is SSE, not Socket.IO** — 4.1's `/log` Socket.IO namespace
   becomes the `/api/v1/events/logs` SSE endpoint (ADR-0009: SSE is primary for
   one-way server→client streams; LB-friendly, no proxy-tunnel problem).
2. **No polled `read_all()` loop** — 4.1's `socketio.sleep(0.01)` +
   `update(timeout=5)` + `read_all()` polling (the proxy-drop failure mode) is
   replaced by a per-session reader thread that reads as data arrives +
   ≤8KB-chunked events.
3. **Terminal resize is implemented** — 4.1 had NO `resize` (the
   narrow-column "dump to scroll" bug); 5.0's `term.onResize` →
   `wsclient.resize_pty(rows, cols)` tracks the live grid.
4. **Proper key-encoding, not raw `e.key`** — 4.1 emitted `e.key` per keydown
   (flaky Ctrl+C); 5.0 emits encoded key-sequences (Ctrl+C → `\x03`, etc.).
5. **xterm-native copy/paste, not the Ctrl+Shift hack** — 4.1's
   Ctrl+Shift+C / Ctrl+Shift+V clipboard hack is replaced by xterm's mouse
   selection + the platform's normal copy/paste.
6. **No `_request_timeout=1` on the long-lived streams** — 4.1 passed a
   1-second timeout to the exec/log streams (a latent disconnect); 5.0 uses
   the pool's configured timeout (the house rule).
7. **The terminal is a real grid, not an append-only div** — xterm's own
   buffer + scrollback at the live pty width (the "dump to scroll" feel is
   gone by construction).
8. **Exec is gated by `KUBEDASH_EXEC_ENABLED`** (the §3.6 `features.exec`
   flag) — 4.1 had no gate (exec always on).
