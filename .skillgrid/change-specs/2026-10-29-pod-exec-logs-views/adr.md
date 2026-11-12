# Pod Exec (WebSocket) + Log Tail (SSE) — ADR

## Decision Summary

Implement the pod data page's **Exec** (terminal) and **Logs** (log tail)
buttons per the ratified architecture (ADR-0009 / ARCHITECTURE §3.6), fixing
4.1's buggy Socket.IO-through-proxy solution. **Log tail = SSE** — a plain
Flask route `GET /api/v1/events/logs` (`text/event-stream`,
`Cache-Control: no-cache`) streaming
`read_namespaced_pod_log(follow=True, tail_lines=since)` in **≤8KB chunks**
(the §3.6 backpressure bound); the client uses the native `EventSource`
(auto-reconnect). **Exec = WebSocket** — a Socket.IO namespace `/ws/exec`
(Flask-SocketIO over Gunicorn `gthread` + `async_mode="threading"` —
**ratified 2026-10-29**, NO eventlet/gevent), gated by a new
`KUBEDASH_EXEC_ENABLED` flag (the §3.6 `features.exec` gate); the browser uses
**xterm.js** (`@xterm/xterm` + FitAddon/WebLinks/SearchAddons — **ratified
2026-10-29**, a bundled npm dep, air-gap ADR-0020) wired to the namespace. A
new `socketio` singleton is created in the app factory (`init_app` after
`register_apis` / before `register_static`) and the wsgi app is SocketIO-
wrapped so Gunicorn serves `/socket.io/*`. The three 4.1 bugs are fixed:
**resize** (`term.onResize` → `wsclient.resize_pty`, the 4.1-missing
capability that caused the narrow-column dump), **key-encoding** (Ctrl+C →
`\x03`, etc., not raw `e.key`), and **native copy/paste** (xterm mouse
selection + the platform's normal combos, not the Ctrl+Shift hack). The polled
`read_all()` loop (the proxy-drop failure mode) is replaced by a per-session
reader thread that reads as data arrives.

## Decision Context

- **Why the transports split this way (ADR-0009 / §3.6).** Log tail is one-way
  server→client — SSE is the primary push channel: HTTP-native, stateless,
  LB-friendly, no proxy-tunnel problem (the whole reason 4.1's Socket.IO log
  stream was "buggy through the proxy"). Exec is bidirectional (stdin/stdout)
  — WebSocket/Socket.IO is reserved for exactly this. The split is the
  architecture's; this change implements it for pods.
- **Why `async_mode="threading"` and not eventlet (ratified 2026-10-29).**
  ARCHITECTURE §3.6 says "Flask-SocketIO over Gunicorn eventlet/gevent
  workers," but the 5.0 deployment runs Gunicorn `--threads 2` (threaded
  gthread) with no eventlet/gevent. Switching to eventlet monkey-patches the
  entire stack (Flask/RQ/SQLAlchemy) at import time — a large blast radius on
  a working deployment. `async_mode="threading"` keeps the gthread worker
  unchanged; each exec session's k8s reader runs in a per-session (daemon)
  thread, and WebSocket frame delivery works under gthread. The transport
  (WebSocket/Socket.IO) is unchanged — only the worker-class choice is
  superseded. (A prototype verifies the k8s exec stream under gthread; if the
  `websocket-client` under gthread proves incompatible, the fallback is
  `async_mode="eventlet"` — a one-line change, the ADR's literal path.)
- **Why xterm.js (ratified 2026-10-29).** 4.1 used xterm from a CDN global
  (air-gap violation) and never integrated resize/copy properly. 5.0 bundles
  `@xterm/xterm` + its addons as an npm dep (the air-gapped bundle, ADR-0020)
  and integrates them: FitAddon (fit + `onResize` → the pty), WebLinks,
  Search. xterm is the industry-standard terminal emulator — a real grid with
  scrollback (the "dump to scroll" feel is gone by construction) and native
  mouse-selection copy/paste (the Ctrl+Shift hack is gone).
- **Why a per-session reader thread (not 4.1's polled loop).** 4.1's
  `k8sPodExecStream` runs `while True: socketio.sleep(0.01);
  wsclient.update(timeout=5); output = wsclient.read_all(); emit(...)` — a
  fixed-cadence poll with a 5s update timeout that drops/misorders/stalls
  bytes behind a reverse proxy. 5.0's reader thread reads the k8s websocket
  as data arrives and emits ≤8KB-chunked events (no poll cadence, no 5s
  timeout) — the proxy-drop failure mode is removed. The thread is `daemon`
  (a hung k8s socket doesn't block shutdown) and is joined + the socket
  closed on disconnect/EOF (no leaked threads/sockets — 4.1's failure class).
- **Why the SAR is before the k8s call (ADR-0004).** The exec socket and the
  log read are gated by the same rule as the resource route: binding gate →
  SAR (subresource `exec` / `log` on `pods/<pod>`, group `""`) → the k8s
  call. A SAR-deny never opens the k8s socket (the client call is never made
  on deny).
- **Why the exec gate (`KUBEDASH_EXEC_ENABLED`).** §3.6 gates exec behind
  `features.exec` (exec is a higher-privilege surface — a shell in the pod).
  The gate defaults per ADR-0028 (INI `exec_enabled`; dev `true`, prod `false`
  unless set). When off: the namespace connect closes with `EXEC_DISABLED`
  (the server authority) and the Exec button hides (the client UX, from a
  feature probe / pod-object flag).
- **No `_request_timeout=1` on the long-lived streams.** 4.1 passed a 1-second
  timeout to the exec/log streams (a latent disconnect on a long-lived
  connection); 5.0 uses the pool's configured timeout (the house rule).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | The exec socket + the log read are SAR-gated (subresource `exec` / `log` on `pods/<pod>`, group `""`); the SAR is asked BEFORE the k8s call; deny → an error event + close, the k8s call never made on deny. |
| 0009 | **The transport split this change implements** — SSE for the one-way log tail, WebSocket/Socket.IO for the bidirectional exec. SSE is primary (LB-friendly, no proxy-tunnel problem — the 4.1 bug). |
| 0010 | The exec/log streams are per-session, per-request reads (not the informer-cache read path) — they're the live K8s streams, not cache-derived. |
| 0020 | Air-gap — `@xterm/xterm` + addons are a BUNDLED npm dep (no CDN); `flask-socketio` is already a declared dep; the xterm bundle passes the `fe-check` air-gap assertion. |
| 0021 | The cluster binding gate (404 unbound) before the SAR on both the exec connect and the log tail. |
| 0028 | The INI source for the `exec_enabled` gate (`KUBEDASH_EXEC_ENABLED`, INI `exec_enabled`). |

## Deviations (from 4.1)

1. **Log tail is SSE, not Socket.IO** — 4.1's `/log` Socket.IO namespace
   becomes the `/api/v1/events/logs` SSE endpoint (ADR-0009: SSE is primary
   for one-way server→client streams; LB-friendly, no proxy-tunnel problem).
2. **No polled `read_all()` loop** — 4.1's `socketio.sleep(0.01)` +
   `update(timeout=5)` + `read_all()` (the proxy-drop failure mode) is replaced
   by a per-session reader thread that reads as data arrives + ≤8KB-chunked
   events.
3. **Terminal resize is implemented** — 4.1 had NO `resize` (the narrow-column
   "dump to scroll" bug); 5.0's `term.onResize` → `wsclient.resize_pty(rows,
   cols)` tracks the live grid.
4. **Proper key-encoding, not raw `e.key`** — 4.1 emitted `e.key` per keydown
   (flaky Ctrl+C); 5.0 emits encoded key-sequences (Ctrl+C → `\x03`, Enter →
   `\r`, arrows → ANSI escapes).
5. **xterm-native copy/paste, not the Ctrl+Shift hack** — 4.1's
   Ctrl+Shift+C / Ctrl+Shift+V clipboard hack is replaced by xterm's mouse
   selection + the platform's normal copy/paste.
6. **No `_request_timeout=1` on the long-lived streams** — 5.0 uses the pool's
   configured timeout.
7. **The terminal is a real grid, not an append-only div** — xterm's own
   buffer + scrollback at the live pty width (the "dump to scroll" feel is
   gone by construction).
8. **Exec is gated by `KUBEDASH_EXEC_ENABLED`** (the §3.6 `features.exec`
   flag) — 4.1 had no gate (exec always on).
9. **`async_mode="threading"` (gthread), not eventlet/gevent** (ratified
   2026-10-29) — the ADR's literal "eventlet/gevent workers" is superseded for
   the worker-class choice (the transport — WebSocket/Socket.IO — is
   unchanged); the fallback is `async_mode="eventlet"` if the prototype shows
   the k8s stream is incompatible under gthread.

## Out of Scope

- Exec/logs for kinds other than pods (the pod is the unit; deployments get
  exec via their pod later).
- Multi-terminal / split panes / session persistence (one exec session per
  pod data page visit; reconnect opens a fresh shell — 4.1's behavior).
- `kubectl attach` (this is a fresh `/bin/sh` exec, not attaching to PID 1).
- Port-forward (the k8s `stream.portforward` is out of scope).
- Mid-session JWT rotation (the session authenticates at connect; a JWT expiry
  closes the socket, the client re-auths + reconnects).
- The events/timeline + topology + health SSE streams (the other §3.6 rows —
  the observability change's concern; this change implements only the log
  tail SSE + the exec WebSocket).
