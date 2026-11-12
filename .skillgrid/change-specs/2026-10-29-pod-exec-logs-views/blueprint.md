# Pod Exec (WebSocket) + Log Tail (SSE) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T2 — new real-time transport surface (Socket.IO + SSE) on top of the
existing K8s client; one new npm dependency (`@xterm/xterm`); the wsgi
entrypoint's run path changes (SocketIO-wrapped). No migration, no public
REST contract change (the new endpoints are additive), but it touches the app
factory + the wsgi run path — the load-bearing seam for the whole real-time
layer.

**Classification:** `medium-risk` (the exec websocket is bidirectional and
long-lived — a leak in the reader thread or the k8s socket is a
resource-leak-on-disconnect; the SSE stream must honor the ≤8KB backpressure
bound; the Socket.IO instance must not break the existing Gunicorn `gthread`
deployment). The log tail is low-risk (one-way SSE). The frontend is low-risk
(xterm is a well-trodden integration).

**Build shape:** Tracer thread — Task 1 proves the Socket.IO instance + the
exec namespace end-to-end (app factory → namespace → k8s exec socket → a
client that sends `input`/`resize` and receives `output`) before any
frontend; Task 2 is the SSE log tail endpoint; Task 3 is the xterm exec view;
Task 4 is the log tail view; Task 5 is the pod data page buttons + routing +
the gate. Each task is independently revertable.

**Goal:** Resolve the pod data page's **Exec** (WebSocket terminal) and
**Logs** (SSE tail) buttons to first-class, non-buggy surfaces — fixing 4.1's
proxy-drop polling, missing resize, flaky Ctrl+C, and the copy/paste hack.

**Architecture:**
- **Socket.IO instance** (`app/sockets/__init__.py`): a module-level
  `socketio = SocketIO(async_mode="threading")` singleton, created in the
  existing `app/sockets/__init__.py` (replacing the stub docstring),
  `init_app`'d in `create_app` AFTER `register_apis` and BEFORE
  `register_static`. `wsgi.py` calls `socketio.run(app, ...)` in place of
  `app.run(...)` for the dev path (the Gunicorn `wsgi` module exposes the
  SocketIO-wrapped app — `wsgi = socketio.WSGIApp(app)` or the equivalent so
  Gunicorn serves `/socket.io/*`).
- **Exec namespace** (`app/sockets/exec.py`): a `/ws/exec` namespace. On
  connect: binding gate → SAR (`create` + `get` on `pods/<pod>`, subresource
  `exec`) → open the k8s exec websocket (`kubernetes.stream.stream(
  CoreV1Api().connect_get_namespaced_pod_exec, ..., tty=True,
  _preload_content=False)`). A **per-session reader thread** pumps stdout/
  stderr → `emit("output", {data})` in ≤8KB chunks (replaces 4.1's polled
  `read_all`). `input` event → `wsclient.write_stdin`; `resize` event →
  `wsclient.resize_pty(rows, cols)`. On disconnect/EOF: close the k8s socket +
  stop the reader thread.
- **Log tail SSE** (`app/api/events.py` or `app/sockets/logs.py` → a plain
  Flask route, NOT Smorest, per §3.6): `GET /api/v1/events/logs?cluster=
  &namespace=&pod=&container=&since=` → binding gate → SAR (`get` on
  `pods/<pod>`, subresource `log`) → `read_namespaced_pod_log(follow=True,
  tail_lines=since)` streamed as SSE events, ≤8KB chunks, `{"type": "done"}`
  on EOF, `{"type": "error"}` on failure.
- **Exec gate** (`app/core/config.py`): `Settings.exec_enabled: bool`
  (`KUBEDASH_EXEC_ENABLED`, INI `exec_enabled`, ADR-0028). When false: the
  exec namespace is not registered (or its connect handler closes with
  `EXEC_DISABLED`), and the pod object / a features probe exposes
  `exec_enabled: false` so the Exec button hides.
- **K8s client** (`app/services/k8s_client.py`): two new thin methods —
  `exec_pod(namespace, pod, container)` → the k8s `stream(...)` websocket
  object, and `stream_pod_logs(namespace, pod, container, tail_lines)` → the
  `read_namespaced_pod_log(follow=True)` iterator. These wrap the k8s
  `stream`/`watch` primitives (already available) so the namespace + the SSE
  route don't reach into `kubernetes.stream` directly.
- **Frontend**: `frontend/src/lib/socket.ts` (a thin Socket.IO client wrapper
  over the installed `socket.io-client`), `frontend/src/lib/sse.ts` (a thin
  `EventSource` wrapper), `@xterm/xterm` (+ `@xterm/addon-fit`,
  `@xterm/addon-web-links`, `@xterm/addon-search`) as npm deps, the exec view
  (xterm + key-encoding + resize + copy/paste + container picker), the log
  tail view (SSE + container picker + scrollable `<pre>` + copy), and the two
  buttons on the pod data page.

**Tech Stack:** `flask-socketio` (already a declared dep; threading async
mode — ratified 2026-10-29, NO eventlet/gevent), `kubernetes` `stream` /
`watch` (already available in the client), Flask plain routes for SSE
(`text/event-stream`), React + `socket.io-client` (already a dep) +
`@xterm/xterm` (NEW npm dep — ratified 2026-10-29, air-gapped bundle), no new
Python dependency.

**Spec:** `briefing.md` (R1–R8).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/workload/pod-exec.html.j2`
(xterm.js from a global + `io.connect('/exec')`; `term.onKey(e => socket.emit("exec-input",
{input: e.key}))`; a `customKeyEventHandler` that hacks Ctrl+Shift+C/V for
copy/paste because Ctrl+C is taken by SIGINT and Ctrl+Shift+C by devtools;
FitAddon/WebLinks/SearchAddons loaded but **no `term.onResize` → no resize
emitted to the pty**; the `#terminal` is an append-only div),
`4.1:src/kubedash/templates/workload/pod-log.html.j2` (xterm +
`io.connect('/log')`; init containers listed above regular ones with a
`-----------` separator),
`4.1:src/kubedash/blueprint/workload.py:115-220` (the `/log` + `/exec`
Socket.IO namespaces: `connect`/`message`/`exec-input` handlers;
`start_background_task(k8sPodLogsStream / k8sPodExecStream, ...)`),
`4.1:src/kubedash/lib/k8s/workload.py:547` (`k8sPodLogsStream`:
`watch.Watch().stream(read_namespaced_pod_log, tail_lines=100,
_request_timeout=1)`), `4.1:src/kubedash/lib/k8s/workload.py:571-614`
(`k8sPodExecSocket`: `stream(connect_get_namespaced_pod_exec, command=['/bin/
sh'], stderr=True, stdin=True, stdout=True, tty=True, _preload_content=False,
_request_timeout=1)`; `k8sPodExecStream`: `while True: socketio.sleep(0.01);
wsclient.update(timeout=5); output = wsclient.read_all(); emit("response",
{output})` — **the polled loop that drops bytes through a proxy**),
`4.1:src/kubedash/lib/components.py:31` (`socketio = SocketIO()`),
`4.1:src/kubedash/gunicorn_conf.py:109` (the `/socket.io` log filter). 5.0
in-repo precedents — `.skillgrid/ARCHITECTURE.md:464-485` (§3.6: SSE primary,
WebSocket for exec, the endpoint table, the ≤8KB backpressure bound, the
`features.exec` gate, "Flask-SocketIO over Gunicorn eventlet/gevent workers
— fallback to long-polling NOT enabled"), `backend/app/sockets/__init__.py`
(the stub to replace with the real SocketIO singleton), `backend/app/
sockets/logs.py` + `events.py` (the stub namespaces — `logs` becomes the SSE
tail, `events` stays the events/timeline stub), `backend/app/__init__.py:95-101`
(the `create_app` tail — where `socketio.init_app(app)` goes, AFTER
`register_apis`/`register_health`/`register_errors`/`apidocs` and BEFORE
`register_static`), `backend/app/core/config.py:24` (the `Settings`
BaseSettings — where `exec_enabled: bool` goes, the `resolve_bool` pattern),
`backend/wsgi.py` (the Gunicorn entrypoint — where `wsgi` becomes the
SocketIO-wrapped app), `backend/app/services/k8s_client.py:33-34,212` (the
`kubernetes` import + `self._v1` — where `exec_pod` / `stream_pod_logs` go,
wrapping `kubernetes.stream` / `kubernetes.watch`), `backend/app/core/rbac.py`
(the `rbac.can(...)` SAR helper the exec namespace + SSE route call),
`frontend/package.json:50` (`socket.io-client` already a dep; `@xterm/xterm`
NOT installed — the new dep), `frontend/src/lib/api.ts` (the `apiFetch` + the
auth session the Socket.IO/EventSource clients attach their token to),
`frontend/src/views/Workload/PodData.tsx` (the pod data page that gains the
Exec/Logs buttons — from the `pods-deployments-views` change).

**In-force ADRs:** per `adr.md` — ADR-0004 (the SAR gates the exec socket +
the log read, subresource `exec`/`log`), ADR-0009 (the transport split: SSE
logs / WebSocket exec), ADR-0010 (the read path — the exec/log streams are
per-session, not informer-cache), ADR-0020 (air-gap — `@xterm/xterm` is a
bundled npm dep, no CDN), ADR-0021 (the cluster binding gate), ADR-0028 (the
INI source for `exec_enabled`). None created.

## Terms

None (the spec's vocabulary; "exec" / "log tail" / "Socket.IO" / "SSE" / "xterm"
are established, not new terms).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- The Socket.IO instance is created with `async_mode="threading"` and
  `init_app`'d in `create_app` after `register_apis` / before `register_static`;
  `/socket.io/*` is served by the SocketIO-wrapped app (not the SPA catch-all)
  (`socketio-wired-threading`, `socketio-served-before-static`).
- The exec gate `KUBEDASH_EXEC_ENABLED` (INI `exec_enabled`) defaults per the
  ADR-0028 pattern; when `false` the exec namespace connect closes with
  `EXEC_DISABLED` and the pod data page's Exec button is HIDDEN
  (`exec-gate-off-disables-namespace`, `exec-gate-off-hides-button`).
- `GET /api/v1/events/logs?cluster=&namespace=&pod=&container=&since=` → a
  `text/event-stream` response, `Cache-Control: no-cache`; a bound + SAR-allowed
  user gets `{"type": "log"}` events (≤8KB each) then `{"type": "done"}` on EOF;
  unbound → a `{"type": "error"}` event + close; SAR-deny → a
  `{"type": "error", "code": "RBAC_DENIED"}` event + close (SAR before the
  read); a k8s transport failure → a `{"type": "error", "code":
  "CLUSTER_UNREACHABLE"}` event + close (`logs-sse-200-stream`,
  `logs-sse-sar-denied`, `logs-sse-unbound`, `logs-sse-unreachable`,
  `logs-sse-8kb-chunks`).
- The `/ws/exec` namespace: connect on a bound + SAR-allowed user opens the
  k8s exec websocket and emits `output` events as the shell produces stdout;
  unbound → a close event; SAR-deny → an `RBAC_DENIED` error event + close
  (the SAR is asked BEFORE the k8s socket opens); a k8s transport failure → a
  `CLUSTER_UNREACHABLE` error event + close (`exec-connect-opens-shell`,
  `exec-connect-unbound`, `exec-sar-denied-before-socket`,
  `exec-unreachable`).
- An `input` event `{chars}` writes to the k8s websocket stdin
  (`wsclient.write_stdin` is called with the encoded bytes)
  (`exec-input-writes-stdin`).
- A `resize` event `{cols, rows}` calls `wsclient.resize_pty(rows, cols)`
  (the 4.1-missing capability) (`exec-resize-resizes-pty`).
- On client disconnect or k8s stream EOF the k8s websocket is closed and the
  reader thread is stopped (no leaked threads/sockets) (`exec-disconnect-
  cleans-up`).
- The exec view mounts an xterm terminal with FitAddon + WebLinksAddon +
  SearchAddon; `term.onResize` emits a `resize` event to the server; a key
  handler emits ENCODED sequences (Ctrl+C → `\x03`, Enter → `\r`, arrows →
  ANSI escapes) NOT raw `e.key`; copy/paste is xterm-native (NO Ctrl+Shift
  hack); a container picker reopens the socket on container change; a status
  line shows connecting/connected/disconnected (`exec-view-xterm-addons`,
  `exec-view-resize-emitted`, `exec-view-key-encoding`,
  `exec-view-copy-paste-native`, `exec-view-container-picker`).
- The log tail view uses the native `EventSource` (auto-reconnect), a
  container picker (init above regular with a separator, as in 4.1), a
  scrollable monospace panel (NOT xterm), a Live indicator, a Stop button, and
  a copy-to-clipboard button (`logs-view-eventsource`, `logs-view-
  container-picker`, `logs-view-scrollable-panel`, `logs-view-stop-copy`).
- The pod data page shows the Exec button ONLY when `exec_enabled` is true and
  the pod has containers; the Logs button when the pod has containers; both
  link to `/workload/pods/exec?name=&namespace=` and
  `/workload/pods/logs?name=&namespace=` (`pod-data-exec-button-gated`,
  `pod-data-logs-button`).
- Both new routes are wired + `ProtectedRoute`-gated; no nav leaves; no stub
  removal (`exec-logs-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/sockets/__init__.py` — the real `socketio` singleton (modified,
  replaces the stub).
- `backend/app/sockets/exec.py` — the `/ws/exec` namespace (new).
- `backend/app/api/events.py` (or `app/sockets/logs.py` promoted) — the SSE
  `/api/v1/events/logs` route (new).
- `backend/app/__init__.py` — `socketio.init_app(app)` (modified).
- `backend/app/core/config.py` — `Settings.exec_enabled` (modified).
- `backend/wsgi.py` — the SocketIO-wrapped `wsgi` app (modified).
- `backend/app/services/k8s_client.py` — `exec_pod` + `stream_pod_logs`
  (modified).
- `backend/tests/sockets/test_exec_namespace.py` (new).
- `backend/tests/api/test_events_logs.py` (new).
- `frontend/src/lib/socket.ts` (new) — the Socket.IO client wrapper.
- `frontend/src/lib/sse.ts` (new) — the EventSource wrapper.
- `frontend/package.json` — `@xterm/xterm` + the three addons (modified).
- `frontend/src/views/Workload/PodExec.tsx` (new).
- `frontend/src/views/Workload/PodLogs.tsx` (new).
- `frontend/src/views/Workload/PodData.tsx` — the Exec/Logs buttons
  (modified).
- `frontend/src/App.tsx` — the two routes + the two imports (modified).
- `frontend/tests/views/pod_exec.test.tsx` (new).
- `frontend/tests/views/pod_logs.test.tsx` (new).

**Key links** (critical connections that must work together):
- **The Socket.IO instance is ONE singleton** — `app/sockets/__init__.py`
  exports `socketio`; `create_app` `init_app`s it; `wsgi.py` wraps the app
  with it; the exec namespace registers on it. A second `SocketIO()` instance
  anywhere (e.g. re-created in a test without the same singleton) breaks the
  namespace registration. Tests use the app the factory builds (the
  `init_app`'d instance), not a fresh `SocketIO()`.
- **`socketio.init_app` order** — MUST be after `register_apis` /
  `register_health` / `register_errors` / `apidocs` and BEFORE
  `register_static` (the SPA catch-all must never see `/socket.io/*`).
  Getting the order wrong → the SPA 404-catches the Socket.IO handshake.
- **The exec reader thread must be stopped on disconnect** — the
  `disconnect` handler (and the EOF path) closes the k8s websocket AND joins
  / stops the reader thread. A leaked reader thread per session is a
  resource leak that grows with concurrent execs (the 4.1 failure class).
  The reader thread must be `daemon=True` (so a hung k8s socket doesn't block
  interpreter shutdown) but joined on disconnect for cleanliness.
- **`_preload_content=False` on the exec socket** — the k8s `stream` must be
  opened with `_preload_content=False` (the websocket stays open for
  streaming); with the default the connection is consumed once. This is the
  4.1-critical flag — missing it is a silent no-output exec.
- **The SSE route is NOT Smorest** — §3.6: plain Flask route,
  `text/event-stream`, `Cache-Control: no-cache`. Putting it on a Smorest `Api`
  breaks the streaming (Smoarest wraps the response). It's a `@app.route` (or
  a plain Blueprint route) registered in `create_app`.
- **The SAR is asked BEFORE the k8s call** (exec socket + log read) — ADR-0004,
  the same rule as the resource route: unbound → binding gate first, then the
  SAR (subresource `exec` / `log` on `pods/<pod>`), then the k8s call. A
  SAR-deny must NOT open the k8s socket (test: the `connect_get_namespaced_pod_exec`
  mock is never called on deny).
- **The exec gate is exposed to the client** — the Exec button hides when
  `exec_enabled` is false. The client learns the gate from the pod object
  (`exec_enabled` field) or a `GET /api/v1/features` probe. The gate check on
  the SERVER (namespace not registered / connect closes with `EXEC_DISABLED`)
  is the authority; the client flag is the UX.
- **`@xterm/xterm` is a bundled npm dep** (air-gap, ADR-0020) — the
  `fe-check` air-gap assertion (no `https?://` / `//cdn.` in the bundle) must
  still pass; xterm's CSS is imported as a module (no CDN link). Verify with
  `task fe-check`.
- **The log tail is NOT xterm** — it's a one-way `EventSource` tail rendered
  in a scrollable `<pre>` (the "Live" indicator + Stop + copy). Using xterm
  for logs would imply interactivity the stream doesn't have.

**One-way-door decisions:** The Socket.IO instance in the app factory + the
SocketIO-wrapped wsgi app (the real-time seam for the whole layer — reverting
it removes the exec/logs transport). The `@xterm/xterm` npm dep (air-gapped
bundle). The `KUBEDASH_EXEC_ENABLED` gate (config, reversible).

## Global Constraints

- No new Python dependency — `flask-socketio` is already declared; the k8s
  `stream` / `watch` modules are already in the `kubernetes` client
  (air-gap, ADR-0020).
- ONE new npm dependency — `@xterm/xterm` + `@xterm/addon-fit` +
  `@xterm/addon-web-links` + `@xterm/addon-search` (bundled, air-gapped —
  ratified 2026-10-29). `socket.io-client` is already a dep.
- **`async_mode="threading"`** — NO eventlet/gevent (ratified 2026-10-29);
  the Gunicorn `gthread` worker is unchanged. Long-polling fallback is NOT
  enabled (the §3.6 contract) — `async_mode="threading"` + a real WebSocket
  transport.
- **SSE is plain Flask, not Smorest** — `text/event-stream`,
  `Cache-Control: no-cache`, ≤8KB event chunks (the §3.6 backpressure bound).
- **The exec socket is `_preload_content=False`, `tty=True`, `stdin/
  stdout/stderr=True`, `command=["/bin/sh"]`** (the 4.1 shape, minus the
  `_request_timeout=1`).
- **The SAR is before the k8s call** (exec + log) — ADR-0004, subresource
  `exec` / `log` on `pods/<pod>`, group `""`.
- The exec gate defaults per ADR-0028 (INI `exec_enabled`); dev default `true`,
  prod `false` unless set.
- No `_request_timeout=1` on the long-lived streams (the house rule).
- Conventional commits; spec-zone commits precede code-zone commits; WHY-
  comments on load-bearing invariants (the reader-thread cleanup, the
  `_preload_content=False`, the init_app order, the init-above-regular
  container separator).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly; the xterm types come from `@xterm/xterm`.

## File Structure

- `backend/app/sockets/__init__.py` (modify) — the `socketio =
  SocketIO(async_mode="threading")` singleton (replaces the stub docstring).
- `backend/app/sockets/exec.py` (new) — the `/ws/exec` namespace (connect /
  input / resize / output / disconnect).
- `backend/app/api/events.py` (new) — the SSE `/api/v1/events/logs` plain
  Flask route (the §3.6 contract). (If the team prefers the socket namespace,
  `app/sockets/logs.py` is promoted — but SSE is an HTTP route, so a plain
  Flask route is the §3.6-correct home.)
- `backend/app/__init__.py` (modify) — `socketio.init_app(app)` after
  `register_apis` / before `register_static`.
- `backend/app/core/config.py` (modify) — `Settings.exec_enabled: bool`
  (`KUBEDASH_EXEC_ENABLED`, INI `exec_enabled`).
- `backend/wsgi.py` (modify) — `wsgi` = the SocketIO-wrapped app (so Gunicorn
  serves `/socket.io/*`); the dev `python wsgi.py` path uses
  `socketio.run(...)`.
- `backend/app/services/k8s_client.py` (modify) — `exec_pod(namespace, pod,
  container)` (the k8s `stream(...connect_get_namespaced_pod_exec, ...)`
  websocket) + `stream_pod_logs(namespace, pod, container, tail_lines)` (the
  `read_namespaced_pod_log(follow=True, tail_lines=...)` iterator).
- `backend/tests/sockets/test_exec_namespace.py` (new) — the namespace
  connect/input/resize/output/disconnect tests (a fake k8s exec websocket + a
  fake SAR + the Socket.IO test client).
- `backend/tests/api/test_events_logs.py` (new) — the SSE route tests (a fake
  `stream_pod_logs` iterator + the binding/SAR gates + the ≤8KB chunking +
  the done/error events).
- `frontend/src/lib/socket.ts` (new) — the Socket.IO client wrapper (connect
  with the auth token, the `/ws/exec` namespace, typed `input` / `resize` /
  `output` events).
- `frontend/src/lib/sse.ts` (new) — the EventSource wrapper (the
  `/api/v1/events/logs` URL builder, the typed log/done/error events, the
  auto-reconnect + the Stop).
- `frontend/package.json` (modify) — add `@xterm/xterm`, `@xterm/addon-fit`,
  `@xterm/addon-web-links`, `@xterm/addon-search`.
- `frontend/src/views/Workload/PodExec.tsx` (new) — the xterm terminal (the
  key-encoding, the `onResize` → `resize` event, the copy/paste, the
  container picker, the status line).
- `frontend/src/views/Workload/PodLogs.tsx` (new) — the SSE log tail (the
  container picker with the init-above-regular separator, the scrollable
  `<pre>`, the Live indicator, the Stop, the copy).
- `frontend/src/views/Workload/PodData.tsx` (modify) — the Exec/Logs buttons
  (top-right header, the `exec_enabled` gate on Exec, the has-containers
  guard on both).
- `frontend/src/App.tsx` (modify) — the two routes + the two imports.
- `frontend/tests/views/pod_exec.test.tsx` (new).
- `frontend/tests/views/pod_logs.test.tsx` (new).

---

### Task 1: Backend — Socket.IO instance + the `/ws/exec` namespace (service + namespace + tests)

**SATISFIES:** `socketio-wired-threading`, `socketio-served-before-static`,
`exec-gate-off-disables-namespace`, `exec-connect-opens-shell`,
`exec-connect-unbound`, `exec-sar-denied-before-socket`, `exec-unreachable`,
`exec-input-writes-stdin`, `exec-resize-resizes-pty`, `exec-disconnect-
cleans-up`

**Files:**
- Modify: `backend/app/sockets/__init__.py` (the `socketio` singleton)
- Create: `backend/app/sockets/exec.py` (the `/ws/exec` namespace)
- Modify: `backend/app/__init__.py` (`socketio.init_app`)
- Modify: `backend/app/core/config.py` (`exec_enabled`)
- Modify: `backend/wsgi.py` (the SocketIO-wrapped `wsgi`)
- Modify: `backend/app/services/k8s_client.py` (`exec_pod`)
- Test: `backend/tests/sockets/test_exec_namespace.py` (new)

**Interfaces:**
- Consumes: nothing (first code task — it establishes the real-time seam).
- Produces: the `socketio` singleton (importable by the namespace + wsgi),
  `K8sClient.exec_pod(namespace, pod, container)` (the k8s exec websocket),
  `Settings.exec_enabled`, the `/ws/exec` namespace (connect / input / resize
  / output / disconnect).
- Seam: the Socket.IO test client (`socketio.test_client`) + a fake k8s exec
  websocket (`write_stdin` / `resize_pty` / a stdout/stderr pump) + the
  existing FakeK8s binding/SAR injection pattern.
- Deletion test: remove `socketio.init_app` → the namespace is unreachable
  (the Socket.IO handshake 404s); remove the namespace → the exec connect
  fails; remove `exec_pod` → the connect handler 500s.
- Adapters: 1 (in-process k8s exec socket); no port.

- [ ] **Step 1: Write the failing exec namespace tests** —
  `backend/tests/sockets/test_exec_namespace.py`, using the Socket.IO test
  client + a fake k8s exec websocket:
  - `connect_opens_shell`: a bound + SAR-allowed connect → the fake
    `exec_pod` is called with `(namespace, pod, container)`; the shell's
    stdout is pumped to `output` events.
  - `connect_unbound`: an unbound user → a close event, `exec_pod` NOT called.
  - `sar_denied_before_socket`: SAR deny → an `RBAC_DENIED` error event +
    close; `exec_pod` NOT called (the SAR is before the k8s socket).
  - `unreachable`: a k8s transport failure from `exec_pod` → a
    `CLUSTER_UNREACHABLE` error event + close.
  - `input_writes_stdin`: an `input` event `{chars: "\x03"}` → the fake
    websocket's `write_stdin` is called with `b"\x03"`.
  - `resize_resizes_pty`: a `resize` event `{cols: 100, rows: 30}` → the fake
    websocket's `resize_pty` is called with `(30, 100)`.
  - `disconnect_cleans_up`: a disconnect → the fake websocket is closed + the
    reader thread is stopped (assert no live thread).
  - `exec_gate_off`: with `exec_enabled=False` → the connect closes with
    `EXEC_DISABLED`, `exec_pod` NOT called.
- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/sockets/test_exec_namespace.py -q`.
  Expected: FAIL (no `socketio` singleton / no namespace / no `exec_pod`).
- [ ] **Step 3: Create the `socketio` singleton** — `app/sockets/__init__.py`
  (replace the stub docstring):
  ```python
  """Flask-SocketIO namespaces — per .skillgrid/ARCHITECTURE.md §3.6.

  SSE is the primary push channel (ADR-0009); WebSocket remains for
  bidirectional cases (exec/terminal). ``socketio`` is the single SocketIO
  instance the app factory ``init_app``s (async_mode="threading" — Gunicorn
  gthread, NO eventlet/gevent, ratified 2026-10-29). ``exec`` registers the
  ``/ws/exec`` namespace (gated by ``KUBEDASH_EXEC_ENABLED``); ``logs`` is
  the SSE tail (a plain Flask route, not a namespace)."""
  from flask_socketio import SocketIO

  # threading async mode: keep the Gunicorn gthread worker; each exec session's
  # k8s reader runs in a per-session thread (ratified 2026-10-29). Long-polling
  # fallback is NOT enabled (the §3.6 contract).
  socketio = SocketIO(async_mode="threading")
  ```
- [ ] **Step 4: Add `exec_pod` to `K8sClient`** — `app/services/k8s_client.py`,
  near the other `_v1` methods:
  ```python
  def exec_pod(self, namespace: str, name: str, container: str) -> Any:
      """Open the pod exec websocket (the k8s ``stream`` primitive,
      ``_preload_content=False`` so it stays open for streaming). The caller
      owns the socket: writes stdin, reads stdout/stderr, resizes the pty,
      and closes it on disconnect. A transport failure raises the k8s
      ApiException (the namespace maps it to CLUSTER_UNREACHABLE)."""
      from kubernetes import stream as _k8s_stream
      return _k8s_stream.stream(
          self._v1.connect_get_namespaced_pod_exec,
          name, namespace,
          container=container,
          command=["/bin/sh"],
          stdin=True, stdout=True, stderr=True, tty=True,
          _preload_content=False,
      )
  ```
- [ ] **Step 5: Add the exec gate to config** — `app/core/config.py`:
  ```python
  exec_enabled: bool = Field(default_factory=lambda: ini_config.resolve_bool("exec_enabled"))
  ```
  (the ADR-0028 INI pattern; env `KUBEDASH_EXEC_ENABLED`.)
- [ ] **Step 6: Implement the `/ws/exec` namespace** — `app/sockets/exec.py`:
  ```python
  """The /ws/exec Socket.IO namespace — the bidirectional pod shell
  (ADR-0009: WebSocket for exec). Gated by KUBEDASH_EXEC_ENABLED. A per-session
  reader thread pumps the k8s exec websocket stdout/stderr -> output events in
  <=8KB chunks (replaces 4.1's polled read_all loop). resize -> resize_pty."""
  import threading
  from flask import g
  from flask_socketio import emit

  from app.core import config as _config
  from app.core import rbac
  from app.sockets import socketio
  from app.services import k8s_client as _k8s
  from app.api.resources import _cluster_for  # the binding gate

  _CHUNK = 8192

  class ExecNamespace(socketio.ServerNamespace):
      namespace = "/ws/exec"

      def on_connect(self, environ, auth):
          cluster_id = environ.get("HTTP_X_CLUSTER_ID")  # or from the token
          ns = environ.get("HTTP_X_NAMESPACE")
          pod = environ.get("HTTP_X_POD")
          container = environ.get("HTTP_X_CONTAINER")
          settings = _config.get_settings()
          if not settings.exec_enabled:
              emit("error", {"code": "EXEC_DISABLED"}); self.disconnect(environ["flask.session.sid"])
              return
          user = _current_user(auth); cluster = _cluster_for(user, cluster_id)
          if not rbac.can(user, cluster, "create", f"pods/{pod}", ns, None, "", subresource="exec") \
             or not rbac.can(user, cluster, "get", f"pods/{pod}", ns, None, "", subresource="exec"):
              emit("error", {"code": "RBAC_DENIED"}); self.disconnect(...)
              return
          try:
              ws = _k8s.pool.get(cluster).exec_pod(ns, pod, container)
          except Exception:
              emit("error", {"code": "CLUSTER_UNREACHABLE"}); self.disconnect(...)
              return
          sid = environ["flask.session.sid"]
          session = {"ws": ws, "stop": threading.Event()}
          self._sessions[sid] = session
          self._sessions[sid]["reader"] = threading.Thread(
              target=self._pump, args=(sid,), daemon=True)
          self._sessions[sid]["reader"].start()

      def on_input(self, environ, data):
          s = self._sessions.get(environ["flask.session.sid"])
          if s: s["ws"].write_stdin(data["chars"].encode())

      def on_resize(self, environ, data):
          s = self._sessions.get(environ["flask.session.sid"])
          if s: s["ws"].resize_pty(data["rows"], data["cols"])

      def _pump(self, sid):
          s = self._sessions[sid]
          try:
              while not s["stop"].is_set():
                  out = s["ws"].read_channel(1)  # stdout
                  err = s["ws"].read_channel(2)  # stderr
                  chunk = (out or b"") + (err or b"")
                  if chunk:
                      for i in range(0, len(chunk), _CHUNK):
                          emit("output", {"data": chunk[i:i+_CHUNK].decode(errors="replace")}, to=sid)
          finally:
              self._cleanup(sid)

      def on_disconnect(self, environ):
          self._cleanup(environ["flask.session.sid"])

      def _cleanup(self, sid):
          s = self._sessions.pop(sid, None)
          if s:
              s["stop"].set()
              s["reader"].join(timeout=2)
              try: s["ws"].close()
              except Exception: pass
  ```
  (the exact k8s `stream` websocket read API — `read_channel` / the stdout-
  stderr split — is verified against the installed `kubernetes.stream.WebSocket`
  in the prototype; match the 4.1 `read_all` equivalent. Register:
  `socketio.on_namespace(ExecNamespace())` at import, guarded by
  `settings.exec_enabled`.)
- [ ] **Step 7: Wire the app factory + the wsgi** — `app/__init__.py`: after
  `apidocs.register_asset_routes(app)` and BEFORE `register_static(app)`, add
  `from app.sockets import socketio; socketio.init_app(app)`. `wsgi.py`:
  expose the SocketIO-wrapped app (`wsgi = socketio.WSGIApp(app)` or the
  equivalent) so Gunicorn serves `/socket.io/*`; the dev path uses
  `socketio.run(app, ...)`.
- [ ] **Step 8: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/sockets/test_exec_namespace.py -q`.
- [ ] **Step 9: Commit** —
  `git add backend/app/sockets/__init__.py backend/app/sockets/exec.py backend/app/__init__.py backend/app/core/config.py backend/wsgi.py backend/app/services/k8s_client.py backend/tests/sockets/test_exec_namespace.py`
  `git commit -m "feat(sockets): SocketIO instance (threading) + /ws/exec namespace + exec gate"`

### Task 2: Backend — the SSE log tail endpoint (`/api/v1/events/logs`)

**SATISFIES:** `logs-sse-200-stream`, `logs-sse-sar-denied`,
`logs-sse-unbound`, `logs-sse-unreachable`, `logs-sse-8kb-chunks`

**Files:**
- Create: `backend/app/api/events.py` (the SSE route)
- Modify: `backend/app/services/k8s_client.py` (`stream_pod_logs`)
- Modify: `backend/app/__init__.py` (register the route)
- Test: `backend/tests/api/test_events_logs.py` (new)

**Interfaces:**
- Consumes: Task 1's `socketio` is NOT needed (SSE is plain Flask); the
  existing binding gate + `rbac.can`.
- Produces: `K8sClient.stream_pod_logs(namespace, pod, container, tail_lines)`
  (the `read_namespaced_pod_log(follow=True, tail_lines=...)` iterator) + the
  `GET /api/v1/events/logs` SSE route.
- Seam: the Flask test client with `response.content_type ==
  "text/event-stream"` + a fake `stream_pod_logs` iterator (yields lines,
  then stops) + the binding/SAR gates.
- Deletion test: remove the route → the URL 404s; remove `stream_pod_logs` →
  the route 500s.
- Adapters: 1 (in-process k8s log stream); no port.

- [ ] **Step 1: Write the failing SSE tests** — `backend/tests/api/test_events_logs.py`:
  - `logs_sse_200_stream`: a bound + SAR-allowed GET → `content-type:
    text/event-stream`, `cache-control: no-cache`; the body has `{"type":
    "log"}` events (each ≤8KB) then `{"type": "done"}`.
  - `logs_sse_8kb_chunks`: a stream that yields a >8KB line → split into
    ≤8KB events.
  - `logs_sse_sar_denied`: SAR deny → a `{"type": "error", "code":
    "RBAC_DENIED"}` event + close; `stream_pod_logs` NOT called.
  - `logs_sse_unbound`: unbound → a `{"type": "error"}` event + close.
  - `logs_sse_unreachable`: a k8s transport failure → a `{"type": "error",
    "code": "CLUSTER_UNREACHABLE"}` event + close.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Add `stream_pod_logs` to `K8sClient`**:
  ```python
  def stream_pod_logs(self, namespace: str, name: str, container: str, tail_lines: int = 100):
      """The pod log tail as a follow=True iterator (the k8s
      ``read_namespaced_pod_log`` primitive). The caller (the SSE route)
      iterates line-by-line and closes the generator on disconnect/EOF. A
      transport failure raises the k8s ApiException (the route maps it to
      CLUSTER_UNREACHABLE)."""
      return self._v1.read_namespaced_pod_log(
          name, namespace, container=container, follow=True, tail_lines=tail_lines,
      )
  ```
- [ ] **Step 4: Implement the SSE route** — `app/api/events.py` (a plain
  Flask Blueprint, NOT Smorest, per §3.6):
  ```python
  """SSE event routes — per .skillgrid/ARCHITECTURE.md §3.6. Plain Flask
  routes (NOT Smorest) returning text/event-stream. The log tail is the K8s
  read_namespaced_pod_log(follow=True) streamed in <=8KB chunks."""
  import json
  from flask import Blueprint, Response, stream_with_context
  from app.api._authhook import apply_auth
  from app.core import rbac
  from app.services import k8s_client as _k8s
  from app.api.resources import _cluster_for

  blp = Blueprint("events", __name__, url_prefix="/v1/events")
  _CHUNK = 8192

  def _sse(payload: dict) -> str:
      return f"data: {json.dumps(payload)}\n\n"

  @blp.route("/logs", methods=["GET"])
  def log_tail():
      # binding gate + SAR before the read (ADR-0004)
      ...  # resolve user + cluster; unbound -> yield error event + close
      ...  # rbac.can(user, cluster, "get", f"pods/{pod}", ns, None, "", subresource="log")
      def gen():
          try:
              lines = _k8s.pool.get(cluster).stream_pod_logs(ns, pod, container, tail_lines)
              buf = ""
              for line in lines:
                  buf += str(line) + "\n"
                  while len(buf.encode()) > _CHUNK:
                      cut = buf.encode()[:_CHUNK].decode(errors="ignore")
                      yield _sse({"type": "log", "data": cut}); buf = buf[len(cut):]
              if buf: yield _sse({"type": "log", "data": buf})
              yield _sse({"type": "done"})
          except Exception:
              yield _sse({"type": "error", "code": "CLUSTER_UNREACHABLE"})
      return Response(stream_with_context(gen()), mimetype="text/event-stream",
                      headers={"Cache-Control": "no-cache"})
  ```
  (register `blp` in `create_app` after `register_apis` / before
  `register_static`, with `apply_auth`.)
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(events): SSE /api/v1/events/logs pod log tail (follow, <=8KB chunks)"`

### Task 3: Frontend — the xterm exec view + the Socket.IO client lib

**SATISFIES:** `exec-view-xterm-addons`, `exec-view-resize-emitted`,
`exec-view-key-encoding`, `exec-view-copy-paste-native`,
`exec-view-container-picker`

**Files:**
- Modify: `frontend/package.json` (the `@xterm/xterm` + addons)
- Create: `frontend/src/lib/socket.ts` (the Socket.IO client wrapper)
- Create: `frontend/src/views/Workload/PodExec.tsx`
- Test: `frontend/tests/views/pod_exec.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `/ws/exec` namespace + the auth session (the token the
  Socket.IO client attaches).
- Produces: the exec terminal view (the xterm grid wired to the namespace).
- Seam: `socket.io-client` (installed) + `@xterm/xterm` (new) + the `apiFetch`
  auth session.
- Deletion test: removing the view → the route (Task 5) 404s.
- Adapters: 1 (the Socket.IO client); no port.

- [ ] **Step 1: Install the xterm deps** — `cd frontend && corepack pnpm add @xterm/xterm @xterm/addon-fit @xterm/addon-web-links @xterm/addon-search`.
  Verify `task fe-check` still passes (the air-gap assertion — xterm's CSS is
  a module import, no CDN).
- [ ] **Step 2: Write the failing exec view test** — `frontend/tests/views/pod_exec.test.tsx`
  (a mocked Socket.IO client + a mocked xterm Terminal):
  - the view mounts an xterm Terminal with FitAddon + WebLinksAddon +
    SearchAddon loaded.
  - `term.onResize` → the socket emits a `resize` event `{cols, rows}`.
  - a key handler: Ctrl+C → emits `input` `{chars: "\x03"}`; Enter → `{chars:
    "\r"}`; a plain char → `{chars: "a"}` (encoded, NOT raw `e.key`).
  - copy/paste: the view uses xterm's native selection (no Ctrl+Shift
    handler).
  - the container picker: selecting a different container reconnects the
    socket with the new container.
  - the status line: connecting → connected (on the socket `connect` event) →
    disconnected (on `disconnect`).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement the Socket.IO client lib** — `frontend/src/lib/socket.ts`
  (a thin wrapper: `connectExec({cluster, namespace, pod, container})` → a
  Socket.IO client attached to `/ws/exec` with the auth token; typed
  `input` / `resize` / `output` / `error` events; a `disconnect()`).
- [ ] **Step 5: Implement the exec view** — `frontend/src/views/Workload/PodExec.tsx`:
  the xterm Terminal (import `@xterm/xterm/css/xterm.css`), load FitAddon +
  WebLinksAddon + SearchAddon, `term.open(el)`, `fit.fit()` on mount + on
  window resize; `term.onResize(({cols, rows}) => socket.emit("resize",
  {cols, rows}))`; `term.onKey(({key, ctrl, shift, meta}) => socket.emit("input",
  {chars: encodeKey(key, ctrl, shift, meta)}))` (the `encodeKey` helper maps
  Ctrl+C → `\x03`, Enter → `\r`, Tab → `\t`, arrows → `\x1b[A` etc., plain →
  the char); `socket.on("output", ({data}) => term.write(data))`; the
  container picker (a `<select>` from the pod's containers, onChange →
  reconnect); the status line. Copy/paste is xterm-native (no custom
  Ctrl+Shift handler — 4.1's hack is gone).
- [ ] **Step 6: Run, confirm GREEN.**
- [ ] **Step 7: Commit** —
  `git commit -m "feat(frontend): xterm exec view + Socket.IO client (resize + key-encoding + native copy/paste)"`

### Task 4: Frontend — the SSE log tail view

**SATISFIES:** `logs-view-eventsource`, `logs-view-container-picker`,
`logs-view-scrollable-panel`, `logs-view-stop-copy`

**Files:**
- Create: `frontend/src/lib/sse.ts` (the EventSource wrapper)
- Create: `frontend/src/views/Workload/PodLogs.tsx`
- Test: `frontend/tests/views/pod_logs.test.tsx` (new)

**Interfaces:**
- Consumes: Task 2's `/api/v1/events/logs` SSE route.
- Produces: the log tail view (the `EventSource` wired to the scrollable
  panel).
- Seam: the native `EventSource` (auto-reconnect) + the `apiFetch` auth
  (the token in the query or header).
- Deletion test: removing the view → the route (Task 5) 404s.
- Adapters: 1 (the EventSource wrapper); no port.

- [ ] **Step 1: Write the failing log tail view test** —
  `frontend/tests/views/pod_logs.test.tsx` (a mocked EventSource):
  - the view opens an EventSource against
    `/api/v1/events/logs?cluster=&namespace=&pod=&container=`.
  - `{"type": "log"}` events append to the scrollable `<pre>` (auto-scroll to
    the bottom).
  - the container picker: init containers above regular ones with a
    `-----------` separator (4.1's shape); selecting one re-opens the
    EventSource with the new container.
  - a Live indicator (the EventSource `open` state) + a Stop button (closes
    the EventSource) + a copy-to-clipboard button (copies the visible tail).
  - `{"type": "done"}` → the Live indicator stops; `{"type": "error"}` → an
    error line.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement the SSE lib** — `frontend/src/lib/sse.ts` (a thin
  EventSource wrapper: `openLogs({cluster, namespace, pod, container})` → an
  EventSource with the auth; typed `log` / `done` / `error` events; a
  `close()`).
- [ ] **Step 4: Implement the log tail view** —
  `frontend/src/views/Workload/PodLogs.tsx`: the EventSource, the container
  picker (init-above-regular with the separator), the scrollable monospace
  `<pre>` (auto-scroll), the Live indicator, the Stop button, the copy button.
  (NOT xterm — it's a one-way tail.)
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): SSE log tail view (EventSource + container picker + stop/copy)"`

### Task 5: Frontend — pod data page buttons + routing + the gate exposure + full verification

**SATISFIES:** `pod-data-exec-button-gated`, `pod-data-logs-button`,
`exec-logs-routes-wired`, `exec-gate-off-hides-button`

**Files:**
- Modify: `frontend/src/views/Workload/PodData.tsx` (the Exec/Logs buttons)
- Modify: `frontend/src/App.tsx` (the two routes + the two imports)

**Interfaces:**
- Consumes: Tasks 3–4's views + the `exec_enabled` flag (from the pod object
  or a `/api/v1/features` probe).
- Produces: the two buttons on the pod data page (the goal).
- Seam: react-router `Route` + the pod data page header.
- Deletion test: delete the two `Route`s → the paths 404; delete the buttons →
  the pages are unreachable.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the two view imports + the
  two routes (the namespaced data-page pattern):
  ```tsx
  <Route path="/workload/pods/exec" element={<ProtectedRoute><PodExecView /></ProtectedRoute>} />
  <Route path="/workload/pods/logs" element={<ProtectedRoute><PodLogsView /></ProtectedRoute>} />
  ```
- [ ] **Step 2: Add the buttons to the pod data page** — `PodData.tsx`
  (top-right of the page header, as in 4.1's `pod-data.html.j2`): an **Exec**
  button (the terminal icon) → `navigate(`/workload/pods/exec?name=${pod}&namespace=${ns}`)`,
  shown ONLY when `exec_enabled` is true AND the pod has containers; a **Logs**
  button (the list icon) → `navigate(`/workload/pods/logs?name=${pod}&namespace=${ns}`)`,
  shown when the pod has containers. (The `exec_enabled` flag comes from the
  pod object field or a `/api/v1/features` probe — the server gate is the
  authority, the flag is the UX.)
- [ ] **Step 3: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — confirms the xterm
    import + the button wiring compile).
  - `task fe-check` (air-gap — the xterm bundle has no CDN refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green — the exec namespace + the SSE route tests).
  - A manual smoke (dev stack): open a pod data page → click Exec → a shell
    appears (type `ls`, press Ctrl+C → it interrupts, resize the window → the
    pty resizes, select text + Ctrl+C → it copies); click Logs → the tail
    streams, Stop halts it, copy works. (The interactive bits are a manual
    check; the tests cover the wiring + the event contracts.)
- [ ] **Step 4: Commit** —
  `git add frontend/src/views/Workload/PodData.tsx frontend/src/App.tsx`
  `git commit -m "feat(frontend): pod data exec/logs buttons + routes + exec gate"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/sockets/test_exec_namespace.py tests/api/test_events_logs.py -q` — all new tests green.
- `cd frontend && corepack pnpm vitest run tests/views/pod_exec.test.tsx tests/views/pod_logs.test.tsx` — green.
- `task fe-build` + `task fe-check` — green (the xterm bundle is air-gapped).
- `cd backend && uv run pytest -m "not integration" -q` — the full unit suite green (the Socket.IO + SSE additions don't break the existing suite).
- A manual dev-stack smoke: the exec shell works (Ctrl+C interrupts, resize tracks, copy works) and the log tail streams + stops + copies (the three 4.1 bugs are gone).

## Task Dependencies

```
Task 1 (SocketIO + /ws/exec + gate) ──► Task 3 (xterm exec view + socket lib) ──► Task 5 (buttons + routes + verification)
                        (no dep)       └─► Task 2 (SSE log tail) ──► Task 4 (log tail view) ──┘
```

Task 1 first (it establishes the real-time seam — the SocketIO instance the
whole layer depends on). Tasks 2 and 3 are independent of each other (Task 2
is the SSE route, Task 3 is the exec frontend; both consume only the existing
client + Task 1's seam). Task 4 consumes Task 2; Task 5 consumes Tasks 3–4
(the buttons + the routes need the views). Task 5 last.

## Rollback

Each task is one conventional commit and independently revertable. Reverting
Task 5 removes the buttons + routes (self-contained). Reverting Task 4 removes
the log tail view; reverting Task 3 removes the exec view + the xterm deps.
Reverting Task 2 removes the SSE route. **Reverting Task 1 is the big one** —
it removes the SocketIO instance + the exec namespace + the gate + the SocketIO-
wrapped wsgi app (the real-time seam); the exec/logs transport is gone, and
the wsgi reverts to the bare Flask app. Because Task 1 touches the app factory
+ the wsgi run path, its revert must land BEFORE Tasks 2–5 are reverted (or
they reference a missing seam) — revert in reverse task order (5→4→3→2→1).
