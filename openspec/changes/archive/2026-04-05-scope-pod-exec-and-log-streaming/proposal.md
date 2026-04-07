## Why

Pod exec (interactive shell) and real-time log streaming use Flask-SocketIO namespaces `/exec` and `/log` but emit to every client in the namespace. There is no per-connection scoping: a single global exec stream is stored per process, and all log output is broadcast to all connected clients. As a result, multiple tabs or users share one logical channel—stdin can go to the wrong session, output is mixed or sent to the wrong viewer, and there is no way to stop a stream when switching pod/container. This makes exec and log streaming unreliable and confusing in multi-tab or multi-user use.

## What Changes

- **Scope exec and log streams by SocketIO connection:** Use rooms or `request.sid` so each browser tab/connection has its own logical channel. Emit response events only to the client that started the stream.
- **Replace global exec wsclient:** Store exec stream state (e.g. wsclient) keyed by connection id so `exec-input` is written to the correct stream and multiple sessions do not overwrite each other.
- **Add optional stop for exec:** Allow the client to signal "stop" so the server can break the exec loop and clean up; on stream death (pod deleted, network error), break the loop and notify the client (e.g. "closed" or "error" event).
- **Add optional stop/unsubscribe for log stream:** When the client switches pod/container or disconnects, stop the previous log stream for that connection (e.g. cancel flag or per-connection task handle) so old streams do not keep emitting.
- **Exec paste support:** Send pasted text to the container (e.g. emit pasted string via `exec-input` so the server writes it to the exec stream), so paste is not only local to the terminal buffer.

## Capabilities

### New Capabilities

- **exec-per-connection**: Pod exec scoped by SocketIO connection: per-connection wsclient (or equivalent) keyed by sid/room, emit exec output only to the requesting client, optional stop event and stream-exit handling, and paste sent to container via exec-input.
- **log-stream-per-connection**: Log streaming scoped by SocketIO connection: emit log lines only to the client that started the stream, and optional stop/unsubscribe so switching pod/container or disconnect stops the previous stream for that connection.

### Modified Capabilities

- None (no existing OpenSpec specs for pod-exec or log streaming).

## Impact

- **Code:** `src/kubedash/blueprint/workload/workload.py` (SocketIO handlers for `/exec` and `/log`, connection/room handling, per-connection state). `src/kubedash/lib/k8s/workload.py` (`k8sPodExecStream`, `k8sPodLogsStream`—pass sid/room for targeted emit; exec loop exit and optional cancel for log task). `src/kubedash/templates/workload/pod-exec.html.j2` (paste: send pasted text via exec-input; optional stop button and "closed"/"error" UI). `src/kubedash/templates/workload/pod-log.html.j2` (optional stop/unsubscribe on container switch or disconnect).
- **APIs:** SocketIO events unchanged (message, response, exec-input); optional new events for "stop" and "closed"/"error" if we add them.
- **Dependencies:** None new. Flask-SocketIO rooms or emit-by-sid are built-in.
