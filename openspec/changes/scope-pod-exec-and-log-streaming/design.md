## Context

- **Current state:** Pod exec and pod log streaming use Flask-SocketIO namespaces `/exec` and `/log`. The server stores a single global `wsclient` for exec and emits all output with `socketio.emit(..., namespace="/exec")` or `namespace="/log"`, so every client in the namespace receives every message. There are no rooms or per-connection state. Multiple tabs or users therefore share one logical exec stream (stdin and output mixed) and receive all log lines from any active log stream. There is no client-triggered stop for exec or unsubscribe for logs; exec paste only updates the local terminal and is not sent to the container. Key code: `src/kubedash/blueprint/workload/workload.py` (SocketIO handlers), `src/kubedash/lib/k8s/workload.py` (`k8sPodExecSocket`, `k8sPodExecStream`, `k8sPodLogsStream`), and templates `pod-exec.html.j2`, `pod-log.html.j2`.
- **Constraints:** Keep existing SocketIO event names (message, response, exec-input) for compatibility; use Flask-SocketIO’s built-in rooms or emit-by-sid. No new external dependencies. Auth and RBAC remain unchanged (user token/role for K8s API).

## Goals / Non-Goals

**Goals:**

- Scope exec and log streams by SocketIO connection so each tab/connection has its own channel; emit only to the client that started the stream.
- Replace the global exec wsclient with per-connection state keyed by connection id (e.g. `request.sid`).
- Support optional stop for exec and unsubscribe for log stream so switching pod/container or disconnect stops the previous stream for that connection.
- On exec stream death (e.g. pod deleted, network error), break the server loop and notify the client (e.g. "closed" or "error" event).
- Support exec paste: send pasted text to the container via the existing exec-input path (server writes to wsclient stdin).

**Non-Goals:**

- Changing tail_lines or timeout for log streaming; adding UI for them is out of scope.
- Changing the exec command (e.g. to bash or setting TERM) is out of scope.
- Changing auth, RBAC, or validation rules beyond what’s needed for per-connection state.

## Decisions

1. **Scoping mechanism: emit by sid vs rooms**
   - **Decision:** Use `request.sid` as the connection key. When starting an exec or log stream, pass `request.sid` into the background task; emit with `socketio.emit(..., room=request.sid)` (or the equivalent in the task, e.g. store sid and use `room=sid`). Do not require the client to join a named room; the sid is sufficient and avoids extra join/leave logic.
   - **Rationale:** Flask-SocketIO allows emitting to a single session via `room=sid`. One sid per connection; no cross-connection leakage. Simpler than maintaining a custom room name per stream.
   - **Alternative considered:** Create a room per stream (e.g. `exec-{sid}`) and have the client join on connect. Same effect; using sid as room is standard and avoids an extra join step.

2. **Per-connection exec state**
   - **Decision:** Replace the global `wsclient` with a module-level dict, e.g. `exec_streams: dict[str, Any]` keyed by `request.sid`, storing the wsclient (and optionally a "cancel" or "closed" flag for stop). On `message` (start exec), create the stream and store it under `request.sid`. On `exec_input`, look up by `request.sid` and write to that wsclient; if sid not in dict, ignore or log. On disconnect (SocketIO `disconnect`), remove the entry and close the stream if possible so the background task can exit.
   - **Rationale:** Ensures stdin and output are tied to the same connection; multiple tabs each get their own stream. Cleanup on disconnect avoids leaking streams.

3. **Exec stream exit and client notification**
   - **Decision:** In `k8sPodExecStream`, when an exception indicates stream closure (e.g. connection error, pod gone), break the loop, remove the sid from `exec_streams`, and emit an event (e.g. `socketio.emit("closed", {...}, room=sid, namespace="/exec")`) so the client can show "Disconnected". Use a single "closed" event with an optional message; avoid a separate "error" event unless we need to distinguish user-initiated stop from failure.
   - **Rationale:** Stops the task from spinning and gives the UI a clear signal. One event keeps the contract simple.

4. **Log stream: stopping the previous stream**
   - **Decision:** For each connection, maintain a "cancel" flag or event (e.g. a `threading.Event` or a dict `log_cancel: dict[sid, Event]`). When the client sends a new `message` (new pod/container) or disconnects, set the cancel for that sid. The log background task checks the flag periodically (e.g. after each line or every N seconds); when set, exit the loop and clean up. Emit log lines with `room=sid`.
   - **Rationale:** Ensures only one active log stream per connection and stops old streams when the user switches or leaves, without requiring a new "stop" event (message or disconnect is enough). Alternative of killing the thread is harder; a cancel flag is simple and portable.

5. **Exec stop event (optional)**
   - **Decision:** Add an optional SocketIO event (e.g. `stop` or `exec-stop`) that the client can emit when the user clicks "Disconnect". Server sets a "stop" flag for that sid (or closes the wsclient write side / removes from dict) so the exec loop exits and emits "closed". If we do not add a dedicated stop in v1, disconnect alone still cleans up via disconnect handler.
   - **Rationale:** Improves UX (explicit disconnect button). Can be added in the same change or a small follow-up; design supports it either way.

6. **Exec paste**
   - **Decision:** Client: on paste (e.g. Ctrl+V), read clipboard and send the full string in one or more `exec-input` payloads (e.g. one event with `input: pastedText`). Server: `exec_input` handler already receives `data["input"]` and writes to wsclient; accept multi-character input and write it as-is to `wsclient.write_stdin(...)` so the container receives the pasted text. No TTY-specific handling required for basic paste.
   - **Rationale:** Reuses existing exec-input path; only the client must send the pasted string instead of only single keys. Server may need to accept string (not only single char); current code uses `.encode()` so a full string is fine.

## Risks / Trade-offs

- **[Sid in background task]** The background task runs in another thread and does not have `request.sid` in scope. **Mitigation:** Pass `sid` (or a copy) into `k8sPodExecStream` and `k8sPodLogsStream` when starting the task; use that sid for emit `room=sid` and for lookup in exec_streams / log_cancel.
- **[Disconnect race]** Client disconnects while the exec/log task is emitting. **Mitigation:** Emit to room=sid; if the client is gone, SocketIO drops the message. Cleanup in disconnect handler removes the sid from state so we do not leak. No need to check "is client still connected" before every emit.
- **[Cancel flag lifetime]** Log cancel flag must be created before starting the task and cleared when the task exits. **Mitigation:** Create the Event (or dict entry) in the message handler, pass it into the task; task sets it or clears the dict entry on exit. Disconnect handler sets the event so the task exits and then removes the entry.

## Migration Plan

- No data migration. Deploy: ship code changes; existing clients will get scoped behavior (each connection gets its own stream). No API contract change for event names. Rollback: revert code; behavior reverts to global/broadcast (with known multi-tab issues).

## Open Questions

- None.
- Optional: add a small "Disconnect" button for exec that emits "stop" in a follow-up if not in the first implementation.
