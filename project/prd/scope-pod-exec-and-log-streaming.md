### PRD: Scope Pod Exec and Log Streaming

**OpenSpec change**: `openspec/changes/scope-pod-exec-and-log-streaming/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

KubeDash exposes powerful capabilities for:

- Executing commands inside pods (`exec`).
- Streaming pod logs (including live tails).

If not carefully scoped and controlled, these features can:

- Expose users to more pods/namespaces than they are authorized to access.
- Increase the blast radius of compromised credentials.
- Cause excessive load on the Kubernetes API/server when many long‑lived streams are active.

We need tighter **scoping, limits, and observability** around pod exec and log streaming.

#### Goals

- Align exec and log access strictly with Kubernetes RBAC and KubeDash’s own access rules.
- Limit per‑connection behavior (e.g. namespaces, pods, lifetime) in a predictable way.
- Make it easier for security and SRE teams to understand who is doing what and when.

#### Functional Requirements

- Exec (`kubectl exec`‑style) and log streaming endpoints must:
  - Enforce namespace and pod access using the same permission checks used elsewhere in KubeDash.
  - Respect user’s default namespace and any namespace filters configured in KubeDash.
- Introduce **per‑connection policies**, such as:
  - Maximum stream duration (timeout).
  - Maximum number of concurrent exec/log streams per user/session (configurable).
- Improve **auditing**:
  - Log exec and log streaming actions with:
    - User identity.
    - Namespace/pod/container.
    - Command (for exec) or tail options (for logs).
    - Start/end timestamps and status.

#### Non‑Functional Requirements

- **Performance**
  - Streaming must remain responsive and avoid excessive resource use on the KubeDash pod(s).
  - Enforce backpressure or sensible defaults for buffer sizes.
- **Security**
  - Ensure exec and logs use the same user token/context as other K8s calls so Kubernetes RBAC continues to apply.
  - Make it easy for operators to disable exec entirely or restrict it to certain roles/namespaces.

---

### Implementation Tasks (from OpenSpec)

#### 1. Exec Per‑Connection State and Emit

- [x] 1.1 Replace global `wsclient` in workload blueprint with a dict keyed by SocketIO connection id (e.g. `exec_streams[sid]`) and pass `request.sid` into `k8sPodExecStream`.
- [x] 1.2 In `k8sPodExecStream`, emit `response` events with `room=sid` (or equivalent) instead of `namespace="/exec"` only, so only the requesting client receives output.
- [x] 1.3 In `exec_input` handler, look up `wsclient` by `request.sid` and write stdin to that stream; ignore or log if `sid` not in dict.
- [x] 1.4 On SocketIO `disconnect` for `/exec`, remove the connection’s entry from `exec_streams` and close/clean up the stream if possible.

#### 2. Exec Stream Exit and Closed Event

- [x] 2.1 In `k8sPodExecStream`, on exception indicating stream closure, break the loop, remove `sid` from `exec_streams`, and emit a `"closed"` event to that `sid` in `/exec` namespace.
- [x] 2.2 In pod‑exec template, listen for `"closed"` (or equivalent) and update UI to show disconnected state (e.g. message or disable input).

#### 3. Exec Paste

- [x] 3.1 In pod‑exec template, on paste (e.g. Ctrl+V), read clipboard and send the pasted string via `exec-input` (one or more events with full string).
- [x] 3.2 Ensure server `exec_input` handler accepts multi‑character `input` and writes it to `wsclient` stdin (no change if already supported).

#### 4. Log Stream Per‑Connection and Emit

- [x] 4.1 Pass `request.sid` into `k8sPodLogsStream` and emit each log line with `room=sid` so only the requesting client receives it.
- [x] 4.2 Add per‑connection cancel signal (e.g. `log_cancel[sid]` `threading.Event` or dict); create it in log `message` handler and pass into the log background task.
- [x] 4.3 In the log task loop, check the cancel signal periodically; when set, exit the loop and clean up the connection’s cancel state.
- [x] 4.4 When client sends a new `message` (new pod/container), set the cancel signal for that `sid` so the previous log task exits, then start the new stream.
- [x] 4.5 On SocketIO `disconnect` for `/log`, set the cancel signal for that `sid` (and remove from any state dict) so the log task exits.

#### 5. Optional Exec Stop

- [x] 5.1 Add SocketIO handler for `"stop"` (or `"exec-stop"`) in `/exec` that sets a stop flag or closes the stream for that `sid` so the exec loop exits and emit `"closed"` to that `sid`.
- [x] 5.2 In pod‑exec template, add a “Disconnect” (or similar) button that emits the stop event.

