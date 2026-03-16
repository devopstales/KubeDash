## 1. Exec per-connection state and emit

- [ ] 1.1 Replace global wsclient in workload blueprint with a dict keyed by SocketIO connection id (e.g. `exec_streams[sid]`) and pass `request.sid` into `k8sPodExecStream`
- [ ] 1.2 In `k8sPodExecStream`, emit `response` events with `room=sid` (or equivalent) instead of `namespace="/exec"` only, so only the requesting client receives output
- [ ] 1.3 In `exec_input` handler, look up wsclient by `request.sid` and write stdin to that stream; ignore or log if sid not in dict
- [ ] 1.4 On SocketIO `disconnect` for `/exec`, remove the connection’s entry from `exec_streams` and close/clean up the stream if possible

## 2. Exec stream exit and closed event

- [ ] 2.1 In `k8sPodExecStream`, on exception indicating stream closure, break the loop, remove sid from `exec_streams`, and emit a "closed" event to that sid in `/exec` namespace
- [ ] 2.2 In pod-exec template, listen for "closed" (or equivalent) and update UI to show disconnected state (e.g. message or disable input)

## 3. Exec paste

- [ ] 3.1 In pod-exec template, on paste (e.g. Ctrl+V), read clipboard and send the pasted string via `exec-input` (one or more events with full string)
- [ ] 3.2 Ensure server `exec_input` handler accepts multi-character `input` and writes it to wsclient stdin (no change if already supported)

## 4. Log stream per-connection and emit

- [ ] 4.1 Pass `request.sid` into `k8sPodLogsStream` and emit each log line with `room=sid` so only the requesting client receives it
- [ ] 4.2 Add per-connection cancel signal (e.g. `log_cancel[sid]` threading.Event or dict); create it in log `message` handler and pass into the log background task
- [ ] 4.3 In the log task loop, check the cancel signal periodically; when set, exit the loop and clean up the connection’s cancel state
- [ ] 4.4 When client sends a new `message` (new pod/container), set the cancel signal for that sid so the previous log task exits, then start the new stream
- [ ] 4.5 On SocketIO `disconnect` for `/log`, set the cancel signal for that sid (and remove from any state dict) so the log task exits

## 5. Optional exec stop

- [ ] 5.1 Add SocketIO handler for "stop" (or "exec-stop") in `/exec` that sets a stop flag or closes the stream for that sid so the exec loop exits and emit "closed" to that sid
- [ ] 5.2 In pod-exec template, add a "Disconnect" (or similar) button that emits the stop event
