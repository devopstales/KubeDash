## ADDED Requirements

### Requirement: Exec stream is scoped by SocketIO connection

The system SHALL associate each pod exec stream with exactly one SocketIO connection (session id). The server SHALL emit exec output only to the client that started that stream (e.g. emit to `room=request.sid`). The server SHALL store exec stream state (e.g. wsclient) keyed by connection id and SHALL route `exec-input` events to the wsclient for the connection that sent the event.

#### Scenario: Single client receives only its exec output

- **WHEN** client A connects to namespace `/exec` and sends `message(podName, containerName)` to start exec
- **THEN** all `response` events containing exec output for that stream are delivered only to client A

#### Scenario: Multiple clients have independent exec streams

- **WHEN** client A and client B are connected to `/exec` and each has started an exec stream (possibly different pods/containers)
- **THEN** client A receives only output from A’s stream and client B receives only output from B’s stream; `exec-input` from A is written only to A’s stream and from B only to B’s stream

#### Scenario: Exec input is routed by connection

- **WHEN** client A has an active exec stream and sends `exec-input` with key data
- **THEN** the server writes that data to the wsclient associated with client A’s connection id, not to any other connection’s stream

### Requirement: Exec stream cleanup on disconnect or stream death

The system SHALL remove per-connection exec state when the client disconnects from the `/exec` namespace. When the exec stream dies (e.g. pod deleted, network error), the server SHALL break the exec read loop, remove the connection’s state, and SHALL emit a "closed" (or equivalent) event to that connection so the client can show disconnected state.

#### Scenario: Cleanup on disconnect

- **WHEN** a client that had an active exec stream disconnects from `/exec`
- **THEN** the server removes that connection’s exec state (e.g. wsclient) and the background task for that stream can exit or is no longer used

#### Scenario: Client notified when stream dies

- **WHEN** the exec stream for a connection ends due to error or pod termination
- **THEN** the server emits a "closed" (or equivalent) event to that connection’s room/sid so the UI can display that the session ended

### Requirement: Exec paste sends text to the container

The system SHALL allow the client to send pasted text (multiple characters) to the exec stream. The server SHALL accept `exec-input` payloads whose `input` field is a string of one or more characters and SHALL write that string to the exec stream’s stdin so the container receives the pasted content.

#### Scenario: Paste is delivered to container

- **WHEN** the client emits `exec-input` with `input` set to a multi-character string (e.g. pasted from clipboard)
- **THEN** the server writes that string to the wsclient stdin for that connection so the container’s shell receives the pasted text

### Requirement: Optional exec stop

The system MAY support a "stop" (or "exec-stop") SocketIO event that the client can emit to request closing the exec session. When the server receives stop for a connection that has an active exec stream, it SHALL close or signal that stream so the read loop exits and SHALL emit "closed" to that connection.

#### Scenario: User-initiated stop

- **WHEN** the client emits a stop event and that connection has an active exec stream
- **THEN** the server stops the exec stream for that connection and emits "closed" to that connection
