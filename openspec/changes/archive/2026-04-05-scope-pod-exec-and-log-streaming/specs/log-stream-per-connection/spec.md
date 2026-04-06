## ADDED Requirements

### Requirement: Log stream is scoped by SocketIO connection

The system SHALL associate each pod log stream with exactly one SocketIO connection (session id). The server SHALL emit log line events only to the client that started that stream (e.g. emit to `room=request.sid`). Multiple clients connected to `/log` SHALL each receive only the log lines for the stream they started.

#### Scenario: Single client receives only its log stream

- **WHEN** client A connects to namespace `/log` and sends `message(podName, containerName)` to start a log stream
- **THEN** all `response` events containing log data for that stream are delivered only to client A

#### Scenario: Multiple clients have independent log streams

- **WHEN** client A is tailing pod P1 and client B is tailing pod P2, both connected to `/log`
- **THEN** client A receives only lines from P1 and client B receives only lines from P2; no interleaving or cross-delivery

### Requirement: Previous log stream is stopped when client starts a new stream or disconnects

The system SHALL support stopping the log stream for a connection when that connection sends a new `message` (new pod/container) or disconnects. The server SHALL use a per-connection cancel signal (e.g. flag or event) so the background task for the previous stream exits and SHALL emit log lines only for the current stream for that connection.

#### Scenario: New message stops previous stream

- **WHEN** client A first sends `message(pod1, container1)` and then sends `message(pod2, container2)` before disconnecting
- **THEN** the server stops emitting log lines for (pod1, container1) to client A and starts emitting only lines for (pod2, container2) to client A

#### Scenario: Disconnect stops stream

- **WHEN** client A had an active log stream and then disconnects from `/log`
- **THEN** the server stops the log background task for that connection (e.g. via cancel flag or cleanup) so it does not continue emitting
