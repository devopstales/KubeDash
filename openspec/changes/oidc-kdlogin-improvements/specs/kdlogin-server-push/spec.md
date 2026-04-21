## ADDED Requirements

### Requirement: Kdlogin push runs only for kdlogin-initiated OIDC

The server SHALL probe the client's kdlogin HTTP endpoint (GET `/info` and, when appropriate, POST kubeconfig) only when the user started OpenID Connect from the kdlogin entry path (e.g. plugin flow via the dedicated kdlogin route). When the user authenticates via standard browser SSO (login page or other entry that does not mark the session as kdlogin), the server SHALL NOT send HTTP requests to the client's loopback for kdlogin discovery or push.

#### Scenario: Kdlogin entry sets session marker

- **WHEN** the user begins OIDC from the kdlogin entry route (e.g. GET `/kdlogin` or equivalent)
- **THEN** the server SHALL set a session-scoped marker before redirecting to the IdP that indicates kdlogin client flow

#### Scenario: Standard login does not probe kdlogin

- **WHEN** the user completes OIDC after starting from standard web login (no kdlogin marker in session)
- **THEN** the server SHALL NOT perform GET or POST to the user's address on the kdlogin listen port for plugin push

#### Scenario: Callback clears marker after handling

- **WHEN** the OIDC callback runs and kdlogin push logic has completed (success, failure, or skip)
- **THEN** the server SHALL clear the kdlogin session marker so subsequent requests do not treat the session as kdlogin unless the user starts again from the kdlogin entry

### Requirement: Observable kdlogin push with logging and OpenTelemetry

The server SHALL record kdlogin push attempts in logs and distributed traces. Failures (timeouts, connection errors, HTTP error responses, or unexpected `/info` payload) SHALL NOT be discarded without a log record at warning or error severity. The server SHALL create an OpenTelemetry span for the kdlogin push operation (including child spans or events for the info probe and config POST as appropriate) and SHALL attach useful attributes (e.g. outcome, HTTP status when available) and record exceptions on failure.

#### Scenario: Failure is logged

- **WHEN** the kdlogin info probe or config POST fails after the flow is gated as kdlogin
- **THEN** the server SHALL emit a structured log entry with severity at least WARNING, including the failure phase and sufficient context to diagnose (e.g. exception type or HTTP status, without leaking secrets)

#### Scenario: Trace covers push

- **WHEN** the server performs kdlogin push for a kdlogin-marked session
- **THEN** an OpenTelemetry span SHALL be created for the operation so that backends can visualize the callback-to-plugin HTTP interaction

### Requirement: Configurable timeouts for kdlogin HTTP client

HTTP requests from the server to the kdlogin plugin (GET `/info` and POST of kubeconfig payload) SHALL use explicit timeouts. Timeout values SHALL be configurable (e.g. application config or environment) with documented defaults.

#### Scenario: Requests do not hang indefinitely

- **WHEN** the server issues GET `/info` or POST to the kdlogin plugin
- **THEN** each request SHALL use a finite timeout derived from configuration

#### Scenario: Operators can tune timeouts

- **WHEN** deployment needs longer or shorter limits for slow or fast networks
- **THEN** operators SHALL be able to adjust timeout settings without code changes (within the same deployment mechanism as other KubeDash settings)
