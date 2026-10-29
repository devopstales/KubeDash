@views @pod-exec-logs
Feature: Pod Exec (WebSocket) + Log Tail (SSE)

  As a user of the KubeDash dashboard
  I want a pod exec terminal and a pod log tail
  So that I can shell into a pod and follow its logs without 4.1's buggy proxy path

  Background:
    Given the "prod" cluster is selected
    And the namespace "team-a" is selected
    And the user is bound to the "prod" cluster
    And the user has RBAC permission for the resource
    And exec is enabled

  # ── Socket.IO wiring ─────────────────────────────────────────────────────

  @socketio
  Scenario: The Socket.IO instance is wired in threading mode
    When the app is created
    Then the Socket.IO instance uses async_mode "threading"
    And the Socket.IO namespace /ws/exec is registered
    And /socket.io/* is served by the Socket.IO app (not the SPA catch-all)

  # ── Exec gate ────────────────────────────────────────────────────────────

  @exec-gate
  Scenario: The exec gate off disables the namespace
    Given exec is disabled
    When a client connects to /ws/exec
    Then the connection closes with code "EXEC_DISABLED"
    And the k8s exec socket was not opened

  @exec-gate
  Scenario: The exec gate off hides the exec button
    Given exec is disabled
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the page does not show the Exec button
    And the page shows the Logs button

  # ── Exec namespace (SAR) ─────────────────────────────────────────────────

  @exec-api
  Scenario: The exec connect opens the shell
    Given a pod "web-1" in namespace "team-a"
    When a client connects to /ws/exec with pod "web-1" and container "web"
    Then the k8s exec socket is opened for "web-1" in "team-a" container "web"
    And shell stdout is emitted as "output" events

  @exec-api
  Scenario: The exec connect is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When a client connects to /ws/exec with pod "web-1"
    Then the connection closes with an error
    And the k8s exec socket was not opened

  @exec-api
  Scenario: The exec connect denies SAR before the socket
    Given the user lacks "create" on "pods/web-1" subresource "exec" in namespace "team-a"
    When a client connects to /ws/exec with pod "web-1"
    Then an error event with code "RBAC_DENIED" is emitted
    And the connection closes
    And the k8s exec socket was not opened

  @exec-api
  Scenario: The exec connect is unreachable
    Given the k8s exec socket fails to open
    When a client connects to /ws/exec with pod "web-1"
    Then an error event with code "CLUSTER_UNREACHABLE" is emitted
    And the connection closes

  @exec-api
  Scenario: The exec input writes to stdin
    Given a client is connected to /ws/exec with pod "web-1"
    When the client emits "input" with chars "ls"
    Then the k8s exec socket stdin receives "ls"

  @exec-api
  Scenario: The exec resize resizes the pty
    Given a client is connected to /ws/exec with pod "web-1"
    When the client emits "resize" with cols 100 and rows 30
    Then the k8s exec socket pty is resized to 30 rows and 100 cols

  @exec-api
  Scenario: The exec disconnect cleans up
    Given a client is connected to /ws/exec with pod "web-1"
    When the client disconnects
    Then the k8s exec socket is closed
    And the reader thread is stopped (no leaked thread)

  # ── Exec view (xterm) ────────────────────────────────────────────────────

  @exec-view
  Scenario: The exec view mounts xterm with the addons
    When I open /workload/pods/exec?name=web-1&namespace=team-a
    Then an xterm terminal is rendered
    And the FitAddon, WebLinksAddon and SearchAddon are loaded
    And a status line shows "connecting" then "connected"

  @exec-view
  Scenario: The exec view emits resize on terminal resize
    Given I am on /workload/pods/exec?name=web-1&namespace=team-a
    When the terminal is resized to 80 cols and 24 rows
    Then a "resize" event is emitted to /ws/exec with cols 80 and rows 24

  @exec-view
  Scenario: The exec view encodes keys (not raw e.key)
    Given I am on /workload/pods/exec?name=web-1&namespace=team-a
    When I press Ctrl+C
    Then an "input" event is emitted with chars "\x03"
    When I press Enter
    Then an "input" event is emitted with chars "\r"
    When I press "a"
    Then an "input" event is emitted with chars "a"

  @exec-view
  Scenario: The exec view uses native copy/paste (no Ctrl+Shift hack)
    Given I am on /workload/pods/exec?name=web-1&namespace=team-a
    Then there is no custom Ctrl+Shift+C / Ctrl+Shift+V clipboard handler
    And copying the selection uses the platform's normal copy shortcut

  @exec-view
  Scenario: The exec view container picker reopens the socket
    Given I am on /workload/pods/exec?name=web-1&namespace=team-a
    And the pod has containers "web" and "sidecar"
    When I select the "sidecar" container
    Then the /ws/exec socket reconnects with container "sidecar"

  # ── Log tail SSE (SAR) ───────────────────────────────────────────────────

  @logs-api
  Scenario: The log tail SSE streams the log
    Given a pod "web-1" in namespace "team-a" with logs
    When I send GET /api/v1/events/logs?cluster=prod&namespace=team-a&pod=web-1&container=web
    Then the response content-type is "text/event-stream"
    And the response cache-control is "no-cache"
    And the stream emits {"type": "log"} events
    And the stream ends with {"type": "done"}

  @logs-api
  Scenario: The log tail SSE chunks at 8KB
    Given a pod "web-1" whose log line exceeds 8KB
    When I send GET /api/v1/events/logs?cluster=prod&namespace=team-a&pod=web-1&container=web
    Then each {"type": "log"} event is at most 8KB

  @logs-api
  Scenario: The log tail SSE denies SAR before the read
    Given the user lacks "get" on "pods/web-1" subresource "log" in namespace "team-a"
    When I send GET /api/v1/events/logs?cluster=prod&namespace=team-a&pod=web-1&container=web
    Then the stream emits {"type": "error", "code": "RBAC_DENIED"}
    And the stream closes
    And the k8s log read was not made

  @logs-api
  Scenario: The log tail SSE is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/events/logs?cluster=prod&namespace=team-a&pod=web-1&container=web
    Then the stream emits {"type": "error"}
    And the stream closes

  @logs-api
  Scenario: The log tail SSE is unreachable
    Given the k8s log stream fails
    When I send GET /api/v1/events/logs?cluster=prod&namespace=team-a&pod=web-1&container=web
    Then the stream emits {"type": "error", "code": "CLUSTER_UNREACHABLE"}
    And the stream closes

  # ── Log tail view ────────────────────────────────────────────────────────

  @logs-view
  Scenario: The log tail view streams via EventSource
    When I open /workload/pods/logs?name=web-1&namespace=team-a
    Then an EventSource is opened against /api/v1/events/logs with the pod and container
    And {"type": "log"} events append to a scrollable monospace panel
    And a Live indicator shows the connection state

  @logs-view
  Scenario: The log tail view container picker (init above regular)
    Given a pod "web-1" with init container "init" and container "web"
    When I open /workload/pods/logs?name=web-1&namespace=team-a
    Then the container picker lists "init" above a separator above "web"
    When I select "init"
    Then the EventSource reopens with container "init"

  @logs-view
  Scenario: The log tail view stop and copy
    Given I am on /workload/pods/logs?name=web-1&namespace=team-a
    When I click Stop
    Then the EventSource is closed
    And the Live indicator stops
    When I click copy
    Then the visible tail is copied to the clipboard

  # ── Pod data page buttons ────────────────────────────────────────────────

  @pod-data
  Scenario: The pod data page shows the exec and logs buttons
    Given exec is enabled
    And a pod "web-1" with containers
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the page shows an Exec button linking to /workload/pods/exec?name=web-1&namespace=team-a
    And the page shows a Logs button linking to /workload/pods/logs?name=web-1&namespace=team-a

  @pod-data
  Scenario: The pod data page hides the exec button when exec is disabled
    Given exec is disabled
    And a pod "web-1" with containers
    When I open /workload/pods/data?name=web-1&namespace=team-a
    Then the page does not show the Exec button
    And the page shows the Logs button

  @pod-data
  Scenario: The pod data page hides both buttons when the pod has no containers
    Given a pod "empty-1" with no containers
    When I open /workload/pods/data?name=empty-1&namespace=team-a
    Then the page shows neither the Exec button nor the Logs button

  # ── Routing ──────────────────────────────────────────────────────────────

  @routing
  Scenario: The exec and logs routes resolve
    When I open /workload/pods/exec?name=web-1&namespace=team-a
    Then the page is the exec terminal view
    When I open /workload/pods/logs?name=web-1&namespace=team-a
    Then the page is the log tail view
    And neither path is a nav leaf
    And neither path is a stub
