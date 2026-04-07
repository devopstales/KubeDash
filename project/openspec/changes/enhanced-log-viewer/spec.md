## ADDED Requirements

### Requirement: Enhanced Log Viewer UI

The system SHALL provide an enhanced log viewer component for viewing pod logs served by the existing `join_pod_logs` Socket.IO event in the `/log` namespace. The viewer SHALL render log lines in a scrollable terminal-style panel using either xterm.js or a custom DOM-based renderer and SHALL include the following controls:

- Auto-scroll toggle (enabled by default)
- Timestamp visibility toggle (enabled by default)
- Search input field (empty by default)
- Log level filter multi-select (all levels selected by default)
- Export button (download current buffer)
- Buffer usage indicator (shows lines displayed / max buffer)

The viewer SHALL receive log line events from the Socket.IO `response` event scoped to the user's connection (`room=request.sid`) and append each line to the client-side buffer.

#### Scenario: Default log view loads
- **WHEN** user navigates to the log view for a pod/container
- **THEN** the system SHALL connect to `/log` via Socket.IO, send `join_pod_logs` with pod/container details, and begin streaming logs into the viewer with auto-scroll and timestamps enabled

#### Scenario: User toggles auto-scroll off
- **WHEN** user is viewing logs and clicks the auto-scroll toggle to disable it
- **THEN** the system SHALL stop automatically scrolling to the bottom when new log lines arrive
- **AND** a visual indicator SHALL show "Paused — new lines arriving" or equivalent

#### Scenario: User toggles timestamps off
- **WHEN** user clicks the timestamp toggle
- **THEN** the system SHALL hide the timestamp column from displayed logs without re-fetching data
- **AND** the underlying buffer SHALL retain timestamps for re-display when toggle is re-enabled

### Requirement: Log Level Filtering

The log viewer SHALL parse each incoming log line for common severity indicators and filter display based on user-selected levels. The supported log level patterns SHALL include:

| Level | Matched Patterns |
|-------|-----------------|
| DEBUG | `debug`, `DEBUG`, `D `, `dbg` |
| INFO | `info`, `INFO`, `I `, notice, `INF`, `N ` |
| WARN | `warn`, `WARN`, `W `, `WARNING`, warning |
| ERROR | `error`, `ERROR`, `E `, err, `ERR` |
| FATAL | `fatal`, `FATAL`, `F `, panic, `CRITICAL`, `CRIT` |

Lines that do not match any pattern SHALL be classified as "UNKNOWN" and displayed whenever any other level is selected. When the user deselects a level, lines of that level SHALL be hidden from the view (removed from DOM or set to `display: none`) but SHALL remain in the buffer. Re-selecting a level SHALL make previously hidden lines of that level visible again.

#### Scenario: Filter to errors only
- **WHEN** user is viewing logs with all levels selected and then selects only ERROR and FATAL
- **THEN** the system SHALL hide all non-ERROR and non-FATAL lines from the view
- **AND** the buffer SHALL retain all lines for potential re-filtering
- **AND** a counter SHALL show "Showing X of Y lines" where X is visible and Y is total

#### Scenario: Unknown level lines always visible
- **WHEN** log lines contain no recognizable level pattern and all known levels are deselected
- **THEN** "UNKNOWN" level lines SHALL still be displayed

#### Scenario: Regex custom filter
- **WHEN** user enters a text string or regex pattern in the search/filter field
- **THEN** the system SHALL apply an additional filter showing only lines matching the pattern (case-insensitive by default, with a case-sensitive toggle option)
- **AND** the filter SHALL be applied in combination with the level filter (AND logic)

### Requirement: Log Text Search

The log viewer SHALL provide full-text search across all lines in the current client-side buffer. The search SHALL:

- Be incremental (results update as user types, debounced at 300ms)
- Highlight all matches in the viewport with CSS styling (e.g., yellow/green background)
- Display the total match count
- Support "Next Match" and "Previous Match" navigation buttons that scroll to the match and visually distinguish the current match
- Support case-sensitive toggle (default: case-insensitive)
- Clear highlights when the search field is emptied

Search SHALL operate on the visible portion of the buffer (all lines received, not just the currently rendered DOM if virtual scrolling is used). Search does NOT require a server round-trip.

#### Scenario: Search with multiple matches
- **WHEN** user enters "timeout" in the search field and there are 5 matching lines in the buffer
- **THEN** the system SHALL highlight all 5 matches and display "5 matches" in the search bar

#### Scenario: Navigate between matches
- **WHEN** search results are active and user clicks "Next Match"
- **THEN** the system SHALL scroll to the next match after the current selection (or to the first match if none selected), highlight it as the current match (e.g., orange background), and update a "Match X of N" indicator

### Requirement: Multi-Pod Log Aggregation

The system SHALL support streaming logs from multiple pods simultaneously into a single unified view. Multi-pod aggregation SHALL be initiated from a workload-level view (Deployment, StatefulSet, DaemonSet, or ReplicaSet) and SHALL gather logs from all pods belonging to that workload. Each line SHALL be prefixed with the pod name (and optionally container name) for identification. Pod names SHALL be color-coded (assign a consistent color per pod in the session) for visual differentiation.

The multi-pod aggregation SHALL:
- Connect to `join_pod_logs` for each pod/container combination sequentially
- Merge log lines into a single chronologically ordered stream
- Maintain separate per-pod level tracking so filtering works globally across all pods
- Respect the same buffer management limits regardless of pod count

Multi-pod aggregation SHALL use the existing `join_pod_logs` Socket.IO mechanism — one connection instance per pod/stream, all scoped to the same user session.

#### Scenario: View all pods in a Deployment
- **WHEN** user is viewing a Deployment detail page and clicks "View All Logs"
- **THEN** the system SHALL identify all pods belonging to that Deployment, start log streams for each pod/container, and merge output into a single unified view

#### Scenario: Multi-pod color coding
- **WHEN** logs from 3 pods are displayed in a multi-pod view
- **THEN** each pod's name prefix SHALL have a distinct, consistent color throughout the session (e.g., Pod A = blue, Pod B = green, Pod C = purple)

#### Scenario: Pod added during multi-pod view
- **WHEN** a new pod is created for the workload while the multi-pod log view is active
- **THEN** the system SHALL offer to include logs from the new pod (or auto-include if auto-discovery is enabled)

### Requirement: Log Export / Download

The log viewer SHALL provide an export function that downloads the current log buffer as a text file. The export SHALL:

- Include all lines in the buffer (respecting current filter state — exported lines match what is visible)
- Support timestamp format toggle (include timestamps as received, include ISO-formatted timestamps, or no timestamps)
- Use a filename based on the log source: `<namespace>_<pod>_<container>_<timestamp>.log` for single-pod, or `<namespace>_<workload-kind>_<workload-name>_<timestamp>.log` for multi-pod
- Support export formats: `.log` (plain text with newline delimiters) and `.json` (one JSON object per line with timestamp, pod, container, and message fields)
- Perform the export entirely client-side (no server round-trip required)
- Handle large buffers efficiently (use Blob and URL.createObjectURL for download)

#### Scenario: Export single pod logs
- **WHEN** user clicks "Export" while viewing logs for pod `my-app-abc123` in namespace `default`
- **THEN** the system SHALL trigger a download of `default_my-app-abc123_2026-04-07-093000.log` with the current buffer contents

#### Scenario: Export respects active filters
- **WHEN** user has filtered to show only ERROR and FATAL lines and clicks "Export"
- **THEN** the system SHALL export only the currently visible filtered lines, not the entire buffer

### Requirement: Log Buffer Management

The client-side log buffer SHALL support a configurable maximum number of lines (default: 10,000). When the maximum is reached, the oldest lines SHALL be evicted (circular buffer behavior). The buffer SHALL:

- Track the total number of lines received (including evicted) and display a "showing X of Y total lines received" indicator
- Support "Load older lines" via the existing `join_pod_logs` mechanism with `tail_lines` parameter (fetch previous N lines from K8s API via a new stream)
- Display a buffer utilization indicator (e.g., "9,200 / 10,000 lines") with a warning color when >80% full
- Support user configuration of max buffer size (1,000 — 50,000 lines, saved in user session or localStorage)

#### Scenario: Buffer reaches capacity
- **WHEN** the user is viewing a high-throughput pod and the buffer reaches 10,000 lines
- **THEN** the system SHALL evict the oldest lines to make room for new ones
- **AND** a counter SHALL show "10,000 shown (2,400 older lines evicted)"

#### Scenario: Load older lines
- **WHEN** the buffer has evicted oldest lines and user clicks "Load older lines"
- **THEN** the system SHALL request the last tail_lines from the K8s log API via Socket.IO and prepend them to the buffer
- **AND** the user SHALL be scrolled to the position where they were viewing (not auto-scrolled to bottom unless auto-scroll was enabled)

### Requirement: Auto-Scroll Behavior

The log viewer SHALL maintain an auto-scroll toggle state (default: ON). When auto-scroll is enabled, the viewport SHALL automatically scroll to the bottom when new log lines are received. When disabled, new lines continue to be received and buffered but the viewport does NOT automatically move. The viewer SHALL display a visual indicator (e.g., a floating "Scroll to Bottom" button or banner) when auto-scroll is disabled and new lines have arrived since the user last scrolled.

#### Scenario: Auto-scroll detects manual scroll
- **WHEN** auto-scroll is enabled and the user manually scrolls up (more than ~5 lines from bottom)
- **THEN** the system SHALL automatically pause auto-scroll and display a "Paused — scroll to bottom to resume" indicator

#### Scenario: Resume auto-scroll
- **WHEN** auto-scroll is paused and the user scrolls to the bottom of the viewer
- **THEN** the system SHALL re-enable auto-scroll

### Requirement: Multi-Container Support

The log viewer SHALL support switching between containers within the same pod without disconnecting the overall view. The user SHALL be able to select a container from a dropdown, and the viewer SHALL stop the current log stream and start a new one for the selected container. The buffer SHALL be cleared when switching containers (with an option to keep previous container's logs).

#### Scenario: Switch containers in multi-container pod
- **WHEN** user is viewing logs for container `app` in a pod and selects container `sidecar-proxy` from the dropdown
- **THEN** the system SHALL stop the current stream for `app`, clear the buffer, and start streaming logs for `sidecar-proxy`

### Requirement: Connection Status and Error Handling

The log viewer SHALL display the connection status to the user. Possible states and their indicators:

| State | Indicator |
|-------|-----------|
| Connecting | "Connecting to log stream..." spinner |
| Streaming | Green dot + "Streaming" |
| Disconnected | Red dot + "Disconnected" with reconnect button |
| Error | Red banner with error message from server (`error` event) |
| Completed | Gray indicator + "Log stream ended (pod may have terminated)" |

When the Socket.IO connection drops, the viewer SHALL attempt automatic reconnection (using Socket.IO's built-in reconnect mechanism) and display a "Reconnecting..." indicator. If reconnection fails after 3 attempts, it SHALL display a manual reconnect button.

#### Scenario: Pod terminates while streaming
- **WHEN** the user is streaming logs and the pod is deleted or terminates
- **THEN** the K8s log API SHALL close the stream, the server SHALL emit a `log_stream_ended` event (or Socket.IO `disconnect`), and the viewer SHALL show "Log stream ended — pod may have terminated"

### Requirement: Security and Access Control

All log viewing operations SHALL respect the existing KubeDash RBAC model and Kubernetes RBAC enforcement:

- The `join_pod_logs` event SHALL continue to check namespace access before starting a stream
- Multi-pod aggregation SHALL only include pods in namespaces the user has access to
- Log export SHALL only include data already displayed in the viewer (no server-side access to non-visible logs)
- Log data SHALL NOT be persisted to disk on the KubeDash server (no caching beyond the in-memory stream buffer)
- All log access SHALL be logged to the KubeDash audit log (user, namespace, pod, container, timestamp)

#### Scenario: User lacks namespace access
- **WHEN** a user attempts to view logs for a pod in a namespace they don't have access to
- **THEN** the system SHALL reject the Socket.IO `join_pod_logs` event with an error message and display "Access denied" to the user
