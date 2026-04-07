### PRD: Enhanced Log Viewer

**OpenSpec change**: `openspec/changes/enhanced-log-viewer/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

KubeDash has Socket.IO-based pod log streaming infrastructure (`join_pod_logs` event, `xterm.js` target, K8sService `get_pod_logs()` with `follow=true`) but the current viewer only outputs raw log lines with no interactivity. Enterprise operators and developers need a rich, filterable log viewing experience to debug issues quickly — comparable to `stern`, `lnav`, or commercial K8s dashboards. Without filtering, search, multi-pod aggregation, and export, users fall back to `kubectl logs` or external tools.

#### Goals

- Provide a feature-rich log viewer layered on top of the existing real-time streaming backend
- Enable real-time filtering by log level (DEBUG/INFO/WARN/ERROR/FATAL) and custom regex
- Add client-side full-text search across the displayed log buffer
- Support multi-pod log aggregation (all pods in a Deployment/StatefulSet) into a single unified view
- Enable export/download of current log buffer as text or JSON
- Improve UX with auto-scroll toggle, timestamp toggle, and connection status indicators

#### Functional Requirements

- **Log Level Filtering**: Parse incoming log lines for severity indicators (DEBUG, INFO, WARN, ERROR, FATAL) and filter display based on user selection. Multi-select support with a "showing X of Y lines" counter.
- **Text Search**: Client-side full-text search across the log buffer with match highlighting, next/previous navigation, match count, and case-sensitive toggle.
- **Multi-Pod Aggregation**: Stream logs from all pods matching a label selector or from all pods in a Deployment/StatefulSet/DaemonSet/ReplicaSet into a single view. Each line prefixed with pod name and color-coded.
- **Export/Download**: One-click download of the current log buffer as `.log` (plain text) or `.json` (JSONL) format. Respects active filters. Configurable timestamp inclusion.
- **Auto-Scroll Toggle**: Toggle between auto-scroll (default) and manual scroll. Auto-pause when user scrolls up, auto-resume when user scrolls to bottom.
- **Timestamp Toggle**: Show/hide timestamp column without re-fetching data. Timestamps retained in buffer for re-display.
- **Buffer Management**: Configurable client-side circular buffer (default 10,000 lines, max 50,000). Oldest-line eviction when full. "Load older lines" via existing `join_pod_logs` with `tail_lines` parameter.
- **Multi-Container Support**: Switch between containers in the same pod via dropdown. Buffer cleared on switch with optional keep-previous option.
- **Connection Status**: Visual indicator for states — Connecting (spinner), Streaming (green dot), Disconnected (red dot + reconnect button), Error (banner with message), Completed (gray indicator).
- **Security**: Log access respects KubeDash RBAC and K8s token scoping. All log access logged to audit log. No server-side log caching beyond in-memory stream buffer.

#### Non‑Functional Requirements

- **Performance**: Client-side filtering and search avoid server load. DOM virtual scrolling (or capped rendering) for high-throughput pods (100+ lines/sec). Buffer memory capped at configurable max.
- **Security**: Multi-pod aggregation only gathers pods in authorized namespaces. Log export only includes data already displayed. Existing `join_pod_logs` Socket.IO event remains the sole server-side entry point — no new auth surface.
- **Compatibility**: Must work with existing `join_pod_logs` / `response` / `disconnect` event protocol. No breaking changes to backend.
- **Accessibility**: Log content readable in dark mode. Toolbar controls keyboard-accessible. Color-coded elements use both color and icon/shape for status.

#### Implementation Tasks

- [ ] 1. Core log viewer component (circular buffer, DOM renderer, level detector, filter, main controller)
- [ ] 2. Search (debounced full-text search, match highlighting, navigation) and Export (text/JSON Blob download)
- [ ] 3. Multi-pod log aggregation (API endpoint for pod listing, merged view with color coding)
- [ ] 4. Polish: connection status handling, audit logging, user preferences, responsive layout, performance testing, documentation
