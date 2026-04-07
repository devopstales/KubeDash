## Why

KubeDash has Socket.IO-based pod log streaming infrastructure (`join_pod_logs` event, `xterm.js` terminal target, K8sService `get_pod_logs()` with `follow=true`), but the current viewer only outputs raw log lines with no interactivity. Enterprise operators and developers need a rich, filterable log viewing experience to debug issues quickly — comparable to `stern`, `lnav`, or commercial K8s dashboards. Without filtering, search, multi-pod aggregation, and export capabilities, users are forced to fall back to `kubectl logs` or external tools, defeating KubeDash's purpose as a unified dashboard.

This change implements a feature-rich log viewer UI layered on top of the existing real-time streaming backend (OpenSpec specs: `log-stream-per-connection`). The existing Socket.IO rooms architecture, per-connection state management, and `request.sid` routing remain the backbone — this change adds the UX capabilities on top.

## What Changes

- **Enhanced Log Viewer UI**: Replace or augment the current raw log output with a xterm.js-based or custom DOM-based log renderer supporting filtering, search, auto-scroll toggles, and timestamp controls.
- **Text Search**: Client-side full-text search within displayed log buffer with match highlighting, jump-to-next/previous, and match count display.
- **Log Level Filtering**: Real-time parse-and-filter by common log levels (DEBUG, INFO, WARN, ERROR, FATAL) and custom regex patterns.
- **Multi-Pod Log Aggregation**: Stream logs from all pods matching a label selector or from all pods in a Deployment/ReplicaSet into a single view with pod name prefixes.
- **Export / Download**: Client-side export of the current log buffer as a text file, with options for timestamp inclusion/exclusion.
- **Auto-Scroll Toggle**: Toggle between "follow" auto-scroll (new lines push viewport to bottom) and manual scroll mode for reviewing earlier output.
- **Timestamp Toggle**: Show/hide timestamp column in the log display without re-fetching data (timestamps always captured server-side).
- **Buffer Management**: Configurable client-side line buffer (max 10,000 lines) with oldest-line eviction to prevent browser memory issues on long-running streams.
- **No Breaking Changes**: Existing `join_pod_logs` Socket.IO event, `/log` namespace, and per-connection architecture remain unchanged. All enhancements are client-side features or additive backend endpoints.

## Capabilities

### New Capabilities

- `enhanced-log-viewer-ui`: Rich log viewer component with xterm.js or DOM-based rendering, auto-scroll toggle, timestamp toggle, search bar, and filter controls
- `log-level-filtering`: Real-time filtering of displayed log lines by severity level (DEBUG/INFO/WARN/ERROR/FATAL) with multi-select support
- `log-text-search`: Client-side full-text search across displayed log buffer with match highlighting, navigation, and count
- `multi-pod-log-stream`: Aggregate log streaming from multiple pods (by label selector, Deployment, StatefulSet, or DaemonSet) into a single unified view with per-pod color coding
- `log-export`: One-click download of current log buffer as `.log` or `.txt` file with configurable timestamp format
- `log-buffer-management`: Client-side circular buffer with configurable max size (default 10,000 lines), oldest-line eviction, and buffer usage indicator

### Modified Capabilities

- `log-stream-per-connection` (existing spec): No changes to the connection scoping. The `response` events continue to emit with `room=request.sid`. The enhanced viewer is a new consumer of these events.
- `join_pod_logs` (Socket.IO event): Remains unchanged. Enhanced viewer sends the same message format.

## Impact

- **Affected code**: New JavaScript modules in `static/js/log_viewer/`, new Jinja2 template for enhanced log view (`pod-logs.html.j2` or enhanced existing template), possible new API endpoint for multi-pod pod listing
- **APIs**: No new REST API endpoints required for v1 (all filtering/search/export is client-side). May add `GET /api/v1/workloads/<kind>/<name>/pods` for multi-pod aggregation
- **Dependencies**: Existing xterm.js (already referenced in architecture for logs); Chart.js already available; no new npm/CDN dependencies if reusing existing
- **Security**: Log export respects user's K8s RBAC scope (only pods they can access). Multi-pod aggregation only gathers pods in authorized namespaces. No new authentication surface.
- **Configuration**: Optional settings for default buffer size, default auto-scroll behavior, default timestamp visibility in user preferences
- **Performance**: Client-side filtering/search avoids server load. Server-side work is limited to multi-pod stream management (multiplexed through existing Socket.IO infra).
