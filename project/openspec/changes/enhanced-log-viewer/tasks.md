## Phase 1: Core Log Viewer Component

- [ ] 1.1 Create `pod-logs.html.j2` Jinja2 template with toolbar (auto-scroll toggle, timestamp toggle, level filter dropdowns), log content area, and status bar
- [ ] 1.2 Implement `static/js/log_viewer/log_buffer.js` — circular buffer with configurable max lines, eviction tracking, and `getFilteredLines()` method
- [ ] 1.3 Implement `static/js/log_viewer/log_renderer.js` — DOM-based renderer with styled log lines (timestamps, level colors, pod prefix support), auto-scroll logic
- [ ] 1.4 Implement `static/js/log_viewer/log_level_detector.js` — regex-based log level detection from line text (DEBUG, INFO, WARN, ERROR, FATAL patterns)
- [ ] 1.5 Implement `static/js/log_viewer/log_filter.js` — level filter with multi-select and custom regex filter with case sensitivity toggle
- [ ] 1.6 Implement `static/js/log_viewer/log_viewer.js` — main controller connecting Socket.IO `/log` events to buffer, filter, and renderer
- [ ] 1.7 Implement `static/js/log_viewer/log_init.js` — initialization script that reads config from template data attributes, instantiates LogViewer, and wires up toolbar controls
- [ ] 1.8 Add UI routes in workloads blueprint for log view page (or enhance existing log template)
- [ ] 1.9 Write unit tests for LogBuffer (add, evict, getFilteredLines, totalReceived tracking)
- [ ] 1.10 Write unit tests for LogLevelDetector (pattern matching for common log formats)

## Phase 2: Search and Export Features

- [ ] 2.1 Implement `static/js/log_viewer/log_search.js` — client-side full-text search across buffer with debounced input (300ms), match highlighting, next/previous navigation, match count display
- [ ] 2.2 Add search bar UI to `pod-logs.html.j2` toolbar with input, clear button, match count, and navigation arrows
- [ ] 2.3 Implement `static/js/log_viewer/log_exporter.js` — client-side export with text and JSON format options, filename generation, Blob-based download
- [ ] 2.4 Add Export button to log viewer toolbar with format dropdown (text/JSON) and timestamp options
- [ ] 2.5 Implement "Load older lines" functionality via new `join_pod_logs` call with `tail_lines` parameter (prepends to buffer, preserves scroll position)
- [ ] 2.6 Add buffer utilization indicator to status bar (showing "X / Y lines" with warning color at >80%)
- [ ] 2.7 Write unit tests for LogSearch (match detection, navigation, highlight management, clear)
- [ ] 2.8 Write unit tests for LogExporter (filename generation, text formatting, JSON formatting, Blob creation)

## Phase 3: Multi-Pod Log Aggregation

- [ ] 3.1 Implement `static/js/log_viewer/multi_pod_aggregator.js` — coordinates multiple LogViewer instances, merges output into single chronological view with pod name prefix and color coding
- [ ] 3.2 Add `GET /api/v1/workloads/<kind>/<name>/pods` endpoint to workloads API blueprint (returns pod list for Deployment/StatefulSet/DaemonSet/ReplicaSet with containers info)
- [ ] 3.3 Create "View All Logs" button on workload detail pages (Deployment, StatefulSet, DaemonSet, ReplicaSet) that opens multi-pod log view
- [ ] 3.4 Implement multi-pod log view template with workload name header, pod selector, and merged log display
- [ ] 3.5 Add pod name prefix coloring with consistent per-pod color assignment across session
- [ ] 3.6 Implement auto-discovery toggle for new pods appearing during multi-pod session (polling every 30s or event-based via existing Socket.IO)
- [ ] 3.7 Add per-pod log level tracking and global filter application across all pods
- [ ] 3.8 Write integration tests for multi-pod API endpoint with mocked K8s responses

## Phase 4: Polish, Security, and Documentation

- [ ] 4.1 Add connection status indicator with states (connecting, streaming, disconnected, error, completed) and reconnect button
- [ ] 4.2 Implement Socket.IO disconnect/reconnect handling with existing reconnect mechanism
- [ ] 4.3 Add audit logging for log access in Socket.IO `join_pod_logs` handler (user, namespace, pod, container, timestamp)
- [ ] 4.4 Implement user preference storage for log viewer settings (buffer size, auto-scroll default, timestamp visibility, favorite log levels) using localStorage
- [ ] 4.5 Add CSS styles for log viewer (dark mode compatible), level coloring, search highlights, toolbar layout
- [ ] 4.6 Implement responsive layout for tablet screens (collapsible toolbar, full-width log area)
- [ ] 4.7 Write functional tests for log view page rendering with mocked Socket.IO events
- [ ] 4.8 Performance test with 10,000-log-line buffer and high-throughput simulated stream
- [ ] 4.9 Write user documentation: using the log viewer, filtering, search, export, multi-pod mode
- [ ] 4.10 Add feature flag for progressive rollout (enable via `kubedash.ini` config)
