## Context

KubeDash has a working log viewer in `src/kubedash/templates/workload/pod-log.html.j2` (214 lines)
with an xterm.js-based terminal rendering approach. Current implementation:

**What already exists:**
- xterm.js v4.11.0 already included in `src/kubedash/static/vendor/xterm.js@4.11.0/`
  - With addons: FitAddon, WebLinksAddon, SearchAddon
- Socket.IO `/log` namespace with `message` event (sends podName, containerName)
- Response format: `socket.on('response', msg => term.write(msg.data + "\r\n"))`
- Backend log stream: `k8sPodLogsStream()` in `src/kubedash/lib/k8s/workload.py`
  - Uses `watch.Watch().stream()` on `read_namespaced_pod_log`
  - `tail_lines=100`, `_request_timeout=300`
- Per-connection cancel via `log_cancel` dict with threading.Event
- Disconnect handler sets cancel event
- Container selector dropdown with init container support
- Socket snippet include: `segments/components/socket_snippet.html.j2`
- CSS: CoreUI-based with dark mode support via `[data-coreui-theme="dark"]`
- CSP-compliant inline scripts with nonce

**What's missing (gaps this spec addresses):**
- No log level filtering (raw output only)
- No multi-pod log aggregation
- No export/download functionality
- No auto-scroll toggle (xterm auto-scrolls by default always)
- No timestamp toggle (timestamps come from K8s, no control)
- No buffer management (scrollback=10000 hardcoded, no eviction indicator)
- No search UI (SearchAddon loaded but never invoked from template)
- No connection state feedback beyond "connecting..." / "connected" / "disconnected"

**Key backend details to interface with:**
- Socket event: `socket.send(podName, containerName)` on `/log` namespace
- Response event: `{data: "log line text"}` 
- Disconnect handler: `log_disconnect()` pops and sets cancel event
- `log_message()` handler: validates pod/namespace, cancels previous stream, starts new one
- Backend function signature: `k8sPodLogsStream(username_role, user_token, namespace, pod_name, container, sid, cancel_event)`
- No `join_pod_logs` event name — the current event IS `message` on `/log` namespace

**Constraints:**
- Must maintain compatibility with existing backend Socket.IO `/log` namespace
- Must use xterm.js v4.11.0 already in vendor (NOT v5.x — upgrade would be separate work)
- Must work within Server-rendered Flask + Jinja2 + AJAX paradigm
- Must stay CSP-compliant (nonce-based inline scripts, no eval)
- The current template uses `socket.send()` which is the Socket.IO `message` event shorthand

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Browser                        │
│                                                  │
│  ┌───────────────────────────────────────────┐  │
│  │         Enhanced Log Viewer Component     │  │
│  │  ┌─────────┐ ┌─────────┐ ┌────────────┐  │  │
│  │  │ Filter  │ │ Search  │ │ Auto-Scroll│  │  │
│  │  │ Bar     │ │ Bar     │ │ Toggle      │  │  │
│  │  └─────────┘ └─────────┘ └────────────┘  │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │        Log Buffer (Array)          │  │  │
│  │  │  [{timestamp, line, level,         │  │  │
│  │  │    pod, container, visible}]       │  │  │
│  │  └──────────────┬──────────────────────┘  │  │
│  │                 │ render                    │  │
│  │  ┌──────────────▼────────────────────┐    │  │
│  │  │       xterm.js or DOM Renderer     │    │  │
│  │  └────────────────────────────────────┘    │  │
│  └───────────────────────────────────────────┘  │
│           │                                      │
│           │ Socket.IO (existing)                 │
│           │ join_pod_logs / response             │
│           ▼                                      │
├───────────────────────────────────────────────────┤
│  Flask Backend (existing, unchanged)              │
│                                                   │
│  Socket.IO /log namespace:                        │
│    join_pod_logs → start_log_stream()             │
│    response events → room=request.sid             │
│                                                   │
│  K8sService:                                      │
│    get_pod_logs(follow=true) streaming            │
└───────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. LogViewer (Main Component)

The central controller that:
- Manages the Socket.IO connection lifecycle (join/leave/ reconnect)
- Receives log lines and pushes them into the LogBuffer
- Dispatches to the renderer on buffer changes
- Handles UI state (auto-scroll, timestamp visibility, active filters)

```javascript
class LogViewer {
  constructor(options) {
    this.socket = io('/log');
    this.buffer = new LogBuffer(options.maxLines || 10000);
    this.renderer = new LogRenderer(options.container, options.useXterm);
    this.filter = new LogFilter();
    this.search = new LogSearch(this.buffer, this.renderer);
    this.autoScroll = true;
    this.showTimestamps = true;
    this.connectionState = 'disconnected';
  }

  connect(podName, container, namespace) {
    this.socket.emit('join_pod_logs', {
      podName, container, namespace
    });
  }

  onLogLine(data) {
    const entry = this.buffer.add(data);
    if (this.filter.matches(entry) && !this.search.active) {
      this.renderer.append(entry);
    }
    if (this.autoScroll) {
      this.renderer.scrollToBottom();
    }
  }
}
```

### 2. LogBuffer (Client-Side Circular Buffer)

Manages the in-memory log line store:

```javascript
class LogBuffer {
  constructor(maxLines = 10000) {
    this.lines = [];
    this.maxLines = maxLines;
    this.totalReceived = 0;
    this.evicted = 0;
  }

  add(data) {
    const entry = this.parse(data);
    entry.index = this.totalReceived;
    if (this.lines.length >= this.maxLines) {
      this.lines.shift();
      this.evicted++;
    }
    this.lines.push(entry);
    this.totalReceived++;
    return entry;
  }

  parse(data) {
    return {
      timestamp: Date.now(),
      line: data.text || data,
      level: LogLevelDetector.detect(data.text || data),
      visible: true
    };
  }

  getFilteredLines(filter) {
    return this.lines.filter(l => filter.matches(l));
  }

  getAllLines() { return [...this.lines]; }
}
```

### 3. LogFilter

Handles level filtering and custom regex filtering:

```javascript
class LogFilter {
  constructor() {
    this.activeLevels = new Set(['DEBUG','INFO','WARN','ERROR','FATAL','UNKNOWN']);
    this.textPattern = null;
    this.caseSensitive = false;
  }

  setLevels(levels) { this.activeLevels = new Set(levels); }
  setSearchPattern(pattern, caseSensitive = false) {
    this.textPattern = pattern ? new RegExp(pattern, caseSensitive ? 'g' : 'gi') : null;
    this.caseSensitive = caseSensitive;
  }

  matches(entry) {
    if (!this.activeLevels.has(entry.level)) return false;
    if (this.textPattern && !this.textPattern.test(entry.line)) return false;
    return true;
  }
}
```

### 4. LogLevelDetector

Static utility for parsing log level from line text:

```javascript
const LogLevelDetector = {
  PATTERNS: {
    FATAL:   /^(DEBUG\s+)?(FATAL|PANIC|CRIT|CRITICAL|F\s)/i,
    ERROR:   /^(DEBUG\s+)?(ERROR|ERR|E\s)/i,
    WARN:    /^(DEBUG\s+)?(WARN|WARNING|W\s)/i,
    INFO:    /^(DEBUG\s+)?(INFO|INF|I\s|NOTICE|N\s)/i,
    DEBUG:   /^(DEBUG|DBG|D\s)/i,
  },

  detect(line) {
    for (const [level, regex] of Object.entries(this.PATTERNS)) {
      if (regex.test(line)) return level;
    }
    return 'UNKNOWN';
  }
};
```

### 5. LogRenderer

Renders buffered entries to the DOM. Two implementation modes:

**Mode A: xterm.js** — Uses xterm.js terminal as the rendering surface. Better for very high-throughput logs, supports ANSI color codes from log sources. Requires managing xterm's fit addon for responsive sizing.

**Mode B: Custom DOM** — Uses a `<pre>` or scrollable `<div>` with styled `<span>` elements. Simpler, easier CSS control for timestamps, pod prefixes in multi-pod mode, and search highlighting.

**Decision:** Use Mode B (Custom DOM) as primary renderer. xterm.js is better suited for interactive terminal (exec) use. Log viewing benefits from CSS-based styling, search highlighting, and multi-column layouts. xterm.js may be used as a fallback option.

```javascript
class LogRenderer {
  constructor(containerEl, options) {
    this.container = containerEl;
    this.virtualScroll = options.virtualScroll || false;
    this.podColors = {};
  }

  append(entry) {
    if (!entry.visible) return;
    const el = this.createLineElement(entry);
    this.container.appendChild(el);
    if (this.virtualScroll) {
      this.updateVirtualViewport();
    }
  }

  createLineElement(entry) {
    const row = document.createElement('div');
    row.className = `log-line level-${entry.level.toLowerCase()}`;
    row.dataset.level = entry.level;

    if (options.showTimestamps) {
      const ts = document.createElement('span');
      ts.className = 'log-timestamp';
      ts.textContent = formatTimestamp(entry.timestamp);
      row.appendChild(ts);
    }

    if (entry.pod) {
      const pod = document.createElement('span');
      pod.className = 'log-pod-name';
      pod.style.color = this.getPodColor(entry.pod);
      pod.textContent = `[${entry.pod}] `;
      row.appendChild(pod);
    }

    const msg = document.createElement('span');
    msg.className = 'log-message';
    msg.textContent = entry.line;
    msg.dataset.index = entry.index;
    row.appendChild(msg);

    return row;
  }

  clearSearchHighlights() { /* ... */ }
  highlightMatches(range) { /* ... */ }
  scrollToBottom() { /* ... */ }
  updateVisibility(filter) { /* re-render visible lines */ }

  getPodColor(podName) {
    if (!this.podColors[podName]) {
      const colors = ['#42a5f5','#66bb6a','#ffa726','#ef5350','#ab47bc','#26c6da'];
      const idx = Object.keys(this.podColors).length % colors.length;
      this.podColors[podName] = colors[idx];
    }
    return this.podColors[podName];
  }
}
```

### 6. LogSearch

Client-side search implementation:

```javascript
class LogSearch {
  constructor(buffer, renderer) {
    this.buffer = buffer;
    this.renderer = renderer;
    this.active = false;
    this.currentMatch = -1;
    this.matches = [];
  }

  search(query, caseSensitive = false) {
    if (!query) { this.clear(); return; }
    this.active = true;
    const flags = caseSensitive ? 'g' : 'gi';
    const regex = new RegExp(this.escapeRegex(query), flags);
    this.matches = [];

    for (let i = 0; i < this.buffer.lines.length; i++) {
      const line = this.buffer.lines[i];
      if (regex.test(line.line)) {
        this.matches.push({ lineIndex: i, matchIndex: this.matches.length });
      }
    }
    this.renderer.highlightMatches(this.matches);
  }

  nextMatch() { /* cycle forward */ }
  prevMatch() { /* cycle backward */ }
  clear() { /* reset and remove highlights */ }
}
```

### 7. LogExporter

Client-side export implementation:

```javascript
class LogExporter {
  static exportAsText(entries, options = {}) {
    const lines = entries
      .filter(e => e.visible)
      .map(e => this.formatLine(e, options));
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    this.download(blob, options.filename);
  }

  static exportAsJson(entries, options = {}) {
    const json = entries
      .filter(e => e.visible)
      .map(e => JSON.stringify({
        timestamp: e.timestamp,
        pod: e.pod,
        container: e.container,
        message: e.line,
        level: e.level
      }));
    const blob = new Blob([json.join('\n')], { type: 'application/jsonl' });
    this.download(blob, options.filename);
  }

  static formatLine(entry, opts) {
    let parts = [];
    if (opts.timestamps) {
      parts.push(formatTimestamp(entry.timestamp, opts.tsFormat));
    }
    if (entry.pod) parts.push(`[${entry.pod}]`);
    parts.push(entry.line);
    return parts.join(' ');
  }

  static download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
}
```

### 8. MultiPodAggregator

Coordinates multiple log streams for a workload:

```javascript
class MultiPodAggregator {
  constructor(logViewers) {
    this.viewers = {};  // podName -> LogViewer instance
    this.mergedBuffer = new LogBuffer();
    this.sortQueue = []; // priority queue for chronological merge
  }

  addViewer(podName, container, namespace) {
    const viewer = new LogViewer({...});
    viewer.onLogLine = (data) => this.onLine(podName, container, data);
    viewer.connect(podName, container, namespace);
    this.viewers[podName] = viewer;
  }

  onLine(podName, container, data) {
    const entry = this.mergedBuffer.add({
      ...data,
      pod: podName,
      container: container
    });
    this.mergedBufferRenderer.append(entry);
  }
}
```

## Data Flows

### Single Pod Log Streaming

The actual implementation flow (updated for real backend):

```
User clicks "View Logs" on Pod detail page
    │
    ▼
UI Template: pod-log.html.j2 renders page with inline JS
  - Loads xterm.js v4.11.0 + FitAddon + WebLinksAddon + SearchAddon
  - Creates term = new Terminal({scrollback: 10000})
  - socket = io.connect('/log')
    │
    ▼
Container selector loads containers via:
  GET /api/v1/workloads/pods/{pod_name}/containers?namespace={ns}
  → Response: {data: {containers: [...], init_containers: [...]}}
    │
    ▼
socket.send(podName, containerName)   // sends 'message' event on /log namespace
    │
    ▼
Backend: log_message() handler in workload.py
  - Validates pod_name via validate_pod_name()
  - Validates namespace via validate_namespace()
  - Cancels previous stream: log_cancel.pop(sid).set()
  - Creates new threading.Event, stores in log_cancel[sid]
  - socketio.start_background_task(k8sPodLogsStream, ..., sid, cancel_ev)
    │
    ▼
k8sPodLogsStream() in lib/k8s/workload.py:
  - watch.Watch().stream(read_namespaced_pod_log, ..., tail_lines=100)
  - For each line: socketio.emit("response", {data: str(line)}, room=sid)
    │
    ▼
Browser: socket.on('response', msg => {
  term.write(msg.data + "\r\n");
  logBuffer.add(msg.data);
  applyFilter();
})
    │
    ├─► LogFilter.matches() → show/hide based on level (DOM, not xterm)
    ├─► LogSearch.active → highlight matches via DOM spans
    └─► AutoScroll → term.scrollToBottom() or leave in place
```

### Multi-Pod Log Streaming

```
User clicks "View All Logs" on Deployment detail
    │
    ▼
API call: GET /api/v1/workloads/deployments/<name>/pods
    │
    ▼
Response: [{name, namespace, containers: [...], status}]
    │
    ▼
MultiPodAggregator.create() for each pod/container
    │
    ▼
Each pod opens its own Socket.IO log stream
All streams feed into single MergedLogBuffer
    │
    ▼
Single unified view with pod name prefix and color coding
```

## State Management

```
┌───────────────────────────────────────────┐
│            LogViewer State                │
│                                           │
│  socket: SocketIO connection ref          │
│  buffer: LogBuffer (circular, max lines)  │
│  renderer: DOM or xterm.js ref            │
│  filter: LogFilter (active levels, regex) │
│  search: LogSearch (query, matches)       │
│  autoScroll: boolean                      │
│  showTimestamps: boolean                  │
│  connectionState: 'connecting|streaming   │
│                  |disconnected|error'      │
│  podMeta: {name, namespace, containers}   │
│  isMultiPod: boolean                      │
│  exportFormat: 'text' | 'json'            │
│                                           │
│  Saved to localStorage:                   │
│    - maxBufferLines                        │
│    - defaultAutoScroll                    │
│    - defaultShowTimestamps                │
│    - favoriteLogLevels                    │
└───────────────────────────────────────────┘
```

## Frontend / Backend Split

| Responsibility | Location | Details |
|---------------|----------|---------|
| Socket.IO connection management | Frontend (LogViewer) | Join/leave `/log` namespace, handle reconnect |
| Log line parsing and level detection | Frontend (LogLevelDetector) | Regex-based parsing in browser |
| Circular buffer management | Frontend (LogBuffer) | Client-side max lines, eviction |
| Text search and highlighting | Frontend (LogSearch) | No server involvement |
| Level filtering | Frontend (LogFilter) | CSS visibility toggle |
| Export/download | Frontend (LogExporter) | Blob-based client download |
| Auto-scroll logic | Frontend (LogRenderer) | Viewport management |
| Multi-pod pod listing | Backend (API endpoint) | `GET /api/v1/workloads/<kind>/<name>/pods` |
| Auth check for log access | Backend (Socket.IO handler) | Existing namespace access verification |
| Log stream to K8s API | Backend (K8sService) | Existing `get_pod_logs(follow=true)` |
| Audit logging | Backend (Socket.IO handler) | Log access event to AuditLog model |

## Template Structure

The log viewer is rendered via a Jinja2 template:

```
kubedash-ui/templates/workloads/
  └── pod-logs.html.j2          # Main log viewer page
      Renders:
      - Pod selector dropdown (for multi-container pods)
      - Toolbar: auto-scroll toggle, timestamp toggle, level filters
      - Search bar with match navigation
      - Log content area (scrollable div, xterm.js container fallback)
      - Status bar: connection state, buffer usage, export button
      - Script tag: loads static/js/log_viewer/init.js with config
```

## CSS Considerations

```css
.log-viewer-container {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 200px);
  min-height: 400px;
}

.log-toolbar {
  display: flex;
  gap: 8px;
  padding: 8px;
  border-bottom: 1px solid var(--border-color);
  background: var(--surface-color);
  flex-wrap: wrap;
  align-items: center;
}

.log-content {
  flex: 1;
  overflow-y: auto;
  font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
  font-size: 13px;
  line-height: 1.5;
  background: #0d1117;
  color: #c9d1d9;
  padding: 8px;
}

.log-line {
  display: flex;
  gap: 8px;
  padding: 1px 4px;
  border-radius: 2px;
}
.log-line:hover { background: rgba(255,255,255,0.05); }

.log-timestamp {
  color: #8b949e;
  user-select: none;
  white-space: nowrap;
}

.log-pod-name {
  font-weight: 600;
  white-space: nowrap;
}

.log-level-error .log-message { color: #f85149; }
.log-level-warn .log-message  { color: #d29922; }
.log-level-fatal .log-message { color: #f47067; }
.log-level-info .log-message  { color: #58a6ff; }
.log-level-debug .log-message { color: #8b949e; }

.search-match {
  background: rgba(187, 128, 9, 0.4);
  border-radius: 2px;
}
.search-match-current {
  background: rgba(187, 128, 9, 0.7);
  outline: 2px solid #d29922;
}

.log-status-bar {
  display: flex;
  justify-content: space-between;
  padding: 4px 8px;
  font-size: 12px;
  color: var(--text-muted);
  border-top: 1px solid var(--border-color);
  background: var(--surface-color);
}
```

## Risks / Trade-offs

### [High-Throughput Log Performance]
Pods with 100+ lines/sec can overwhelm DOM rendering. **Mitigation:** Use virtual scrolling (render only visible lines + buffer), batch DOM updates with requestAnimationFrame, cap DOM node count at 5,000 regardless of buffer size.

### [Large Log Lines]
Some logs contain very long lines (JSON payloads, stack traces). **Mitigation:** CSS `white-space: normal` with configurable line wrapping, "Expand" button for truncated lines, tooltip hover for full content.

### [Memory Usage on Long Sessions]
50,000 line buffer with 2KB per line = 100MB. **Mitigation:** Default max 10,000 lines, configurable to 50,000 max, user warning at >5,000 lines, garbage collection prompt.

### [Browser Compatibility]
Some log viewer features (Blob download, IntersectionObserver for virtual scroll) require modern browsers. **Mitigation:** Graceful fallbacks, feature detection, IE11 not supported (matches existing KubeDash policy).
