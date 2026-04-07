## Context

KubeDash has a working terminal in `src/kubedash/templates/workload/pod-exec.html.j2` (297 lines)
with an xterm.js v4.11.0-based terminal already. Current implementation:

**What already exists:**
- xterm.js v4.11.0 already in `src/kubedash/static/vendor/xterm.js@4.11.0/`
  - With addons: FitAddon, WebLinksAddon, SearchAddon
- Socket.IO `/exec` namespace
- Input loop: `term.onKey(e => socket.emit("exec-input", {"input": e.key}))`
- Response: `socket.on("response", msg => term.write(msg.output))`
- Paste handling: Ctrl+V/Cmd+V/Shift+Ctrl+V via customKeyEventHandler AND element paste event
- Copy handling: Ctrl+C/Cmd+C with selection, Ctrl+Shift+C/X alternate
- Disconnect button: `socket.emit("stop")`
- Closed event handler: `socket.on("closed", msg => term.writeln("\r\n" + msg.message))`
- Backend: `k8sPodExecStream()` in `src/kubedash/lib/k8s/workload.py`
  - Uses `exec_streams` dict keyed by `request.sid`
  - `wsclient.update(timeout=5)` loop with `output = wsclient.read_all()`
  - Cancel via `cancel_ev` threading.Event
  - Hardcoded command: `['/bin/sh']` in `k8sPodExecSocket()`
  - Cleanup: `exec_streams.pop(sid, None)` + `socketio.emit("closed", ..., room=sid)`
- Container selector dropdown with init container support
- CSP-compliant inline scripts with nonce

**What's missing (gaps this spec addresses):**
- No multi-tab management (single session only)
- No session recording for audit compliance
- No timeout warnings or auto-disconnect countdown
- No quick commands panel
- No terminal settings/preferences persistence
- No fullscreen mode
- No tab-based pod switching (reselecting requires page reload)
- No "recent sessions" history

**Key backend details to interface with:**
- Socket event: `socket.send(podName, containerName)` on `/exec` namespace (the `message` event)
- Input event: `socket.emit("exec-input", {"input": key})`
- Response event: `socket.on("response", msg => term.write(msg.output))`
- Closed event: `socket.on("closed", msg => term.writeln(terminated_message))`
- Stop event: `socket.emit("stop")` to disconnect
- Backend function: `k8sPodExecStream(wsclient, username_role, user_token, namespace, pod_name, container, sid, exec_streams, cancel_ev)`
- Socket factory: `k8sPodExecSocket(username_role, user_token, namespace, pod_name, container)` returns wsclient with `/bin/sh` hardcoded

**Constraints:**
- Must use xterm.js v4.11.0 already in vendor (NOT v5.x)
- Must maintain compatibility with existing `/exec` namespace event protocol
- Must stay CSP-compliant (nonce-based inline scripts)
- The `customKeyEventHandler` already handles paste/copy — new code must not break it
- xterm.js referenced in architecture diagrams as the exec rendering target
- Redis-backed sessions for multi-replica support
- AuditLog model already available for logging

The gap is UX and compliance: users have raw exec access but no polished terminal, no session recording for audit, no multi-tab management, no quick commands, no timeout handling. This design adds a full-featured terminal client on top of the existing backend without modifying the core exec protocol.

**Constraints:**
- Must be compatible with existing `pod_exec` / `response` / `exec-input` / `closed` / `stop` event protocol
- Must respect per-user K8s token scoping
- Must work within Flask + Jinja2 + AJAX paradigm
- Session recording must not add excessive overhead to I/O
- Exec sessions are single-use (K8s limitation) — reconnecting means starting a new session

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Browser                               │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐│
│  │             Terminal Manager (Main Controller)          ││
│  │                                                         ││
│  │  ┌──────────────────────────┐  ┌─────────────────────┐  ││
│  │  │  Tab 1: my-app-abc123    │  │  Tab 2: worker-xyz  │  ││
│  │  │  ┌────────────────────┐  │  │  ┌───────────────┐  │  ││
│  │  │  │   xterm.js         │  │  │  │   xterm.js    │  │  ││
│  │  │  │   (terminal 1)     │  │  │  │   (terminal 2)│  │  ││
│  │  │  │                    │  │  │  │               │  │  ││
│  │  │  │  Socket.IO conn #1 │  │  │  │  Socket.IO #2 │  │  ││
│  │  │  └─────────┬──────────┘  │  │  └───────┬───────┘  │  ││
│  │  └────────────┼────────────┘  └──────────┼──────────┘  ││
│  │               │                          │              ││
│  │  ┌────────────▼──────────────────────────┴────────────┐ ││
│  │  │              Quick Commands Panel                   │ ││
│  │  │  ┌──────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐        │ ││
│  │  │  │ls /  │ │env  │ │ps   │ │df -h│ │tail │ + Add  │ ││
│  │  │  └──────┘ └─────┘ └─────┘ └─────┘ └─────┘        │ ││
│  │  └────────────────────────────────────────────────────┘ ││
│  │                                                         ││
│  │  ┌───────────────────────────────────────────────────┐  ││
│  │  │              Session Recorder (per tab)           │  ││
│  │  │  Records: input + output + metadata + timestamps  │  ││
│  │  └───────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────┘│
│                                                              │
│  Socket.IO /exec namespace (per-connection, bidirectional)  │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│  Flask Backend (existing exec infra, extended)               │
│                                                              │
│  Socket.IO /exec namespace:                                  │
│    pod_exec → start_exec_session(sid, data)                  │
│    exec-input(sid, data) → write to wsclient                 │
│    stop(sid) → close exec stream                             │
│    disconnect event → cleanup wsclient, finalize recording   │
│                                                              │
│  Session Recorder:                                           │
│    Captures I/O events from exec loop                        │
│    Stores to PostgreSQL (session_records table)              │
│    Provides /api/v1/exec/sessions REST endpoints             │
│                                                              │
│  K8sService:                                                 │
│    exec_pod(namespace, pod, container, command) → K8s exec   │
│                                                              │
│  AuditLog:                                                   │
│    Exec session start/stop events logged                     │
└──────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### 1. TerminalManager (Main Controller)

Coordinates global terminal state, tab management, Socket.IO connections:

```javascript
class TerminalManager {
  constructor(options) {
    this.tabs = [];           // Array of TerminalTab instances
    this.activeTabIndex = 0;
    this.maxTabs = options.maxTabs || 8;
    this.tabBar = document.getElementById('terminal-tab-bar');
    this.tabContent = document.getElementById('terminal-tab-content');
    this.quickCommands = new QuickCommandManager();
    this.settings = TerminalSettings.load();
    this.socket = io('/exec', {
      reconnection: true,
      reconnectionAttempts: 3,
      reconnectionDelay: 1000
    });
  }

  openTab(pod, container, namespace) {
    if (this.tabs.length >= this.maxTabs) {
      this.showTabLimitWarning();
      return null;
    }
    const tab = new TerminalTab(pod, container, namespace, this.socket);
    tab.settings = this.settings;
    tab.onClose = () => this.removeTab(tab);
    this.tabs.push(tab);
    this.activeTabIndex = this.tabs.length - 1;
    this.renderTabBar();
    tab.activate();
    return tab;
  }

  removeTab(tab) {
    if (tab.isActive) {
      tab.emitStopRequest();
    }
    tab.destroy();
    const idx = this.tabs.indexOf(tab);
    this.tabs.splice(idx, 1);
    if (this.activeTabIndex >= this.tabs.length) {
      this.activeTabIndex = Math.max(0, this.tabs.length - 1);
    }
    if (this.tabs[this.activeTabIndex]) {
      this.tabs[this.activeTabIndex].activate();
    }
    this.renderTabBar();
  }
}
```

### 2. TerminalTab

Represents a single exec session tab:

```javascript
class TerminalTab {
  constructor(pod, container, namespace, socket) {
    this.id = generateUUID();
    this.pod = pod;
    this.container = container;
    this.namespace = namespace;
    this.socket = socket;
    this.state = 'connecting';
    this.tabName = `${namespace}/${pod}`;
    this.customName = null;
    this.terminal = null;  // xterm.js instance
    this.recorder = new SessionRecorder();
    this.timeoutHandle = null;
    this.timeoutWarningShown = false;
    this.sessionStartTime = null;
  }

  activate() {
    this.terminal = this.createXtermInstance();
    this.recorder.start(this);
    this.sessionStartTime = Date.now();
    this.startTimeoutTimer();
    this.connect();
  }

  createXtermInstance() {
    const term = new Terminal({
      cursorBlink: this.settings.cursorBlink,
      cursorStyle: this.settings.cursorStyle,
      fontSize: this.settings.fontSize,
      fontFamily: this.settings.fontFamily,
      scrollback: this.settings.scrollbackLines,
      bellStyle: this.settings.bellStyle,
      allowProposedApi: true
    });

    term.loadAddon(new WebLinksAddon());
    term.loadAddon(new FitAddon());

    term.onData(data => this.onInput(data));
    term.onResize(size => this.onResize(size));
    term.attachCustomKeyEventHandler(e => this.onKey(e));

    return term;
  }

  connect() {
    this.socket.emit('pod_exec', {
      podName: this.pod,
      container: this.container,
      namespace: this.namespace
    });

    // Handle server events
    this.socket.on('response', (data) => this.onOutput(data));
    this.socket.on('closed', () => this.onConnectionClosed());
    this.socket.on('error', (err) => this.onError(err));

    this.state = 'connecting';
    this.updateStatusIndicator();
  }

  onInput(data) {
    this.recorder.record('input', data);
    this.socket.emit('exec-input', { data: data });
  }

  onOutput(data) {
    this.recorder.record('output', data);
    if (this.terminal) {
      this.terminal.write(data.text || data);
    }
  }

  emitStopRequest() {
    this.socket.emit('stop', { podName: this.pod });
  }

  startTimeoutTimer() {
    const maxMs = this.settings.maxSessionMinutes * 60 * 1000;
    const warningMs = this.settings.warningBeforeMinutes * 60 * 1000;

    this.timeoutHandle = setTimeout(() => {
      this.showWarning();
      setTimeout(() => {
        this.onSessionTimeout();
      }, warningMs);
    }, maxMs - warningMs);
  }

  onSessionTimeout() {
    this.recordFinalize('timeout');
    this.emitStopRequest();
    this.terminal.writeln('\r\n\x1b[33mSession expired. Click Reconnect to start a new session.\x1b[0m');
    this.state = 'expired';
    this.updateStatusIndicator('expired');
  }
}
```

### 3. SessionRecorder

Captures I/O events with timestamps for audit playback:

```javascript
class SessionRecorder {
  constructor() {
    this.events = [];
    this.startTime = null;
    this.active = false;
    this.syncInterval = null;
    this.sessionId = null;
  }

  start(tab) {
    this.sessionId = generateUUID();
    this.startTime = Date.now();
    this.active = true;
    this.events = [];

    // Periodically sync recording to server
    this.syncInterval = setInterval(() => this.sync(), 10000);

    // Record metadata
    this.meta = {
      session_id: this.sessionId,
      namespace: tab.namespace,
      pod: tab.pod,
      container: tab.container,
      start_time: new Date().toISOString()
    };
  }

  record(type, data) {
    if (!this.active) return;
    this.events.push({
      t: (Date.now() - this.startTime) / 1000,
      type: type,
      data: data
    });
    // Flush to server in batches
    if (this.events.length >= 100) {
      this.sync();
    }
  }

  async sync() {
    if (this.events.length === 0) return;
    const batch = this.events.splice(0, this.events.length);
    await fetch(`/api/v1/exec/sessions/${this.sessionId}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: batch })
    });
  }

  finalize(exitStatus) {
    this.active = false;
    clearInterval(this.syncInterval);

    // Send remaining events
    if (this.events.length > 0) {
      this.sync();
    }

    this.meta.end_time = new Date().toISOString();
    this.meta.duration = Date.now() - this.startTime;
    this.meta.exit_status = exitStatus;

    // Save metadata
    return fetch(`/api/v1/exec/sessions/${this.sessionId}/metadata`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(this.meta)
    });
  }
}
```

### 4. QuickCommandManager

Manages quick command presets:

```javascript
class QuickCommandManager {
  constructor() {
    this.commands = this.loadDefaults();
    this.customCommands = TerminalSettings.getCustomCommands();
  }

  loadDefaults() {
    return [
      { category: 'Filesystem', command: 'ls -la /', description: 'List root directory' },
      { category: 'Filesystem', command: 'df -h', description: 'Disk usage' },
      { category: 'System Info', command: 'env', description: 'Environment variables' },
      { category: 'System Info', command: 'ps aux', description: 'Running processes' },
      { category: 'Logs', command: 'tail -n 100 /var/log/syslog', description: 'Recent system log' },
      // ... full default set
    ];
  }

  getAll() { return [...this.commands, ...this.customCommands]; }

  execute(command, terminal) {
    // Insert command into terminal (user can review before Enter)
    // Sends as exec-input but without trailing newline for safety
    // Actually: follow spec — send as if typed, including newline
    terminal.socket.emit('exec-input', { data: command + '\n' });
  }

  addCustom(name, command, category) {
    this.customCommands.push({
      category: category || 'Custom',
      command: command,
      description: name,
      isCustom: true
    });
    TerminalSettings.saveCustomCommands(this.customCommands);
  }
}
```

### 5. SessionPlayback

Replays recorded sessions for audit review:

```javascript
class SessionPlayback {
  constructor(container, settings) {
    this.terminal = new Terminal({
      ...settings,
      disableStdin: true  // Read-only playback
    });
    this.terminal.open(container);
    this.isReplaying = false;
    this.isPaused = false;
    this.playbackSpeed = 1.0;
  }

  async play(events) {
    this.isReplaying = true;
    this.startTime = Date.now();

    for (const event of events) {
      if (!this.isReplaying) break;

      while (this.isPaused) {
        await new Promise(r => setTimeout(r, 100));
      }

      const targetTime = event.t * 1000 / this.playbackSpeed;
      const elapsed = Date.now() - this.startTime;
      const delay = targetTime - elapsed;

      if (delay > 0) {
        await new Promise(r => setTimeout(r, delay));
      }

      if (event.type === 'output') {
        this.terminal.write(event.data);
      }
      // For playback, we only replay output (what the user saw)
      // Input can be shown as visual markers if the recording includes it
    }

    this.isReplaying = false;
  }
}
```

## Data Models

### Session Record (PostgreSQL)

```sql
CREATE TABLE exec_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER REFERENCES users(id),
    namespace VARCHAR(255) NOT NULL,
    pod VARCHAR(255) NOT NULL,
    container VARCHAR(255) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_ms BIGINT,
    exit_status VARCHAR(50),  -- normal, timeout, error, user-disconnect, connection-lost
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE exec_session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES exec_sessions(id) ON DELETE CASCADE,
    "timestamp" FLOAT NOT NULL,  -- seconds from session start
    event_type VARCHAR(10) NOT NULL,  -- 'input' or 'output'
    data TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_exec_sessions_user ON exec_sessions(user_id);
CREATE INDEX idx_exec_sessions_time ON exec_sessions(start_time DESC);
CREATE INDEX idx_exec_session_events_session ON exec_session_events(session_id);
```

## API Endpoints

### Session Recording API

```
GET    /api/v1/exec/sessions
  Query: user_id, namespace, pod, start_date, end_date, status
  Response: paginated list of exec sessions

GET    /api/v1/exec/sessions/<session_id>
  Response: session metadata (no events payload)

GET    /api/v1/exec/sessions/<session_id>/events
  Query: limit, offset
  Response: paginated list of session events

POST   /api/v1/exec/sessions/<session_id>/events (internal)
  Body: { events: [{ t, type, data }, ...] }
  Auth: Socket.IO session owner

PUT    /api/v1/exec/sessions/<session_id>/metadata
  Body: { namespace, pod, container, start_time, end_time, duration_ms, exit_status }
  Auth: Socket.IO session owner
```

### Quick Commands API

```
GET    /api/v1/user/quick-commands
  Response: user's custom quick commands (merged with defaults client-side)

PUT    /api/v1/user/quick-commands
  Body: { commands: [{ category, command, description, isCustom }, ...] }
  Response: saved commands

DELETE /api/v1/user/quick-commands/<id>
  Response: 204 No Content
```

## Frontend / Backend Split

| Responsibility | Location | Details |
|---------------|----------|---------|
| xterm.js rendering | Frontend | Terminal instance per tab |
| Terminal input capture | Frontend | xterm onData → Socket.IO exec-input |
| Terminal output processing | Frontend | Socket.IO response → terminal.write() |
| Tab management | Frontend | TerminalManager, TerminalTab classes |
| Session recording (capture) | Frontend | SessionRecorder captures I/O events |
| Session recording (storage) | Backend | Flushes to PostgreSQL via REST API |
| Session playback | Frontend | SessionPlayback reads events from API |
| Connection timeout | Frontend | Timer-based, no server involvement |
| Quick commands | Frontend | localStorage + optional server sync |
| K8s exec stream | Backend | Existing exec_pod() + Socket.IO routing |
| Exec session audit | Backend | AuditLog model write on session start/end |
| Session list API | Backend | REST endpoints for querying recordings |
| RBAC enforcement | Backend | Existing role checks on view render + K8s token for exec |

## Template Structure

```
kubedash-ui/templates/workloads/
  └── pod-exec.html.j2          # Terminal page
      Renders:
      - Tab bar with close buttons, status indicators, rename input
      - "+" button for new tab (opens pod/container selector)
      - Terminal content area (xterm.js containers per tab)
      - Quick commands panel (sidebar or toolbar dropdown)
      - Status bar: connection state, timeout countdown, fullscreen toggle
      - Font size controls
      - Script tag: loads static/js/terminal/init.js with config

kubedash-ui/templates/admin/
  └── exec-sessions.html.j2     # Admin session audit page
      Renders:
      - Session list table with filters
      - Session detail view
      - Replay button
```

## Data Flows

### Single Pod Exec Session

The actual implementation flow (updated for real backend):

```
User clicks "Shell" on Pod detail page
    │
    ▼
UI Template: pod-exec.html.j2 renders page with inline JS
  - Loads xterm.js v4.11.0 + FitAddon + WebLinksAddon + SearchAddon
  - Creates term = new Terminal({scrollback: 10000})
  - socket = io.connect('/exec')
  - term.onKey(e => socket.emit("exec-input", {input: e.key}))
  - Custom paste handler (element.addEventListener("paste"))
  - Custom copy handler (customKeyEventHandler Ctrl+V, Ctrl+C)
    │
    ▼
Container selector loads containers via:
  GET /api/v1/workloads/pods/{pod_name}/containers?namespace={ns}
    │
    ▼
socket.send(podName, containerName)   // sends 'message' event on /exec namespace
    │
    ▼
Backend: message() handler in workload.py
  - Validates pod_name, namespace, container
  - Cancels existing exec: exec_streams[sid].get("cancel").set()
  - wsclient = k8sPodExecSocket(user_token, namespace, pod_name, container)
    → Returns stream() wrapping connect_get_namespaced_pod_exec
    → Hardcoded to ['/bin/sh']
  - exec_streams[sid] = {"wsclient": wsclient, "cancel": cancel_ev}
  - socketio.start_background_task(k8sPodExecStream, wsclient, ..., sid, exec_streams, cancel_ev)
    │
    ▼
k8sPodExecStream() in lib/k8s/workload.py:
  - while True:
    - if cancel_ev.is_set(): break
    - wsclient.update(timeout=5)
    - output = wsclient.read_all()
    - if output: socketio.emit("response", {output: output}, room=sid)
  - On cancel/break: break loop
  - finally: exec_streams.pop(sid) + emit("closed", room=sid)
    │
    ▼
Browser: socket.on("response", msg => term.write(msg.output))
    │
    ▼
User types: term.onKey(e => socket.emit("exec-input", {input: e.key}))

## State Management

```
┌──────────────────────────────────────────┐
│         TerminalManager State            │
│                                          │
│  tabs: [TerminalTab, ...]               │
│  activeTabIndex: number                 │
│  maxTabs: number (config, default: 8)   │
│  settings: TerminalSettings             │
│  socket: SocketIO /exec connection      │
│  quickCommands: QuickCommandManager     │
│                                          │
│  TerminalTab State:                     │
│    id: UUID                              │
│    pod, container, namespace             │
│    tabName: string (custom or default)   │
│    state: connecting|connected|expired   │
│          |disconnected|error             │
│    terminal: xterm.Terminal instance     │
│    recorder: SessionRecorder             │
│    sessionStartTime: timestamp           │
│    timeoutHandle: NodeJS.Timeout | null  │
│    timeoutWarningShown: boolean          │
│                                          │
│  TerminalSettings (localStorage):        │
│    fontSize: 14                          │
│    fontFamily: string                    │
│    cursorStyle: 'block'                  │
│    cursorBlink: true                     │
│    scrollbackLines: 5000                 │
│    bellStyle: 'none'                     │
│    maxTabs: 8                            │
│    maxSessionMinutes: 30                 │
│    warningBeforeMinutes: 5              │
│    customCommands: Array                 │
└─────────────────────────────────────────┘
```

## CSS Considerations

```css
.terminal-container {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 220px);
  min-height: 300px;
}

.terminal-tab-bar {
  display: flex;
  gap: 2px;
  padding: 4px 4px 0;
  background: var(--surface-color);
  border-bottom: 1px solid var(--border-color);
  overflow-x: auto;
}

.terminal-tab {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: var(--panel-bg);
  border: 1px solid var(--border-color);
  border-bottom: none;
  border-radius: 4px 4px 0 0;
  cursor: pointer;
  white-space: nowrap;
  font-size: 13px;
  user-select: none;
}
.terminal-tab.active {
  background: var(--terminal-bg);
  border-color: var(--terminal-bg);
}
.terminal-tab .status-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
}
.terminal-tab .status-dot.connected { background: #34d399; }
.terminal-tab .status-dot.connecting { background: #fbbf24; animation: pulse 1s infinite; }
.terminal-tab .status-dot.disconnected { background: #ef4444; }

.terminal-tab .close-btn {
  opacity: 0.5;
  cursor: pointer;
  font-size: 11px;
}
.terminal-tab:hover .close-btn { opacity: 1; }

.terminal-tab-content {
  flex: 1;
  position: relative;
  background: #1a1b26;
  overflow: hidden;
}

.terminal-tab-pane {
  display: none;
  position: absolute;
  inset: 0;
}
.terminal-tab-pane.active { display: block; }

.xterm { padding: 8px; height: 100% !important; }

.terminal-status-bar {
  display: flex;
  justify-content: space-between;
  padding: 4px 8px;
  font-size: 12px;
  color: var(--text-muted);
  border-top: 1px solid var(--border-color);
  background: var(--surface-color);
}

.timeout-warning {
  background: #d97706;
  color: white;
  text-align: center;
  padding: 4px;
  font-size: 12px;
  font-weight: 600;
}

.quick-commands-panel {
  background: var(--surface-color);
  border-bottom: 1px solid var(--border-color);
  padding: 4px 8px;
  max-height: 120px;
  overflow-y: auto;
}

.quick-command {
  display: inline-block;
  padding: 2px 8px;
  margin: 2px;
  background: var(--panel-bg);
  border: 1px solid var(--border-color);
  border-radius: 3px;
  font-size: 12px;
  cursor: pointer;
  font-family: monospace;
}
.quick-command:hover { background: var(--hover-bg); }
```

## Session Recording Data Flow

```
User types in xterm.js terminal
    │
    ▼
xterm.onData(data)
    │
    ▼
TerminalTab.onInput(data)
    │
    ├──► recorder.record('input', data)  ← captured for audit
    │
    └──► socket.emit('exec-input', {data})  ← sent to K8s
                    │
                    ▼
         Flask: writes to wsclient stdin
                    │
                    ▼
         K8s API: command executes in container
                    │
                    ▼
         K8s API: stdout/stderr output via WebSocket
                    │
                    ▼
         Flask: reads stream, emits 'response' event
                    │
                    ▼
Browser: TerminalTab.onOutput(data)
    │
    ├──► recorder.record('output', data)  ← captured for audit
    │
    └──► terminal.write(data.text)  ← displayed in xterm.js
```

## Migration Plan

### Phase 1: Core Terminal (Week 1-2)
1. Create terminal template page with xterm.js integration
2. Implement basic Socket.IO connection using existing exec protocol
3. Build single-tab terminal with input/output loop
4. Test exec into pods across different namespaces

### Phase 2: Tab Management and Quick Commands (Week 3-4)
1. Implement multi-tab terminal with pod selector
2. Add quick commands panel with default preset library
3. Build connection status indicators and error handling
4. Add session timeout with warning banner

### Phase 3: Session Recording (Week 5-6)
1. Create database models for exec_sessions and exec_session_events
2. Implement SessionRecorder with batch sync to server
3. Build admin session list page with filters
4. Add session replay functionality

### Phase 4: Polish and Release (Week 7-8)
1. Fullscreen toggle, clipboard integration, settings persistence
2. RBAC enforcement (Viewer role cannot open terminal)
3. Performance testing with high-throughput terminal sessions
4. Documentation and Helm chart integration

**Rollback Strategy:**
- New templates and JS modules — no changes to existing exec functionality
- Database migration is additive (new tables only, no alterations to existing tables)
- Disable via feature flag or remove template references

## Open Questions

1. **Recording storage volume:** For busy clusters with many concurrent exec sessions, how much storage will session_events consume? Need to benchmark with typical session durations (5-30 min). **Mitigation:** Configurable retention period, compression for events data, periodic cleanup job.

2. **Multi-replica sync:** If Socket.IO routes a user's exec session to a different replica than the recording API, how do we ensure the recording is associated correctly? **Answer:** Session recording is server-push to REST API, not Socket.IO, so stickiness isn't required. The session_id UUID ensures correct association.

3. **Replay performance:** Replaying a 30-minute session with 100,000 events may be slow. **Mitigation:** Batch events into 1-second chunks, use playback speed options (1x, 2x, 5x, 10x), show progress bar.

4. **Sensitive data in recordings:** Some exec sessions may include passwords typed into interactive prompts. **Mitigation:** This is an inherent limitation of exec auditing. Document this in compliance guide. Consider input redaction option for sensitive patterns (future enhancement).

5. **Container shell detection:** Different container images have different default shells (/bin/sh, /bin/bash, /bin/ash, /bin/zsh). **Mitigation:** Detect shell from container spec or try common shells in order. Display shell info in tab title.
