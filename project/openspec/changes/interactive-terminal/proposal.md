## Why

KubeDash has Socket.IO-based pod exec infrastructure (`pod_exec` event in `/exec` namespace, per-connection state management, K8sService `exec_pod()` method, xterm.js in architecture diagrams), but no polished terminal UI. The existing exec capability works at the protocol level but presents users with a raw, single-session terminal with no session management, audit compliance features, or UX conveniences expected of a modern web terminal. Enterprise users comparing KubeDash against Lens, Octant, or the Kubernetes Dashboard expect a full-featured terminal experience.

This change implements an interactive xterm.js terminal for pod exec with tab management, session recording for auditing, timeout warnings, quick command presets, and robust connection handling — all built on top of the existing Socket.IO exec infrastructure (OpenSpec spec: `exec-per-connection`).

## What Changes

- **xterm.js Terminal Integration**: Full interactive terminal embedded in the UI using xterm.js with WebLinks addon, FitAddon, and AttachAddon support
- **Multi-Tab Terminal Management**: Open multiple terminal sessions in tabs, switch between pods/namespaces/containers, rename tabs, close with confirmation if process running
- **Session Recording**: Record all terminal I/O (input and output) for audit compliance, store session metadata (user, pod, container, commands executed, duration, exit status)
- **Connection Management**: Realistic reconnection handling, session timeout with configurable warning countdown, session health indicator, manual reconnect
- **Quick Commands**: Predefined command presets (`ls /app`, `cat /etc/hostname`, `env`, `ps aux`, `df -h`, `top`, `tail -f /var/log/app.log`) with one-click execution
- **Session History**: Recent terminal sessions per user, ability to replay recorded sessions (input only, for audit)
- **Fullscreen Toggle**: Expand terminal to full viewport for focused debugging
- **Copy/Paste Support**: Proper clipboard integration (Ctrl+Shift+C/V, right-click context menu, paste via xterm.js)
- **No Breaking Changes**: Existing `pod_exec` Socket.IO event, `/exec` namespace, per-connection state via `request.sid` routing continue to work. New features are additive.

## Capabilities

### New Capabilities

- `xterm-terminal`: xterm.js-based interactive terminal with WebLinks, FitAddon, AttachAddon, and custom shell theme
- `terminal-tabs`: Multi-tab terminal session management with tab naming, reordering, pinning, and close warnings
- `session-recording`: Terminal I/O recording with audit storage, playback capability, and session metadata tracking
- `timeout-warnings`: Configurable session timeout with countdown notification, auto-disconnect warning, and session extension option
- `quick-commands`: Command preset library with one-click execution, editable per-user, categorized by use case
- `connection-health`: Real-time connection status indicator, automatic reconnection, session recovery notification
- `fullscreen-terminal`: Viewport-expanding fullscreen mode for focused terminal work
- `clipboard-integration`: Proper copy/paste support with Ctrl+Shift+C/V, right-click menu, and automatic strip of ANSI codes on copy

### Modified Capabilities

- `exec-per-connection` (existing spec): No changes to connection scoping. The existing `response`, `exec-input`, `closed`, and `stop` events continue to function. The xterm terminal is a new consumer of these events.
- `pod_exec` (Socket.IO event): Remains unchanged. Terminal sends the same message format to start exec sessions.

## Impact

- **Affected code**: New JavaScript modules in `static/js/terminal/`, new Jinja2 template for terminal view (`pod-exec.html.j2`), Socket.IO event handlers may receive new events (session recording, tab management)
- **APIs**: New REST endpoints for session recording retrieval (`GET /api/v1/exec/sessions`), session playback (`GET /api/v1/exec/sessions/<id>/replay`), and quick command management (`GET/PUT /api/v1/user/quick-commands`)
- **Dependencies**: xterm.js (already referenced in architecture), xterm-addon-fit, xterm-addon-web-links, xterm-addon-attach (all via CDN or existing package); no new server dependencies
- **Security**: Session recording data is sensitive — stored with user scoping, accessible only to Admin role and session owner. Exec permissions enforced by existing K8s RBAC. Viewer role cannot open terminals. Audit log records all exec sessions.
- **Configuration**: Session timeout duration (default: 30 min), warning countdown (default: 5 min before timeout), recording retention period, maximum concurrent sessions per user, quick command presets list
- **Performance**: xterm.js handles high-throughput output efficiently. Redis pub/sub supports multi-replica exec sessions. Session recording adds ~10% overhead to I/O bandwidth.
