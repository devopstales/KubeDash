### PRD: Interactive Terminal (xterm.js Pod Exec)

**OpenSpec change**: `openspec/changes/interactive-terminal/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

KubeDash has Socket.IO-based pod exec infrastructure (`pod_exec` event, per-connection state management, K8sService `exec_pod()` method, xterm.js in architecture diagrams) but no polished terminal UI. The existing exec capability works at the protocol level but presents users with a raw, single-session terminal with no session management, audit compliance features, or UX conveniences expected of a modern web terminal. Enterprise users comparing KubeDash against Lens, Octant, or the Kubernetes Dashboard expect a full-featured terminal experience.

#### Goals

- Implement an interactive xterm.js terminal for pod exec with tab management, session recording, timeout warnings, and quick commands
- Enable multiple concurrent terminal sessions in tabs for debugging across pods
- Record all exec session I/O for audit compliance with replay capability
- Provide a comfortable terminal UX with quick commands, fullscreen mode, and clipboard support
- Enforce RBAC: Viewer role cannot open terminals; all sessions auditable

#### Functional Requirements

- **xterm.js Terminal**: Full interactive terminal using xterm.js v5.x with WebLinks addon (clickable URLs), FitAddon (responsive sizing), custom theme, configurable font size/family/cursor style.
- **Multi-Tab Management**: Multiple concurrent terminal sessions as tabs. Tab rename via double-click, drag-to-reorder, close confirmation for active sessions. Configurable max tabs (default: 8). Status indicators per tab (connected/connecting/disconnected/expired).
- **Session Recording**: Record all I/O (input + output) with timestamps for audit compliance. Store session metadata (user, pod, container, duration, exit status). Recordings accessible to Admin role and session owner only. Configurable retention period (default: 90 days).
- **Timeout Warnings**: Configurable max session duration (default: 30 min) with countdown warning (default: 5 min before expiry). Clean session close on expiry with "Session expired — click Reconnect" message.
- **Quick Commands**: Predefined command presets organized by category (Filesystem, System Info, Logs, Debugging, Network). One-click execution (inserts into terminal). Custom commands per user, persisted in localStorage with optional server sync.
- **Connection Health**: Real-time connection status indicator, automatic reconnection (3 attempts), manual reconnect button. Clear indication that K8s exec is single-use (reconnect starts a new session).
- **Fullscreen Toggle**: Expand terminal to full viewport with floating overlay controls. Escape key to exit.
- **Clipboard Integration**: Ctrl+Shift+C for copy (ANSI-stripped), Ctrl+Shift+V for paste. Right-click context menu.
- **Session Audit Page**: Admin-only page listing all recorded sessions with filters (user, namespace, pod, date range, status). Session replay with speed controls (1x, 2x, 5x, 10x).
- **RBAC Enforcement**: Viewer role — terminal button hidden/disabled with tooltip. Operator role — exec in assigned namespaces. Admin role — exec in any namespace. All exec subject to K8s `pods/exec` RBAC via per-user token.

#### Non‑Functional Requirements

- **Performance**: xterm.js efficiently handles high-throughput output. Session recording adds ~10% overhead to I/O bandwidth (batched sync every 10 seconds or 100 events). Redis pub/sub supports multi-replica exec sessions.
- **Security**: Session recording data is sensitive — server storage with user scoping, Admin + owner access only. Exec permissions enforced by existing K8s RBAC (per-user token). Audit log records all exec session start/end events. No sensitive data filtering in v1 (documented limitation).
- **Compatibility**: Uses existing `pod_exec` / `response` / `exec-input` / `closed` / `stop` Socket.IO protocol. No backend protocol changes.
- **Storage**: `exec_sessions` and `exec_session_events` tables (new, additive migration). Periodic cleanup job for sessions older than retention period.

#### Implementation Tasks

- [ ] 1. Core xterm.js terminal (single-tab Socket.IO connection, input/output loop, FitAddon, WebLinksAddon, settings)
- [ ] 2. Multi-tab management (tab manager, pod selector, quick commands panel, status indicators, container selection)
- [ ] 3. Session recording (database models, backend REST endpoints, frontend recorder with batch sync, admin session list, RBAC)
- [ ] 4. Polish: timeout handling, reconnection, fullscreen, clipboard, font controls, session replay, performance testing, documentation
