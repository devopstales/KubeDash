## ADDED Requirements

### Requirement: xterm.js Terminal Integration

The system SHALL embed an interactive terminal using xterm.js (v4.11.0 — already in vendor) for pod exec sessions. The terminal SHALL provide:

- Full TTY emulation with proper cursor control, colors, and keyboard handling
- WebLinks addon for clickable URLs in terminal output (already loaded, not invoked from template)
- FitAddon for responsive terminal sizing (terminal fills container — already working)
- SearchAddon for text search within terminal output (already loaded, not invoked from template)
- Custom shell theme matching KubeDash's visual design (dark background, readable colors)
- Configurable font size with Ctrl+Plus/Minus zoom
- Configurable font family (monospace default, with fallbacks)

The terminal SHALL connect to the existing Socket.IO `/exec` namespace using the established `message` (for exec start) / `response` / `exec-input` / `closed` / `stop` event protocol. The current implementation already uses `socket.send(podName, containerName)` for the message event — this SHALL continue unchanged.

#### Scenario: Open terminal session
- **WHEN** user opens a terminal for a pod/container
- **THEN** the system SHALL create an xterm.js terminal instance, connect to `/exec` via Socket.IO, send `pod_exec` with pod/container details, and attach the terminal to the xterm instance
- **AND** the terminal SHALL display a shell prompt ready for input

#### Scenario: Terminal sizing adapts to container
- **WHEN** the user resizes the browser window or terminal container
- **THEN** the terminal SHALL automatically resize to fit the container (via FitAddon)
- **AND** the terminal dimensions SHALL be sent to the server so the TTY is resized in the container

#### Scenario: Clickable URLs in output
- **WHEN** terminal output contains a URL
- **THEN** the system SHALL make the URL clickable (WebLinks addon)
- **AND** clicking the URL SHALL open it in a new browser tab

### Requirement: Multi-Tab Terminal Management

The terminal interface SHALL support multiple concurrent terminal sessions organized as tabs. Each tab represents one exec session to a specific pod/container/namespace combination. Tab management features:

- Tabs SHALL display the pod name and container name (truncated if necessary)
- Users SHALL be able to rename tabs with custom names
- Users SHALL be able to reorder tabs via drag-and-drop (or manual ordering if DnD unavailable)
- Closing a tab with an active exec session SHALL show a confirmation dialog ("Terminal is active. Close anyway?")
- A "+" button SHALL be visible to open a new terminal in a new tab (opens pod selector)
- Tabs SHALL show connection status indicators (green dot = active, yellow = connecting, red = disconnected)
- The interface SHALL support a configurable maximum number of open tabs (default: 8)

#### Scenario: Open multiple terminals
- **WHEN** user has one active terminal and opens a second tab to a different pod
- **THEN** the system SHALL create a new tab with the second terminal, maintaining both sessions independently
- **AND** both sockets SHALL remain connected simultaneously

#### Scenario: Close active tab with confirmation
- **WHEN** user clicks the close button on a tab with an active exec session
- **THEN** the system SHALL display a confirmation dialog
- **AND** if confirmed, the system SHALL clean up the exec session (emit `stop`, clear state), close the tab, and activate the next tab

#### Scenario: Tab limit reached
- **WHEN** user tries to open a 9th tab with max configured at 8
- **THEN** the system SHALL prevent opening the new tab and display a message "Maximum 8 terminal sessions reached"

### Requirement: Session Recording

The system SHALL record all exec session I/O for audit compliance purposes. Recording includes:

- All input (keystrokes sent to the container, including pasted text)
- All output (text received from the container)
- Session metadata: user ID, username, namespace, pod name, container name, start time, end time, duration, exit status (normal, timeout, error, user-disconnect)

Recorded sessions SHALL be stored in a format that allows replay. The recording format SHOULD be:

```json
{
  "session_id": "uuid",
  "user_id": 42,
  "username": "jdoe",
  "namespace": "default",
  "pod": "my-app-abc123",
  "container": "app",
  "start_time": "2026-04-07T10:00:00Z",
  "end_time": "2026-04-07T10:15:30Z",
  "events": [
    {"t": 0.0, "type": "output", "data": "root@my-app:/# "},
    {"t": 1.2, "type": "input", "data": "ls /app\n"},
    {"t": 1.5, "type": "output", "data": "config.yaml  main.py  requirements.txt\n"},
    {"t": 5.0, "type": "input", "data": "cat /app/config.yaml\n"},
    {"t": 5.3, "type": "output", "data": "..."}
  ]
}
```

Recording data SHALL be stored server-side (in PostgreSQL as JSONB or in a dedicated session_records table). Session metadata SHALL be logged to the KubeDash audit log at session start and session end.

Recorded sessions SHALL be viewable by:
- Admin role: all sessions
- Session owner: their own sessions

Recorded sessions SHALL NOT include sensitive information beyond what the terminal itself displays (the server does not filter or redact output — the session record is a faithful representation of what appeared in the terminal).

Recorded sessions SHALL have a configurable retention period (default: 90 days). Sessions older than the retention period SHALL be eligible for deletion.

#### Scenario: Session recording starts
- **WHEN** a user opens a terminal and the exec connection is established
- **THEN** the system SHALL begin recording the session with start timestamp and metadata
- **AND** an audit log entry SHALL be created with user, namespace, pod, container, and start time

#### Scenario: Session recording ends
- **WHEN** the exec session ends (user disconnect, pod termination, timeout, or error)
- **THEN** the system SHALL finalize the recording with end timestamp, duration, and exit status
- **AND** an audit log entry SHALL be created with session summary (duration, exit status)

#### Scenario: Admin views session list
- **WHEN** an admin user navigates to the exec sessions audit page
- **THEN** the system SHALL display a table of recorded sessions with filters (user, namespace, pod, date range, status)

#### Scenario: User replays session recording
- **WHEN** an Admin clicks "Replay" on a recorded session
- **THEN** the system SHALL open a new terminal and replay the session's input/output stream at the original timing intervals
- **AND** a "REPLAY" banner SHALL appear indicating the session is a recording replay, not a live session

### Requirement: Session Timeout and Warning

The system SHALL enforce a configurable maximum exec session duration (default: 30 minutes). The timeout behavior:

- When the session has been active for (timeout - warning_duration) time, the system SHALL display a warning banner in the terminal tab: "Session will expire in X minutes"
- A countdown display SHALL appear showing remaining seconds
- The user SHALL be offered a "Reconnect" button to start a new session before expiration
- When the timeout is reached, the system SHALL cleanly close the exec session, stop recording, and display "Session expired — click Reconnect to open a new session"
- If a command is actively running at timeout expiry, the terminal SHALL display "Session expired (running command terminated)" and close the connection

The session timeout SHALL be configurable per instance in `kubedash.ini`:

```ini
[exec_settings]
max_session_minutes = 30
warning_before_minutes = 5
```

#### Scenario: Session timeout warning
- **WHEN** a terminal session has been active for 25 minutes with a 30-minute timeout
- **THEN** the system SHALL display a yellow warning banner: "Session will expire in 5 minutes"
- **AND** a countdown timer SHALL appear in the banner

#### Scenario: Session expires
- **WHEN** a terminal session reaches its maximum timeout
- **THEN** the system SHALL close the exec stream, finalize the session recording, and display "Session expired — click Reconnect to open a new session"
- **AND** the tab SHALL remain open with the disconnected state and Reconnect button

### Requirement: Quick Commands

The system SHALL provide a library of predefined commands that users can execute with a single click. Quick commands SHALL:

- Be displayed in a dropdown or sidebar panel accessible from the terminal view
- Be organized into categories (Filesystem, System Info, Logs, Debugging, Network)
- Be customizable per user (add, edit, remove, reorder)
- Be stored in the user's session/local storage with optional server sync
- Insert the command text into the terminal input buffer (as if the user typed it) rather than auto-executing (safety: user reviews before sending)

Default quick commands SHALL include:

| Category | Command | Description |
|----------|---------|-------------|
| Filesystem | `ls -la /` | List root directory |
| Filesystem | `ls -la /app` | List application directory |
| Filesystem | `df -h` | Disk usage |
| Filesystem | `cat /etc/hostname` | Show hostname |
| System Info | `env` | Environment variables |
| System Info | `ps aux` | Running processes |
| System Info | `uname -a` | System information |
| System Info | `free -m` | Memory usage |
| Logs | `tail -n 100 /var/log/syslog` | Recent system log |
| Logs | `tail -f /var/log/app.log` | Follow app log |
| Debugging | `top -b -n 1 | head -20` | Top processes snapshot |
| Debugging | `netstat -tlnp` | Listening ports |
| Network | `curl -s http://localhost:health` | Health check |
| Network | `cat /etc/resolv.conf` | DNS config |

#### Scenario: Execute quick command
- **WHEN** user selects "df -h" from the quick commands dropdown
- **THEN** the system SHALL insert `df -h\n` into the terminal input as if typed
- **AND** the command SHALL execute in the container
- **AND** the output SHALL appear in the terminal

#### Scenario: Save custom quick command
- **WHEN** user creates a new quick command `kubectl get pods` with description "List pods"
- **THEN** the system SHALL save it to the user's quick commands list
- **AND** it SHALL appear in future terminal sessions

### Requirement: Connection Health and Reconnection

The terminal SHALL display real-time connection status with the following states:

| State | Indicator | Action |
|-------|-----------|--------|
| Connecting | Yellow spinner | None (automatic) |
| Connected | Green dot + "Connected" | None |
| Warning | Yellow dot + "Latency: Xms" | None |
| Disconnected | Red dot + "Disconnected" | Manual reconnect button |
| Reconnecting | Yellow spinner + "Reconnecting..." | Cancel button |
| Expired | Orange banner + "Session expired" | Reconnect button |

When the Socket.IO connection drops unexpectedly, the terminal SHALL:

1. Display a "Connection lost — reconnecting..." message in the terminal output
2. Automatically attempt to reconnect using Socket.IO's built-in reconnect mechanism (max 3 attempts with exponential backoff)
3. If reconnection succeeds, display "Reconnected — session restored" and resume the terminal
4. If reconnection fails after all attempts, display "Connection lost — click to reconnect" with a button
5. Note: Reconnection to the same exec stream is NOT possible at the K8s level (exec is single-use). The user MUST start a new exec session on reconnection.

#### Scenario: Connection drops and auto-reconnect fails
- **WHEN** the network disconnects during a terminal session
- **THEN** the terminal SHALL show "Connection lost — reconnecting..." in the output
- **AND** after 3 failed reconnect attempts, the terminal SHALL show a reconnect button
- **AND** the session recording SHALL be finalized with exit status "connection-lost"

#### Scenario: User manually reconnects
- **WHEN** the connection is lost and user clicks "Reconnect"
- **THEN** the system SHALL start a new exec session to the same pod/container/namespace
- **AND** the terminal SHALL be cleared and ready for a new shell prompt

### Requirement: Fullscreen Terminal Toggle

The terminal view SHALL provide a fullscreen toggle that expands the terminal to fill the entire browser viewport (minus top navigation if user prefers). In fullscreen mode:

- The terminal font SHALL remain at the user-configured size
- All toolbar controls SHALL be accessible via a floating overlay bar
- Pressing Escape SHALL exit fullscreen mode
- Clicking the exit fullscreen button SHALL also work

#### Scenario: Enter fullscreen
- **WHEN** user clicks the "Fullscreen" button on a terminal tab
- **THEN** the terminal SHALL expand to fill the viewport
- **AND** a floating overlay bar SHALL provide controls for exit, font size, and other settings

### Requirement: Clipboard Integration

The terminal SHALL support clipboard operations:

- Copy: Ctrl+Shift+C (or Cmd+C on Mac) copies selected terminal text to clipboard, with ANSI codes stripped for plain-text copy
- Paste: Ctrl+Shift+V (or Cmd+V on Mac) pastes clipboard content into the terminal, sending it as keystrokes to the exec stream
- Right-click context menu SHALL show "Copy" (if text selected) and "Paste" options
- Single-click paste button on the terminal toolbar (visible for quick paste from clipboard)

#### Scenario: Copy terminal text
- **WHEN** user selects text in the terminal and presses Ctrl+Shift+C
- **THEN** the system SHALL copy the plain text (without ANSI codes) to the clipboard
- **AND** a toast notification SHALL confirm "Copied to clipboard"

#### Scenario: Paste text into terminal
- **WHEN** user presses Ctrl+Shift+V
- **THEN** the system SHALL read clipboard content and send it as `exec-input` events to the container
- **AND** the pasted text SHALL appear in the terminal

### Requirement: Multi-Container Selection

When a pod has multiple containers, the terminal SHALL allow the user to select which container to exec into. The terminal SHALL:

- Present a container selection dialog when opening a terminal to a multi-container pod
- Default to the first container alphabetically (or the container with the same name as the pod)
- Remember the user's last container choice per pod (stored in localStorage)
- Allow switching containers via a dropdown in the terminal toolbar (which closes the current session and opens a new one)

#### Scenario: Select container for multi-container pod
- **WHEN** user opens a terminal for a pod with 3 containers (app, proxy, logger)
- **THEN** the system SHALL display a container selection dialog listing all 3 containers
- **AND** after the user selects "proxy", the terminal SHALL exec into the proxy container

### Requirement: Security and Access Control

All exec operations SHALL respect the existing KubeDash RBAC model:

- Viewer role: Cannot open terminal sessions (button hidden or disabled with "Insufficient permissions" tooltip)
- Operator role: Can open terminals in assigned namespaces only
- Admin role: Can open terminals in any namespace
- All exec sessions SHALL be recorded (recording cannot be disabled by end users)
- Session recordings SHALL only be accessible to Admin role and the session owner
- All exec actions SHALL be subject to per-user K8s token scoping (user must have `pods/exec` permission)

#### Scenario: Viewer attempts to open terminal
- **WHEN** a user with Viewer role clicks the terminal button
- **THEN** the system SHALL display "Terminal access requires Operator or Admin role"
- **AND** No terminal session SHALL be created

#### Scenario: Insufficient K8s permissions
- **WHEN** a user with valid KubeDash role but no `pods/exec` RBAC permission in Kubernetes tries to exec into a pod
- **THEN** the exec SHALL be denied by the K8s API server (enforced by per-user token) and the terminal SHALL display "Permission denied: no pods/exec access for this pod"

### Requirement: Terminal Configuration

The terminal SHALL support user-configurable settings saved in localStorage:

| Setting | Default | Options |
|---------|---------|---------|
| Font size | 14px | 10px - 20px |
| Font family | 'Cascadia Code', 'Fira Code', monospace | Any monospace font |
| Cursor style | Block | Block, Underline, Bar |
| Cursor blink | On | On/Off |
| Scrollback lines | 5000 | 1000 - 50000 |
| Bell style | None | None, Sound, Visual |
| Tab max count | 8 | 1 - 16 |

Settings SHALL be persistent across browser sessions.
