## Phase 1: Core xterm.js Terminal

- [ ] 1.1 Create `pod-exec.html.j2` Jinja2 template with terminal content area and basic toolbar (pod selector, connection status indicator)
- [ ] 1.2 Add xterm.js v5.x script references (CDN or local) — xterm.js, xterm-addon-fit, xterm-addon-web-links, xterm-addon-attach
- [ ] 1.3 Implement `static/js/terminal/terminal_tab.js` — single TerminalTab class with xterm.js initialization, Socket.IO connection to `/exec` namespace, input/output loop via existing `pod_exec` / `response` / `exec-input` / `closed` / `stop` events
- [ ] 1.4 Implement `static/js/terminal/terminal_settings.js` — TerminalSettings class for loading/saving user preferences (font size, font family, cursor style, scrollback, bell, max tabs) to localStorage
- [ ] 1.5 Implement `static/js/terminal/terminal_init.js` — initialization script that instantiates TerminalManager, reads config from template data attributes, and wires up UI controls
- [ ] 1.6 Add UI routes in workloads blueprint for terminal view page (accessible from Pod detail page)
- [ ] 1.7 Implement tab bar UI component with pod name display, status indicator (connecting/connected/disconnected), and close button
- [ ] 1.8 Add CSS styles for terminal view matching KubeDash design system (dark background, monospace font, status bar, toolbar)
- [ ] 1.9 Implement FitAddon integration for responsive terminal sizing on container resize
- [ ] 1.10 Implement WebLinksAddon for clickable URLs in terminal output
- [ ] 1.11 Write unit tests for SessionRecorder (record, sync, finalize event format and timing)

## Phase 2: Multi-Tab Management and Quick Commands

- [ ] 2.1 Implement `static/js/terminal/terminal_manager.js` — TabManager class for managing multiple TerminalTab instances (open, close, reorder, activate, limit enforcement)
- [ ] 2.2 Add pod selector dialog for new tabs (select namespace, workload, pod, container) using existing KubeDash workload browse components
- [ ] 2.3 Implement tab rename (double-click tab name → inline text input)
- [ ] 2.4 Implement close confirmation dialog for tabs with active exec sessions
- [ ] 2.5 Implement quick commands panel (`static/js/terminal/quick_commands.js`) with default preset library categorized by Filesystem, System Info, Logs, Debugging, Network
- [ ] 2.6 Add quick command dropdown/sidebar UI to terminal template with one-click execution (inserts command into terminal with newline)
- [ ] 2.7 Implement custom quick command creation (user adds, edits, removes commands, saved to localStorage with optional server sync)
- [ ] 2.8 Add `GET/PUT /api/v1/user/quick-commands` REST endpoints for server-side quick command persistence
- [ ] 2.9 Implement tab status indicators (green=connected, yellow=connecting, red=disconnected, orange=expired)
- [ ] 2.10 Implement container selection dialog for multi-container pods (defaults to first container, remembers selection)
- [ ] 2.11 Write unit tests for TerminalManager (tab open/close, limit enforcement, active tab switching)
- [ ] 2.12 Write functional tests for quick commands execution flow

## Phase 3: Session Recording and Audit

- [ ] 3.1 Create Alembic migration for `exec_sessions` and `exec_session_events` database tables
- [ ] 3.2 Implement SQLAlchemy models for exec_sessions and exec_session_events in `kubedash-ui/models/exec_session.py`
- [ ] 3.3 Implement `static/js/terminal/session_recorder.js` — SessionRecorder with event capture, batch sync (every 10 seconds or 100 events), and finalization on session end
- [ ] 3.4 Implement `POST /api/v1/exec/sessions/<id>/events` endpoint for receiving event batches from frontend
- [ ] 3.5 Implement `PUT /api/v1/exec/sessions/<id>/metadata` endpoint for session metadata save
- [ ] 3.6 Implement `GET /api/v1/exec/sessions` endpoint with query filtering (user_id, namespace, pod, date range, exit_status) and pagination
- [ ] 3.7 Implement `GET /api/v1/exec/sessions/<id>/events` endpoint for session replay data retrieval with pagination
- [ ] 3.8 Create `exec-sessions.html.j2` admin template for viewing recorded sessions list with sortable columns and filters
- [ ] 3.9 Implement session detail view with basic info display and "Replay" button
- [ ] 3.10 Implement session recording finalization on session end — finalize recorder with exit status, save to database, write AuditLog entry
- [ ] 3.11 Add audit log entries for exec session start (user, namespace, pod, container, start time) and end (duration, exit status)
- [ ] 3.12 Implement RBAC enforcement on session endpoints (Admin: all sessions, user: own sessions only)
- [ ] 3.13 Write integration tests for session recording API (save events, retrieve, filter, paginate)
- [ ] 3.14 Write unit tests for exec session models and repository functions

## Phase 4: Timeout, Reconnection, and Polish

- [ ] 4.1 Implement session timeout with configurable `max_session_minutes` (default: 30) and `warning_before_minutes` (default: 5) from `kubedash.ini`
- [ ] 4.2 Add timeout warning banner UI showing countdown timer ("Session will expire in X minutes")
- [ ] 4.3 Implement session expiration handling — clean close exec stream, finalize recording, show "Session expired — click Reconnect" with reconnect button
- [ ] 4.4 Implement Socket.IO disconnection handling — detect drop, show "Connection lost — reconnecting...", auto-reconnect (3 attempts), manual reconnect button on failure
- [ ] 4.5 Reconnect flow: start new exec session to same pod/container (note: K8s exec is single-use, so terminal is cleared)
- [ ] 4.6 Implement fullscreen toggle — expand terminal to full viewport, floating overlay bar for controls, Escape to exit
- [ ] 4.7 Implement clipboard integration — Ctrl+Shift+C for copy (ANSI-stripped), Ctrl+Shift+V for paste, right-click context menu
- [ ] 4.8 Add font size controls (Ctrl+Plus/Minus, toolbar buttons, 10px-20px range)
- [ ] 4.9 Add cursor style selector (Block/Underline/Bar) and cursor blink toggle in settings
- [ ] 4.10 Implement scrollback configuration (1000-50000 lines, default 5000)
- [ ] 4.11 Add bell style configuration (None/Sound/Visual)
- [ ] 4.12 Implement `GET /api/v1/workloads/pods?namespace=...` endpoint for pod browsing in terminal tab selector (reuse existing if available)
- [ ] 4.13 Viewer role enforcement: hide/disable terminal button with tooltip explaining role requirement
- [ ] 4.14 Add session replay feature — SessionPlayback class that reads events and replays output with timing (1x, 2x, 5x, 10x speed options)
- [ ] 4.15 Add "REPLAY" banner during session playback to distinguish from live sessions
- [ ] 4.16 Write functional tests for timeout behavior (warning, expiration, cleanup)
- [ ] 4.17 Write functional tests for reconnection handling (disconnect, auto-reconnect, fail, manual reconnect)
- [ ] 4.18 Performance test terminal with high-throughput output (100+ lines/sec)
- [ ] 4.19 Write user documentation: using terminal, tabs, quick commands, session recording (audit)
- [ ] 4.20 Write admin documentation: viewing session recordings, session retention configuration, compliance guide
- [ ] 4.21 Add feature flag for progressive rollout (enable via `kubedash.ini` config)
