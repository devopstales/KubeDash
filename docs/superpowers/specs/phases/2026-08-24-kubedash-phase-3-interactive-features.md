# Phase 3: Interactive Features — Cloud Shell, Exec, Logs

## Goal
Add interactive cluster debugging capabilities: socket-based pod exec, real-time log streaming, and a web-based cloud shell.

## Scope

### In Phase 3
- Socket-based pod exec terminal via Flask-SocketIO
- Real-time log streaming with follow mode
- Cloud shell with configurable base image
- xterm.js frontend integration
- Advanced workload management (scale, restart)

### Out of Phase 3
- kdlogin kubectl plugin
- Multi-cluster support
- Advanced CRD rendering
- Documentation site
- Security hardening

---

## Key Components

### 1. Pod Exec Terminal
- WebSocket namespace `/exec` for bidirectional terminal I/O
- `kubernetes.stream` for pod exec connection
- xterm.js for terminal emulation in browser
- Support for multiple concurrent terminal sessions

### 2. Log Viewer
- WebSocket-based log streaming from Kubernetes pods
- Real-time log tail with follow mode
- Log level filtering and search
- Container selection for multi-container pods

### 3. Cloud Shell
- Web-based terminal accessible from KubeDash UI
- Configurable base image (default: `bitnami/kubectl:latest`)
- Runs as a pod in the user's selected namespace
- Flask-SocketIO for terminal I/O
- Pre-installed tools: kubectl, helm, kustomize, git
- Resource limits configurable per namespace or globally
- Session timeout and idle disconnect

### 4. Advanced Workload Management
- Scale deployments
- Restart pods
- View pod details, environment variables, security context, volumes

---

## WebSocket Namespaces

| Namespace | Purpose |
|-----------|---------|
| `/exec` | Pod exec terminal I/O |
| `/logs` | Log streaming |
| `/cloudshell` | Cloud shell terminal I/O |
| `/flux` | GitOps real-time updates (if Phase 2 installed) |

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/exec` | WebSocket | Pod exec terminal |
| `/api/v1/logs` | WebSocket | Log streaming |
| `/api/v1/cloudshell` | WebSocket | Cloud shell terminal |
| `/api/v1/workloads/scale` | POST | Scale deployment |
| `/api/v1/workloads/restart` | POST | Restart pod |

---

## Frontend Components

- xterm.js for terminal emulation
- Log viewer with ANSI color support
- Cloud shell launcher modal
- Workload action buttons (scale, restart)

---

## Database Changes

- Cloud shell session state table
- Exec session tracking (optional)

---

## Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|--------------|
| 1 | User can open terminal to a pod container | Terminal connects, commands execute |
| 2 | User can stream pod logs in real-time | Logs appear with follow mode |
| 3 | User can launch cloud shell | Shell pod starts, terminal connects |
| 4 | Cloud shell respects resource limits | Pod has configured CPU/memory limits |
| 5 | User can scale deployments | Deployment replica count changes |
| 6 | User can restart pods | Pod restarts successfully |

---

## Dependencies Added

| Dependency | Purpose |
|------------|---------|
| xterm.js | Terminal emulation (frontend) |
| xterm-addon-fit | Terminal fit addon |
| xterm-addon-web-links | Web links addon |
