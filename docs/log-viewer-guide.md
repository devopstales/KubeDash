# Enhanced Log Viewer User Guide

## Overview

The KubeDash Enhanced Log Viewer provides a rich, interactive log viewing experience for Kubernetes pods. It replaces the basic raw log output with filtering, search, export, and multi-pod aggregation capabilities.

## Accessing the Log Viewer

### Single Pod Logs
1. Navigate to **Workloads > Pods**
2. Click on a pod name
3. Click **Logs** in the breadcrumb navigation
4. Or directly access: `/workload/pods/logs/enhanced?po_name=<pod-name>`

### Multi-Pod Logs (Workload Level)
1. Navigate to **Workloads > Deployments** (or StatefulSets, DaemonSets, ReplicaSets)
2. Click on a workload name
3. Click the **View All Logs** button in the header
4. This opens a merged view of all pods belonging to that workload

## Toolbar Controls

The log viewer toolbar provides several controls for managing your log viewing experience:

### Container Selector
- For multi-container pods, use the dropdown to switch between containers
- Init containers are shown in a separate group

### Auto-Scroll Toggle
- **Enabled (default)**: New log lines automatically scroll the view to the bottom
- **Disabled**: Scroll up to review historical lines without being pushed to the bottom
- The viewer detects manual scrolling and adjusts accordingly

### Timestamps Toggle
- **Enabled (default)**: Shows ISO 8601 timestamps for each log line
- **Disabled**: Hides the timestamp column for a cleaner view
- Timestamps are always captured; this only affects display

### Level Filter
- Click the **All Levels** dropdown to filter by log severity
- Available levels: **ERROR**, **WARN**, **INFO**, **DEBUG**, **FATAL**
- Uncheck levels you want to hide
- The button shows how many levels are currently active
- Filtering is real-time and doesn't require re-fetching logs

## Search

The search bar allows full-text search across all displayed log lines:

1. **Enter search text**: Type your query in the search input
2. **Match count**: Shows "X matches" for the current query
3. **Navigate matches**: Use the ▲ (previous) and ▼ (next) buttons
4. **Keyboard shortcuts**:
   - `Enter`: Next match
   - `Shift+Enter`: Previous match
5. **Clear search**: Click the × button or clear the input
6. **Highlighting**: Current match has a brighter highlight

Search features:
- Case-insensitive by default
- 300ms debounce for performance
- Works across all visible log lines
- Respects active level filters

## Export

Download the current log buffer for offline analysis:

1. Click the **Export** button
2. Select format from the dropdown:
   - **Text (.log)**: Plain text with timestamps and pod prefixes
   - **JSON (.jsonl)**: JSON Lines format with structured data
3. The file downloads with a timestamp-based filename: `<pod-name>-<timestamp>.log`

Export includes:
- All currently visible lines (respects filters)
- Timestamps (ISO 8601 format)
- Pod name prefix (for multi-pod views)
- Container name (if applicable)

## Status Bar

The status bar at the bottom shows:

- **Connection state**:
  - 🟡 **Connecting...**: Establishing connection to K8s API
  - 🟢 **Streaming**: Actively receiving log lines
  - ⚪ **Disconnected**: Connection lost
  - 🔴 **Connection Error**: Error occurred
  - 🔵 **Completed**: Stream ended

- **Buffer usage**: Shows "X / Y lines" with:
  - Normal: Black text
  - Warning (>80%): Yellow text
  - Critical (>90%): Red text

- **Total lines**: Total lines received and evicted from buffer

- **Reconnect button**: Appears when disconnected; click to retry

## User Preferences

The log viewer saves your preferences in browser localStorage:

- **Buffer size**: Maximum lines to keep (default: 10,000)
- **Auto-scroll**: Default auto-scroll behavior
- **Timestamps**: Default timestamp visibility
- **Favorite levels**: Which levels to show by default

Preferences persist across sessions and are loaded automatically.

## Multi-Pod Mode

When viewing logs for a workload (Deployment, StatefulSet, etc.):

### Features
- **Merged chronological view**: Logs from all pods merged by timestamp
- **Pod name prefixes**: Each line shows which pod it came from
- **Color coding**: Each pod has a consistent color for easy identification
- **Auto-discovery**: New pods appearing during the session are automatically added (polls every 30s)
- **Global filtering**: Level filters apply across all pods

### Pod Selector
- Shows all pods currently being streamed
- Click a pod name to filter to just that pod
- Click "All Pods" to show merged view again

### Per-Pod Statistics
- Shows log level counts per pod (ERROR: 5, WARN: 12, etc.)
- Helps identify which pods are experiencing issues

## Troubleshooting

### No logs appearing
1. Check the connection state in the status bar
2. Verify the pod has containers and is running
3. Try reconnecting using the Reconnect button
4. Check browser console for errors

### Slow performance with many lines
- The viewer caps DOM nodes at 5,000 for performance
- Older lines are kept in the buffer but not rendered
- Use filters to reduce visible line count
- Consider exporting for deep analysis

### Missing log levels
- Check the level filter dropdown
- Ensure the appropriate levels are checked
- The detector uses regex patterns; custom formats may not match

### Multi-pod view not loading
- Verify the workload has running pods
- Check network connectivity to the API
- Try refreshing the page
- Ensure your user has RBAC access to the namespace

## Feature Flag

The enhanced log viewer can be enabled/disabled via `kubedash.ini`:

```ini
[features]
enhanced_log_viewer = true
```

Set to `false` to revert to the classic xterm.js-based viewer.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Next search match |
| `Shift+Enter` | Previous search match |
| `Ctrl+F` | Focus search input (browser default) |
| `Esc` | Clear search (when focused) |

## Browser Compatibility

The enhanced log viewer requires:
- Modern browser (Chrome 80+, Firefox 75+, Safari 13+, Edge 80+)
- JavaScript enabled
- localStorage support for preferences
- WebSocket support (Socket.IO)

Internet Explorer 11 is **not** supported.
