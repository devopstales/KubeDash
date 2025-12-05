# Pod Debugging

KubeDash provides powerful debugging capabilities for pods, including real-time log streaming and interactive terminal access.

## Pod Logs

View container logs in real-time directly from the web UI.

### Accessing Pod Logs

1. Navigate to `Workloads > Pods`
2. Find the pod you want to debug
3. Click the **Logs** icon (or select "Logs" from the pod menu)

![Pod Logs](../img/debugging/pod-logs.png)

### Log Features

| Feature | Description |
|---------|-------------|
| **Real-time streaming** | Logs update automatically via WebSocket |
| **Container selection** | Choose which container's logs to view |
| **Init containers** | View logs from init containers |
| **Auto-scroll** | Automatically scroll to new log entries |

### Selecting Containers

If your pod has multiple containers:

1. Use the container dropdown to select the desired container
2. Logs will automatically switch to the selected container

For init containers, select them from the "Init Containers" section of the dropdown.

### Log Output

The log viewer displays:

- Timestamped log entries (if available from the container)
- Color-coded output for better readability
- Scrollable history

!!! tip
    For large log volumes, consider using the terminal to run `kubectl logs` with additional filtering options like `--since` or `--tail`.

## Pod Terminal (Exec)

Execute commands directly in a running container using an interactive web terminal.

### Accessing the Terminal

1. Navigate to `Workloads > Pods`
2. Find the pod you want to access
3. Click the **Terminal** icon (or select "Exec" from the pod menu)

![Pod Terminal](../img/debugging/pod-exec.png)

### Terminal Features

| Feature | Description |
|---------|-------------|
| **Interactive shell** | Full TTY support for interactive commands |
| **Container selection** | Choose which container to exec into |
| **Real-time I/O** | WebSocket-based communication |
| **Standard shell** | Uses `/bin/sh` by default |

### Using the Terminal

Once connected, you have a full shell session:

```bash
# Check running processes
ps aux

# View environment variables
env

# Check network connectivity
ping -c 3 google.com

# View files
ls -la /app

# Check resource usage
top
```

### Container Selection

If your pod has multiple containers:

1. Use the container dropdown before connecting
2. Select the container you want to access
3. The terminal will connect to that specific container

### Troubleshooting

**Connection Issues:**

- Ensure the pod is in `Running` state
- Verify the container has a shell available (`/bin/sh` or `/bin/bash`)
- Check that your user has RBAC permissions for `pods/exec`

**No Shell Available:**

Some minimal containers (like `distroless`) don't include a shell. In these cases:

- Use `kubectl debug` to attach an ephemeral debug container
- Consider using a different base image for debugging

!!! warning "Security Note"
    Pod exec access is a powerful capability. Ensure proper RBAC controls are in place to restrict who can access container shells.

## Best Practices

### Debugging Workflow

1. **Check pod status** - Verify the pod is running and healthy
2. **Review events** - Check for scheduling or runtime issues
3. **View logs** - Look for application errors or warnings
4. **Access terminal** - Investigate further if needed

### Common Debugging Commands

Once in a pod terminal:

```bash
# Check DNS resolution
nslookup kubernetes.default

# Test service connectivity
curl -v http://service-name:port/health

# Check mounted secrets/configmaps
cat /path/to/mounted/secret

# View resource limits
cat /sys/fs/cgroup/memory/memory.limit_in_bytes

# Check network interfaces
ip addr
```

### When to Use Each Tool

| Scenario | Recommended Tool |
|----------|-----------------|
| Application errors | Pod Logs |
| Startup failures | Pod Logs (init containers) |
| Network issues | Pod Terminal |
| File system inspection | Pod Terminal |
| Environment verification | Pod Terminal |
| Real-time monitoring | Pod Logs |
