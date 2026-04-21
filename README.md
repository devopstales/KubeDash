# KubeDash

KubeDash is a general purpose, python based Kubernetes Dashboard. It allows users to observe applications running in the cluster and troubleshoot them, as well as manage the cluster itself.

KubeDash was created to be a Kubernetes web UI that has the traditional functionality of other web UIs/dashboards available (i.e. to list and view resources) as well as other features.

The default login is admin / admin

## Quickstart

### Minimal-Config Mode (Zero Configuration)

KubeDash can start without any configuration file — simply run it and it will use built-in defaults:

```bash
kubedash run
```

In minimal-config mode:
- **Database**: SQLite (stored at `~/.local/share/kubedash/kubedash.sqlite` or `$XDG_DATA_HOME/kubedash/kubedash.sqlite`)
- **Sessions**: SQLAlchemy (stored in the SQLite database)
- **Authentication**: Kubernetes kubeconfig-based auth
- **Replica mode**: Single replica only

This mode is ideal for local development, quick testing, and evaluation.

### Full Configuration Mode

For production deployments, create a `kubedash.ini` file:

```ini
[database]
type = postgres
host = 127.0.0.1:5432
name = kubedash

[remote_cache]
redis_enabled = true
redis_host = 127.0.0.1
redis_port = 6379
```

When `kubedash.ini` is present, all settings from the file take precedence over built-in defaults.

### Configuration Precedence

1. **Environment variables** (e.g. `DATABASE_URL`, `SESSION_REDIS_URL`)
2. **`kubedash.ini`** file (if present)
3. **Built-in defaults** (used when no config file exists)

## Limitations of Minimal-Config Mode

Minimal-config mode has several intentional limitations compared to full configuration:

| Feature | Minimal Mode | Full Mode |
|---------|-------------|-----------|
| Database | SQLite only | PostgreSQL, SQLite |
| Session backend | SQLAlchemy | Redis, SQLAlchemy, Filesystem |
| OIDC/External auth | Disabled | Enabled |
| Leader election | Disabled | Enabled (multi-replica) |
| Replica mode | Single only | Single or Cluster |

These limitations exist because features like Redis sessions, OIDC, and leader election require explicit configuration for security and reliability reasons.

## Transitioning to Full Configuration

To move from minimal-config mode to a full `kubedash.ini` configuration:

1. **Stop KubeDash**: `Ctrl+C` or kill the process
2. **Create `kubedash.ini`**: Copy the example configuration and customize it
3. **Migrate data (optional)**: If you want to keep your SQLite data, export it and import into PostgreSQL
4. **Restart KubeDash**: It will automatically detect the config file and use full mode

You can verify which mode is active via the health endpoint:

```bash
curl http://localhost:8000/api/health/ready | jq '.config_mode'
# Returns "minimal" or "full"
```

## AI-assisted development

If you use Cursor on this repo, install the **Superpowers** plugin and read [`AGENTS.md`](AGENTS.md) for shared expectations (brainstorming before features, systematic debugging, verification before claiming work complete).
