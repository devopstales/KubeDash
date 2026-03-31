# FluxCD Plugin for KubeDash

Provides visualization and management of FluxCD GitOps objects.

## Features

- **Sources**: GitRepository, HelmRepository, OCIRepository, Bucket
- **Reconcilers**: Kustomization, HelmRelease
- **Notifications**: Alert, Provider, Receiver
- Real-time status updates via WebSocket
- Interactive dependency graph visualization
- Suspend/Resume/Sync actions

## Structure

```
flux/
├── __init__.py          # Blueprint registration & main routes
├── api.py               # REST API endpoints
├── actions.py           # Suspend, Resume, Sync actions
├── details.py           # Flux object details helpers
├── graph.py             # Dependency graph building
├── helm_releases.py     # HelmRelease operations
├── kustomizations.py    # Kustomization operations
├── notifications.py     # Alert/Provider/Receiver operations
├── sources.py           # Git/Helm/OCI/Bucket repository operations
├── websocket.py         # WebSocket handlers for real-time updates
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
flux = true
```

## API Endpoints

- `GET /plugins/flux` - Main Flux objects list view
- `GET /plugins/flux/detail/<kind>/<namespace>/<name>` - Detail view
- `GET /plugins/flux/api/graph` - Graph data for visualization
- `GET /plugins/flux/api/summary` - Summary counts and status
- `POST /plugins/flux/suspend` - Suspend action
- `POST /plugins/flux/resume` - Resume action
- `POST /plugins/flux/sync` - Sync action

## WebSocket Events

- `flux_update` - Real-time Flux object status updates

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
