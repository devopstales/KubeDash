# Helm Plugin for KubeDash

Provides visualization and management of Helm charts in Kubernetes clusters.

## Features

- List Helm charts across namespaces
- View chart details and values
- Client-side data loading via JavaScript API calls

## Structure

```
helm/
├── __init__.py      # Blueprint registration
├── api.py           # REST API endpoints
├── functions.py     # Helper functions for Helm operations
└── README.md        # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
helm = true
```

## API Endpoints

- `GET /plugins/helm-chart` - Helm charts list view
- `GET /plugins/helm-charts/data` - Helm chart data view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
