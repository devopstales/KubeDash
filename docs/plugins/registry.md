# Registry Plugin for KubeDash

Provides container registry management and integration.

## Features

- Registry server configuration
- Image repository browsing
- Registry authentication
- Image vulnerability scanning integration

## Structure

```
registry/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── helpers.py           # Helper functions
├── model.py             # Database models
├── registry.py          # Registry operations
├── registry_server.py   # Registry server management
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
registry = true
```

## API Endpoints

- `GET /plugins/registry` - Registry resources list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
