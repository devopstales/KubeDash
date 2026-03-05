# Gateway API Plugin for KubeDash

Provides visualization and management of Kubernetes Gateway API resources.

## Features

- Gateway class management
- Gateway configuration
- HTTPRoute and TCPRoute visualization
- Traffic routing inspection

## Structure

```
gateway_api/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── functions.py         # Helper functions for Gateway API operations
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
gateway_api = true
```

## API Endpoints

- `GET /plugins/gateway-api` - Gateway API resources list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```

## References

- Gateway API documentation: https://gateway-api.sigs.k8s.io/
