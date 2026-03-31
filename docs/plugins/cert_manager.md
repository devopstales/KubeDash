# Cert Manager Plugin for KubeDash

Provides visualization and management of cert-manager resources in Kubernetes clusters.

## Features

- Certificate request management
- Issuer configuration (ClusterIssuer, Issuer)
- Certificate status visualization
- ACME challenge monitoring

## Structure

```
cert_manager/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── functions.py         # Helper functions for cert-manager operations
├── helper.py            # Additional utilities
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
cert_manager = true
```

## API Endpoints

- `GET /plugins/cert-manager` - Cert-manager resources list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```

## References

- cert-manager documentation: https://cert-manager.io/
