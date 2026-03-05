# External LoadBalancer Plugin for KubeDash

Provides visualization and management of external load balancer configurations.

## Features

- MetalLB configuration management
- Cilium load balancer support
- LoadBalancer service status
- IP address pool management

## Structure

```
external_loadbalancer/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── cilium.py            # Cilium load balancer operations
├── metallb.py           # MetalLB operations
├── helper.py            # Helper functions
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
external_loadbalancer = true
```

## API Endpoints

- `GET /plugins/external-loadbalancer` - External load balancer resources list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```

## References

- MetalLB documentation: https://metallb.universe.tf/
- Cilium documentation: https://cilium.io/
