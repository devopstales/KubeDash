# Trivy Operator Plugin for KubeDash

Provides visualization of Trivy Operator security scan results.

## Features

- Vulnerability scan results
- Config audit reports
- RBAC assessment reports
- Exposed secret detection
- Compliance reports

## Structure

```
trivy_operator/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── functions.py         # Helper functions for Trivy operations
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
trivy_operator = true
```

## API Endpoints

- `GET /plugins/trivy-operator` - Trivy operator resources list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```

## References

- Trivy Operator documentation: https://aquasecurity.github.io/trivy-operator/
