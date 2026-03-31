# Application Catalog Plugin for KubeDash

Provides an application catalog for managing and deploying applications.

## Features

- Application catalog browsing
- Application deployment
- Application lifecycle management
- Embedded application proxy integration

## Structure

```
application_catalog/
├── __init__.py          # Blueprint registration
├── api.py               # REST API endpoints
├── application.py       # Application operations
├── helpers.py           # Helper functions
├── model.py             # Database models
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
application_catalog = true
```

## API Endpoints

- `GET /plugins/application-catalog` - Application catalog list view

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
