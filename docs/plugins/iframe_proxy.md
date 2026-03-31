# iframe_proxy Plugin for KubeDash

Provides proxy functionality for embedding external applications within KubeDash.

## Features

- Proxy requests to embedded applications
- HTTPS dashboard can embed HTTP applications
- URL rewriting for relative paths
- CORS and CSP header management
- Theme synchronization support

## Structure

```
iframe_proxy/
├── __init__.py          # Blueprint registration & proxy logic
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
iframe_proxy = true
```

## API Endpoints

- `GET/POST/PUT/DELETE/PATCH /plugins/iframe-proxy/<app_name>/<path>` - Proxy requests

## How It Works

1. Application URL is stored in the `applications` database table
2. Requests to `/plugins/iframe-proxy/<app_name>/<path>` are proxied to the application
3. Relative URLs in HTML responses are rewritten to go through the proxy
4. JavaScript intercepts `fetch()` and `XMLHttpRequest` for dynamic content

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
