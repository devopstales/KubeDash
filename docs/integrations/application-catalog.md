# Application Catalog

The Application Catalog plugin allows you to manage and embed external applications directly within KubeDash. This feature enables you to create a unified dashboard experience by integrating third-party tools, monitoring systems, and other web applications.

## Overview

The Application Catalog provides:

- **Application Management**: Add, edit, and remove external applications
- **Embedded Applications**: Embed applications directly in KubeDash using iframes
- **Application Links**: Quick access to external tools from the KubeDash menu
- **Security Integration**: Automatic Content Security Policy (CSP) updates for embedded apps
- **HTTPS Proxy**: Secure proxy for embedding HTTP applications in HTTPS dashboards

## Features

### Application Management

- **Create Applications**: Add new applications with name, URL, icon, and embedding options
- **Update Applications**: Modify application settings including URL, icon, and enabled status
- **Delete Applications**: Remove applications from the catalog
- **Enable/Disable**: Toggle applications on/off without deleting them

### Embedded Applications

Applications can be embedded directly in KubeDash pages using iframes. The plugin includes:

- **Iframe Proxy**: Proxies requests to embedded applications, allowing HTTPS dashboards to embed HTTP applications securely
- **URL Rewriting**: Automatically rewrites relative URLs in embedded HTML to work through the proxy
- **CSP Management**: Automatically updates Content Security Policy to allow embedding
- **CORS Handling**: Manages CORS headers for embedded applications

### Configuration Sync

Applications can be configured in two ways:

1. **Configuration File**: Define applications in `kubedash.ini` under `[application_list]` section
2. **Database**: Manage applications through the UI or API, stored in the database

The plugin automatically syncs configuration file entries with the database on startup.

## Configuration

### Configuration File Setup

Add applications to your `kubedash.ini` file:

```ini
[application_list]
# Application 1
app_1_name = Jaeger
app_1_url = http://jaeger.example.com:16686
app_1_icon = https://www.jaegertracing.io/img/jaeger-icon.svg
app_1_embed = true
app_1_enable = true

# Application 2
app_2_name = Grafana
app_2_url = https://grafana.example.com
app_2_icon = https://grafana.com/static/img/menu/grafana2.svg
app_2_embed = false
app_2_enable = true

# Application 3
app_3_name = Prometheus
app_3_url = http://prometheus.example.com:9090
app_3_embed = true
app_3_enable = true
```

### Configuration Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `app_{n}_name` | Application display name | Yes |
| `app_{n}_url` | Full URL to the application | Yes |
| `app_{n}_icon` | Icon URL or base64 encoded image | No |
| `app_{n}_embed` | Whether to embed in iframe (true/false) | No (default: false) |
| `app_{n}_enable` | Whether application is enabled (true/false) | No (default: true) |

### Plugin Activation

Enable the plugin in `kubedash.ini`:

```ini
[plugins]
application_catalog = true
iframe_proxy = true
```

!!! note
    The `iframe_proxy` plugin is required for embedding applications. It's automatically enabled when `application_catalog` is enabled.

## Usage

### Accessing Applications

Applications can be accessed in several ways:

1. **Direct URL**: Navigate to `/plugins/app-catalog/{application_name}`
2. **Settings Page**: Manage applications at `/plugins/app-catalog/settings`
3. **Menu Integration**: Applications appear in the KubeDash menu (if configured)

### Embedded Applications

When an application is configured with `embed = true`, it will be:

- Embedded in an iframe on the application page
- Proxied through KubeDash if using HTTP (for HTTPS dashboards)
- Automatically have URLs rewritten to work through the proxy

### Non-Embedded Applications

Applications with `embed = false` will:

- Open in a new tab/window when accessed
- Use the original URL directly
- Not require proxy or URL rewriting

## API Reference

The Application Catalog provides REST API endpoints for programmatic management. The API is automatically registered under the plugins API namespace.

### Base Path

All API endpoints are under `/api/v1/plugins/application-catalog`

!!! note
    The API is registered as a plugin API, so it's under `/api/v1/plugins/` rather than directly under `/api/v1/`. This is consistent with other plugin APIs in KubeDash.

### JavaScript API Usage

The Application Catalog UI uses JavaScript to interact with the API. The frontend makes asynchronous calls using the Fetch API with proper error handling and CSRF token management.

#### Loading Applications

The UI loads applications on page load using a GET request:

```javascript
async function loadApplications() {
    const apiUrl = '/api/v1/plugins/application-catalog';
    const response = await fetch(apiUrl);
    const data = await response.json();
    const apps = data.data || [];
    populateApplicationsTable(apps);
}
```

#### Creating Applications

Applications are created via POST with JSON payload:

```javascript
const response = await fetch('/api/v1/plugins/application-catalog', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf_token,
    },
    body: JSON.stringify({
        application_name: 'My App',
        application_url: 'https://app.example.com',
        application_icon: 'https://app.example.com/icon.svg',
        application_enabled: true,
        application_embedded: false
    })
});
```

#### Updating Applications

Applications are updated via PUT:

```javascript
const response = await fetch(`/api/v1/plugins/application-catalog/${encodeURIComponent(appName)}`, {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf_token,
    },
    body: JSON.stringify(updatedData)
});
```

#### Deleting Applications

Applications are deleted via DELETE:

```javascript
const response = await fetch(`/api/v1/plugins/application-catalog/${encodeURIComponent(appName)}`, {
    method: 'DELETE',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf_token,
    }
});
```

#### Authentication & CSRF Protection

All API calls require:
- **Authentication**: User must be logged in (handled by Flask-Login)
- **CSRF Token**: Included in `X-CSRF-Token` header for state-changing operations (POST, PUT, DELETE)

The CSRF token is obtained from the template:

```javascript
const csrf_token = {{ csrf_token()|tojson }};
```

#### Error Handling

The UI handles various error scenarios:

- **Redirects**: If the API redirects (e.g., to login), the page redirects accordingly
- **Non-JSON responses**: Redirects to login if authentication is required
- **HTTP errors**: Displays error messages to the user
- **Network errors**: Shows user-friendly error messages

```javascript
if (response.redirected) {
    window.location.href = response.url;
    return;
}
if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
}
const contentType = response.headers.get('content-type') || '';
if (!contentType.includes('application/json')) {
    // Redirect to login
    window.location.href = `/?next=${encodeURIComponent(window.location.pathname)}`;
    return;
}
```

### List Applications

```http
GET /api/v1/plugins/application-catalog
```

Returns all applications in the catalog.

**Response:**
```json
{
  "data": [
    {
      "application_name": "Jaeger",
      "application_url": "http://jaeger.example.com:16686",
      "application_icon": "https://www.jaegertracing.io/img/jaeger-icon.svg",
      "application_enabled": true,
      "application_embedded": true
    }
  ],
  "metadata": {
    "count": 1
  }
}
```

### Get Application

```http
GET /api/v1/plugins/application-catalog/{application_name}
```

Returns details for a specific application.

**Response:**
```json
{
  "data": {
    "application_name": "Jaeger",
    "application_url": "http://jaeger.example.com:16686",
    "application_icon": "https://www.jaegertracing.io/img/jaeger-icon.svg",
    "application_enabled": true,
    "application_embedded": true
  }
}
```

### Create Application

```http
POST /api/v1/plugins/application-catalog
Content-Type: application/json

{
  "application_name": "New App",
  "application_url": "https://app.example.com",
  "application_icon": "https://app.example.com/icon.svg",
  "application_enabled": true,
  "application_embedded": false
}
```

**Response:**
```json
{
  "message": "Application created successfully",
  "data": {
    "application_name": "New App",
    "application_url": "https://app.example.com",
    "application_enabled": true,
    "application_embedded": false
  }
}
```

### Update Application

```http
PUT /api/v1/plugins/application-catalog/{application_name}
Content-Type: application/json

{
  "application_name": "Updated App Name",
  "application_url": "https://app.example.com",
  "application_icon": "https://app.example.com/new-icon.svg",
  "application_enabled": true,
  "application_embedded": true
}
```

### Delete Application

```http
DELETE /api/v1/plugins/application-catalog/{application_name}
```

**Response:**
```json
{
  "message": "Application deleted successfully"
}
```

## Iframe Proxy

The iframe proxy plugin (`iframe_proxy`) enables secure embedding of applications by:

- Proxying requests from KubeDash to the target application
- Rewriting URLs in HTML responses to work through the proxy
- Handling CORS and CSP headers for embedded content
- Supporting all HTTP methods (GET, POST, PUT, DELETE, PATCH)

### Proxy URL Format

```
/plugins/iframe-proxy/{application_name}/{path}
```

For example:
- `/plugins/iframe-proxy/jaeger/` - Main page of Jaeger
- `/plugins/iframe-proxy/jaeger/api/traces` - API endpoint

### URL Rewriting

The proxy automatically rewrites:

- HTML attributes: `href`, `src`, `action`, `data-src`, etc.
- CSS `url()` functions
- `<base>` tags for proper relative URL resolution

This ensures embedded applications work correctly even when their internal URLs are relative.

## Security Considerations

### Content Security Policy

When applications are embedded, KubeDash automatically updates the Content Security Policy (CSP) to:

- Allow framing from application domains
- Maintain security while enabling embedding
- Support both HTTP and HTTPS applications

### HTTPS/HTTP Mixing

The iframe proxy allows HTTPS dashboards to embed HTTP applications securely by:

- Proxying all requests through the HTTPS KubeDash server
- Preventing mixed content warnings
- Maintaining security for the main dashboard

### Authentication

- All application catalog endpoints require authentication
- Embedded applications inherit KubeDash authentication
- Applications accessed directly (non-embedded) may require their own authentication

## API Architecture

The Application Catalog API follows KubeDash's plugin API architecture:

1. **Plugin API Registration**: The API blueprint is automatically discovered and registered under `/api/v1/plugins/`
2. **Dynamic Discovery**: The plugin system scans for `api.py` files in plugin directories
3. **Blueprint Pattern**: Uses Flask blueprints with `url_prefix="/application-catalog"`
4. **CSRF Exemption**: Plugin APIs are exempt from CSRF protection (handled by authentication)
5. **Swagger Documentation**: Automatically included in API documentation

### API Registration Flow

```
Application Catalog Plugin
  └── api.py (application_catalog_api_bp)
      └── url_prefix: "/application-catalog"
          └── Registered under: /api/v1/plugins/
              └── Final path: /api/v1/plugins/application-catalog
```

### Response Format

All API responses follow a consistent format:

**Success Response:**
```json
{
  "data": { ... },
  "metadata": { "count": 1 }
}
```

**Error Response:**
```json
{
  "error": "ErrorType",
  "message": "Human-readable error message"
}
```

## Use Cases

### Observability Stack Integration

Embed monitoring and tracing tools:

```ini
[application_list]
app_1_name = Jaeger Tracing
app_1_url = http://jaeger:16686
app_1_embed = true
app_1_enable = true

app_2_name = Grafana Dashboards
app_2_url = https://grafana:3000
app_2_embed = true
app_2_enable = true

app_3_name = Prometheus
app_3_url = http://prometheus:9090
app_3_embed = true
app_3_enable = true
```

### Development Tools

Integrate development and debugging tools:

```ini
[application_list]
app_1_name = Kubeview
app_1_url = http://kubeview:8080
app_1_embed = true
app_1_enable = true
```

### External Services

Add quick links to external services:

```ini
[application_list]
app_1_name = Kubernetes Dashboard
app_1_url = https://k8s-dashboard.example.com
app_1_embed = false
app_1_enable = true
```

## Troubleshooting

### Application Not Loading

1. **Check Application URL**: Verify the URL is accessible from the KubeDash server
2. **Check CSP**: Ensure the application domain is in the CSP `frame-src` directive
3. **Check Logs**: Review KubeDash logs for proxy errors
4. **Network Connectivity**: Ensure KubeDash can reach the application URL

### URL Rewriting Issues

If embedded applications have broken links:

1. Check that the application uses relative URLs (starting with `/`)
2. Verify the proxy is rewriting URLs correctly (check browser network tab)
3. Some applications may require specific `<base>` tag configuration

### CORS Errors

If you see CORS errors:

1. The iframe proxy should handle CORS automatically
2. Check that the application allows embedding (no `X-Frame-Options: DENY`)
3. Verify CSP settings allow the application domain

### Configuration Not Syncing

If configuration file changes aren't reflected:

1. Restart KubeDash to trigger sync
2. Check the `[application_list]` section format
3. Verify plugin is enabled: `application_catalog = true`

## Best Practices

1. **Use HTTPS**: Prefer HTTPS URLs for applications when possible
2. **Icon URLs**: Use publicly accessible icon URLs or base64 encoded images
3. **Naming**: Use descriptive, unique application names
4. **Testing**: Test embedded applications in a staging environment first
5. **Security**: Only embed trusted applications from known sources
6. **Performance**: Consider the impact of embedded applications on page load time

## Limitations

- Embedded applications must support iframe embedding (no `X-Frame-Options: DENY`)
- Some applications may not work correctly when embedded due to their architecture
- URL rewriting may not work for all JavaScript frameworks
- Large embedded applications may impact dashboard performance

