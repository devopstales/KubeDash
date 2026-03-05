# KubeDash Plugin Development Guide

This guide explains how to develop plugins for KubeDash.

## Overview

KubeDash plugins extend the functionality of the dashboard by adding new features, integrations, and visualizations. Each plugin is a self-contained module that follows a standard structure.

## Plugin Structure

```
plugins/<plugin_name>/
├── __init__.py            # Blueprint registration & main routes
├── config.py              # Plugin-specific configuration (optional)
├── api.py                 # REST API endpoints (optional)
├── services/              # Business logic layer (optional)
│   ├── __init__.py
│   ├── feature1.py
│   └── feature2.py
├── models.py              # Database models (optional)
├── templates/             # UI templates (optional)
│   └── <plugin_name>/
├── static/                # Plugin-specific assets (optional)
│   ├── css/
│   └── js/
├── README.md              # Plugin documentation
└── tests/                 # Plugin tests (optional)
    └── test_<plugin_name>.py
```

## Minimal Plugin Example

A minimal plugin with just a blueprint:

```python
# plugins/my_plugin/__init__.py
#!/usr/bin/env python3

from flask import Blueprint, render_template
from flask_login import login_required

from lib.helper_functions import get_logger

##############################################################
## Variables
##############################################################

my_plugin_bp = Blueprint(
    "my_plugin",
    __name__,
    url_prefix="/plugins",
    template_folder="templates"
)
logger = get_logger()

##############################################################
## Routes
##############################################################

@my_plugin_bp.route('/my-plugin', methods=['GET'])
@login_required
def my_plugin_view():
    """My plugin main view."""
    return render_template('my_plugin/view.html.j2')
```

## Blueprint Registration

The plugin blueprint must follow the naming convention `<plugin_name>_bp`:

```python
my_plugin_bp = Blueprint(
    "my_plugin",           # Blueprint name
    __name__,              # Module name
    url_prefix="/plugins", # URL prefix
    template_folder="templates"  # Template folder (if needed)
)
```

## Enabling Plugins

Plugins are enabled in `kubedash.ini`:

```ini
[plugin_settings]
my_plugin = true
```

## REST API Endpoints

For plugins that need REST APIs, create `api.py`:

```python
# plugins/my_plugin/api.py
from flask_smorest import Blueprint
from flask_login import login_required

from lib.helper_functions import get_logger

my_plugin_api_bp = Blueprint(
    "my_plugin_api",
    "my_plugin_api",
    url_prefix="/my-plugin",
    description="My Plugin API"
)
logger = get_logger()

@my_plugin_api_bp.route('/data')
@my_plugin_api_bp.login_required
@my_plugin_api_bp.response(200)
def get_data():
    """Get plugin data."""
    return {"status": "ok"}
```

The API blueprint naming convention is `<plugin_name>_api_bp`.

## Database Models

For plugins that need database storage:

```python
# plugins/my_plugin/model.py
from lib.components import db

class MyPluginModel(db.Model):
    __tablename__ = 'my_plugin_data'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    data = db.Column(db.Text)
    
    def __repr__(self):
        return f'<MyPluginModel {self.name}>'
```

## Templates

Plugin templates go in `plugins/<plugin_name>/templates/`:

```
plugins/my_plugin/
├── templates/
│   └── my_plugin/
│       ├── view.html.j2
│       └── detail.html.j2
```

Reference in blueprint:

```python
@my_plugin_bp.route('/my-plugin')
@login_required
def my_plugin_view():
    return render_template('my_plugin/view.html.j2')
```

## Configuration

For plugins with custom configuration:

```python
# plugins/my_plugin/config.py
class MyPluginConfig:
    """Configuration for My Plugin."""
    
    DEFAULT_TIMEOUT = 30
    MAX_ITEMS = 100
    
    @classmethod
    def validate(cls, app_config):
        """Validate plugin configuration."""
        # Add validation logic
        pass
```

## Testing

Run plugin tests with Poetry:

```bash
cd src/kubedash
poetry run pytest tests/plugins/test_my_plugin.py -v
```

Example test:

```python
# tests/plugins/test_my_plugin.py
import pytest

def test_my_plugin_view(client, logged_in_client):
    """Test my plugin view."""
    # Anonymous access should redirect
    response = client.get('/plugins/my-plugin')
    assert response.status_code == 302
    
    # Logged in access should work
    response = logged_in_client.get('/plugins/my-plugin')
    assert response.status_code == 200
```

## Best Practices

1. **Follow Naming Conventions**
   - Blueprint: `<plugin_name>_bp`
   - API Blueprint: `<plugin_name>_api_bp`
   - Module files: lowercase with underscores

2. **Keep Plugins Self-Contained**
   - Minimize dependencies on other plugins
   - Use `lib/k8s/` for Kubernetes operations
   - Use `lib/` utilities for common functions

3. **Document Your Plugin**
   - Add a comprehensive `README.md`
   - Document all API endpoints
   - Include configuration options

4. **Handle Errors Gracefully**
   - Log errors with `logger.error()`
   - Return appropriate HTTP status codes
   - Show user-friendly error messages

5. **Use Client-Side Data Loading**
   - Render minimal template structure
   - Load data via JavaScript API calls
   - Improves perceived performance

## Plugin Lifecycle

1. **Discovery**: KubeDash scans `plugins/` directory at startup
2. **Registration**: Enabled plugins have blueprints registered
3. **Initialization**: Plugin models are imported (if present)
4. **Runtime**: Plugin handles requests independently

## Debugging

Enable debug logging for plugins:

```ini
[logging]
level = DEBUG
```

Check logs for plugin initialization:

```
Initialize Plugin APIs Dynamically
#######################################
Plugin APIs:
  Plugin API my_plugin Registered
#######################################
```

## Examples

See existing plugins for reference:
- `helm/` - Simple plugin with basic functionality
- `flux/` - Complex plugin with WebSocket support
- `mcp_integration/` - Plugin with AI/ML integration
- `iframe_proxy/` - Minimal proxy plugin

## Support

For questions or issues, refer to:
- Main documentation: `docs/`
- Source code: `src/kubedash/`
- Issues: GitHub Issues
