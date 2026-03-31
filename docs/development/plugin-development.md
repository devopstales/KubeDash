# KubeDash Plugin Development Guide

This guide explains how to develop plugins for KubeDash. It covers plugin structure, standard components, and best practices.

## Overview

KubeDash plugins extend the functionality of the dashboard by adding new features, integrations, and visualizations. Each plugin is a self-contained module that follows a standard structure.

## ⚠️ Important: Standard Components Required

**All plugins MUST use the standard KubeDash components** for logging, tracing, caching, database access, and authentication.

**Failure to use standard components will result in inconsistent behavior and will not be accepted for merge.**

The following components are **required** for all plugins:

| Component | Module | Required | Purpose |
|-----------|--------|----------|---------|
| Logger | `lib.helper_functions.get_logger()` | ✅ Yes | Centralized logging |
| Audit Log | | Not Implemente | Centralized audit logging |
| OpenTelemetry | `lib.opentelemetry.get_tracer()` | ✅ Yes | Distributed tracing |
| Authentication | `flask_login.login_required` | ✅ Yes | Route protection |
| User Token | `lib.sso.get_user_token()` | ✅ Yes | K8s API authorization |
| K8s Client | `lib.k8s.*` | ✅ Yes | Kubernetes API wrappers |
| Error Handler | `lib.helper_functions.ErrorHandler()` | ✅ Yes | Error handling |
| Session | `flask.session` | ✅ Yes | User session management |
| Cache | `lib.components.cache` | ⚠️ Recommended | Redis caching |
| Database | `lib.components.db` | ⚠️ Optional | Data persistence |
| CSRF | `lib.components.csrf` | ⚠️ Optional | Form protection |

Detailed documentation for each component is provided in the [Standard Components](#standard-components) section below.

---

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

---

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

---

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

---

## Enabling Plugins

Plugins are enabled in `kubedash.ini`:

```ini
[plugin_settings]
my_plugin = true
```

---

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

---

## Database Models

For plugins that need database storage:

```python
# plugins/my_plugin/model.py
from lib.components import db
from datetime import datetime

class MyPluginModel(db.Model):
    __tablename__ = 'my_plugin_data'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    data = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<MyPluginModel {self.name}>'

    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'data': self.data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
```

### Database Migrations

For plugins with models, add migrations:

```python
# migrations/versions/xxxx_my_plugin_tables.py
"""add my_plugin_data table

Revision ID: xxxx
Revises: yyyy
Create Date: 2026-03-05

Related Issue: My plugin feature
"""

def upgrade():
    op.create_table('my_plugin_data',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('data', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade():
    op.drop_table('my_plugin_data')
```

---

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

---

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

Usage in `kubedash.ini`:

```ini
[plugin_settings]
my_plugin = true

[my_plugin]
api_endpoint = https://api.example.com
timeout = 30
max_items = 100
```

---

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

---

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

---

## Plugin Lifecycle

1. **Discovery**: KubeDash scans `plugins/` directory at startup
2. **Registration**: Enabled plugins have blueprints registered
3. **Initialization**: Plugin models are imported (if present)
4. **Runtime**: Plugin handles requests independently

---

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

---

## Examples

See existing plugins for reference:
- `helm/` - Simple plugin with basic functionality
- `flux/` - Complex plugin with WebSocket support
- `mcp_integration/` - Plugin with AI/ML integration
- `iframe_proxy/` - Minimal proxy plugin
- `trivy_operator/` - Security scanning plugin
- `gateway_api/` - Gateway API management

---

# Standard Components

This section provides detailed documentation for each standard component that must be used in plugins.

## 1. Logger

**Module:** `lib.helper_functions.get_logger()`

**Purpose:** Centralized logging with color-coded output and OpenTelemetry integration.

### Usage

```python
from lib.helper_functions import get_logger

logger = get_logger()

@my_plugin_bp.route('/my-view')
@login_required
def my_view():
    logger.info("Plugin view accessed")
    logger.debug("Debug information")
    logger.warning("Warning message")
    logger.error("Error occurred")

    try:
        # Some operation
        pass
    except Exception as e:
        logger.error(f"Operation failed: {e}", exc_info=True)
```

### Log Levels

- `logger.debug()` - Detailed debugging information
- `logger.info()` - General operational messages
- `logger.warning()` - Warning messages (non-critical issues)
- `logger.error()` - Error messages (something went wrong)
- `logger.critical()` - Critical errors (application may be unstable)

### Best Practices

1. **Always use `get_logger()`** - Don't create loggers manually
2. **Include context** - Add relevant information to log messages
3. **Use `exc_info=True`** for exceptions to include stack traces
4. **Avoid logging sensitive data** - Don't log passwords, tokens, etc.

---

## 2. OpenTelemetry Tracing

**Module:** `lib.opentelemetry.get_tracer()`

**Purpose:** Distributed tracing for observability and performance monitoring.

### Usage

```python
from lib.opentelemetry import get_tracer
from opentelemetry import trace

tracer = get_tracer()

@my_plugin_bp.route('/my-operation')
@login_required
def my_operation():
    # Method 1: Decorator (recommended for route handlers)
    @tracer.start_as_current_span("my_plugin.operation")
    def do_something():
        # Your code here
        pass

    # Method 2: Context manager (for specific operations)
    with tracer.start_as_current_span("my_plugin.custom_operation") as span:
        span.set_attribute("custom.attribute", "value")
        span.set_attribute("user.id", session.get('user_id'))

        # Your code here
        result = do_something()

        span.set_attribute("operation.result", "success")
        return result
```

### Span Attributes

Common attributes to set:

```python
with tracer.start_as_current_span("my_plugin.operation") as span:
    # Business context
    span.set_attribute("user.id", session.get('user_id'))
    span.set_attribute("namespace", namespace)
    span.set_attribute("resource.name", resource_name)

    # Operation details
    span.set_attribute("operation.type", "create")
    span.set_attribute("operation.status", "success")

    # Performance metrics
    span.set_attribute("items.processed", count)
    span.set_attribute("processing.time.ms", duration_ms)
```

### Best Practices

1. **Always get tracer with `get_tracer()`** - Don't create tracers manually
2. **Use descriptive span names** - Format: `plugin_name.operation_name`
3. **Set relevant attributes** - Add context for debugging
4. **Wrap async operations** - Trace background tasks
5. **Don't trace sensitive data** - Avoid PII in attributes

---

## 3. Cache

**Module:** `lib.components.cache`

**Purpose:** Redis-based caching for improved performance.

### Usage

```python
from lib.components import cache, short_cache_time, long_cache_time

# Short cache (60 seconds) - for frequently changing data
@cache.memoize(timeout=short_cache_time)
def get_frequently_changing_data(namespace):
    # Expensive operation
    return data

# Long cache (900 seconds) - for static data
@cache.memoize(timeout=long_cache_time)
def get_static_data(name):
    # Expensive operation
    return data

# Manual cache control
@my_plugin_bp.route('/refresh-data')
@login_required
def refresh_data():
    # Delete specific cache entry
    cache.delete('my_plugin:data:namespace:default')

    # Delete all cache entries matching pattern
    cache.delete_many(*cache.get_keys('my_plugin:*'))

    return jsonify({"status": "cache cleared"})
```

### Cache Timeouts

- `short_cache_time` = 60 seconds (for dynamic data)
- `long_cache_time` = 900 seconds (for static data)
- Custom timeout: `@cache.memoize(timeout=300)` (5 minutes)

### Best Practices

1. **Use decorators for simple caching** - `@cache.memoize()`
2. **Choose appropriate timeout** - Balance freshness vs performance
3. **Invalidate cache on updates** - Delete cache when data changes
4. **Use descriptive cache keys** - Format: `plugin_name:type:context`
5. **Handle cache failures gracefully** - Cache is optional, don't break if unavailable

---

## 4. Database

**Module:** `lib.components.db`

**Purpose:** SQLAlchemy ORM for data persistence.

### Usage

```python
from lib.components import db
from datetime import datetime

class MyPluginModel(db.Model):
    """Example plugin database model."""

    __tablename__ = 'my_plugin_data'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<MyPluginModel {self.name}>'

    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

# Usage in routes
@my_plugin_bp.route('/items')
@login_required
def list_items():
    items = MyPluginModel.query.all()
    return jsonify([item.to_dict() for item in items])

@my_plugin_bp.route('/items', methods=['POST'])
@csrf.exempt  # If needed for API endpoints
@login_required
def create_item():
    data = request.json

    item = MyPluginModel(
        name=data['name'],
        description=data.get('description')
    )

    db.session.add(item)
    db.session.commit()

    logger.info(f"Created item: {item.name}")
    return jsonify(item.to_dict()), 201
```

### Best Practices

1. **Use descriptive table names** - Format: `plugin_name_table_name`
2. **Add timestamps** - `created_at`, `updated_at` for audit trails
3. **Implement `to_dict()`** - For easy JSON serialization
4. **Use migrations** - Never modify schema without migration
5. **Handle transactions** - Use `db.session.commit()` appropriately
6. **Add indexes** - For frequently queried columns

---

## 5. CSRF Protection

**Module:** `lib.components.csrf`

**Purpose:** Cross-Site Request Forgery protection for forms.

### Usage

```python
from lib.components import csrf
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

# For forms (CSRF enabled by default)
class MyPluginForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

@my_plugin_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = MyPluginForm()
    if form.validate_on_submit():
        # Process form
        pass
    return render_template('create.html.j2', form=form)

# For API endpoints (exempt from CSRF)
@my_plugin_bp.route('/api/data', methods=['POST'])
@csrf.exempt  # Exempt API endpoints
@login_required
def api_data():
    data = request.json
    return jsonify(data)
```

### When to Exempt CSRF

- ✅ REST API endpoints (use authentication instead)
- ✅ Webhook receivers (use signature verification)
- ✅ WebSocket endpoints (use connection authentication)
- ❌ HTML form submissions (keep CSRF protection)

### Best Practices

1. **Keep CSRF enabled for forms** - Protect against CSRF attacks
2. **Exempt only API endpoints** - Use authentication/authorization
3. **Validate webhook signatures** - Don't just exempt, verify source
4. **Document exemptions** - Explain why CSRF is disabled

---

## 6. Session Management

**Module:** `flask.session`

**Purpose:** User session storage for stateful interactions.

### Usage

```python
from flask import session

@my_plugin_bp.route('/select-namespace', methods=['POST'])
@login_required
def select_namespace():
    # Store user preference
    session['ns_select'] = request.form.get('namespace')
    session['my_plugin.active_tab'] = request.form.get('tab')

    return redirect(url_for('.my_view'))

@my_plugin_bp.route('/my-view')
@login_required
def my_view():
    # Retrieve user preferences
    namespace = session.get('ns_select', 'default')
    active_tab = session.get('my_plugin.active_tab', 'overview')

    return render_template('view.html.j2',
                         namespace=namespace,
                         active_tab=active_tab)
```

### Session Best Practices

1. **Use descriptive keys** - Format: `plugin_name.key_name`
2. **Provide defaults** - `session.get('key', 'default')`
3. **Don't store sensitive data** - No passwords, tokens in session
4. **Clean up old sessions** - Remove unused session data
5. **Respect session lifetime** - Don't rely on permanent storage

---

## 7. Authentication & Authorization

**Module:** `flask_login.login_required`, `lib.sso.get_user_token()`

**Purpose:** User authentication and Kubernetes API authorization.

### Usage

```python
from flask_login import login_required
from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespaceListGet

@my_plugin_bp.route('/my-view')
@login_required  # Require authentication
def my_view():
    # Get user token for K8s API calls
    user_token = get_user_token(session)
    user_role = session['user_role']

    # Use token for K8s operations
    namespaces, error = k8sNamespaceListGet(user_role, user_token)

    return render_template('view.html.j2', namespaces=namespaces)
```

### Authorization Patterns

```python
from lib.k8s.security import k8sCanAccessNamespace

@my_plugin_bp.route('/namespace/<namespace>/data')
@login_required
def namespace_data(namespace):
    user_token = get_user_token(session)
    user_role = session['user_role']

    # Check if user can access namespace
    if not k8sCanAccessNamespace(user_role, user_token, namespace):
        flash('You do not have permission to access this namespace', 'danger')
        return redirect(url_for('.my_view'))

    # Proceed with operation
    data = get_namespace_data(namespace, user_role, user_token)
    return jsonify(data)
```

### Best Practices

1. **Always use `@login_required`** - Protect all routes
2. **Get user token for K8s calls** - Never use service account for user operations
3. **Check namespace permissions** - Verify user can access resources
4. **Handle authorization failures** - Show user-friendly error messages
5. **Log authorization failures** - For security auditing

---

## 8. Kubernetes Client

**Module:** `lib.k8s.*`

**Purpose:** Kubernetes API access with proper error handling and caching.

### Available Modules

```python
# Kubernetes API wrappers
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.workload import k8sPodListGet, k8sDeploymentListGet
from lib.k8s.network import k8sServiceListGet, k8sIngressListGet
from lib.k8s.storage import k8sPVCListGet, k8sPVListGet
from lib.k8s.security import k8sSecretListGet, k8sRoleListGet
from lib.k8s.metrics import k8sPodMetricsGet
from lib.k8s.node import k8sNodeListGet
from lib.k8s.crds import k8sCRDListGet
from lib.k8s.certificate import k8sCertificateListGet
```

### Usage

```python
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.workload import k8sPodListGet
from lib.sso import get_user_token
from lib.helper_functions import get_logger

logger = get_logger()

@my_plugin_bp.route('/pods')
@login_required
def list_pods():
    user_token = get_user_token(session)
    user_role = session['user_role']
    namespace = session.get('ns_select', 'default')

    # Get pods from K8s API
    pods, error = k8sPodListGet(user_role, user_token, namespace)

    if error:
        logger.error(f"Failed to get pods: {error}")
        flash('Failed to load pods', 'danger')
        return redirect(url_for('.my_view'))

    return jsonify(pods)
```

### Best Practices

1. **Use `lib/k8s/` wrappers** - Don't use kubernetes client directly
2. **Always pass user credentials** - `user_role` and `user_token`
3. **Handle errors gracefully** - Check for `error` return value
4. **Log K8s API failures** - For debugging and monitoring
5. **Respect caching** - K8s wrappers include caching

---

## 9. Error Handling

**Module:** `lib.helper_functions.ErrorHandler`

**Purpose:** Centralized error handling with logging and user feedback.

### Usage

```python
from lib.helper_functions import ErrorHandler, get_logger

logger = get_logger()

@my_plugin_bp.route('/operation')
@login_required
def operation():
    try:
        result = do_something()
        return jsonify(result)
    except Exception as e:
        # Log error with context
        logger.error(f"Operation failed: {e}", exc_info=True)

        # Use ErrorHandler for K8s API errors
        ErrorHandler(logger, e, "my_plugin operation")

        # Return user-friendly error
        return jsonify({
            'error': 'Operation failed',
            'message': str(e)
        }), 500
```

### Best Practices

1. **Catch specific exceptions** - Don't catch all exceptions blindly
2. **Log with context** - Include operation name and parameters
3. **Use ErrorHandler for K8s** - Provides consistent K8s error handling
4. **Return user-friendly messages** - Don't expose internal errors
5. **Include stack traces in logs** - Use `exc_info=True`

---

## 10. Configuration

**Module:** `app.config['kubedash.ini']`

**Purpose:** Plugin-specific configuration from `kubedash.ini`.

### Usage

```python
# In kubedash.ini
[plugin_settings]
my_plugin = true

[my_plugin]
api_endpoint = https://api.example.com
timeout = 30
max_items = 100

# In plugin code
@my_plugin_bp.route('/init')
@login_required
def init():
    # Get plugin configuration
    ini = current_app.config['kubedash.ini']

    enabled = ini.getboolean('plugin_settings', 'my_plugin', fallback=False)
    api_endpoint = ini.get('my_plugin', 'api_endpoint', fallback='https://api.example.com')
    timeout = ini.getint('my_plugin', 'timeout', fallback=30)
    max_items = ini.getint('my_plugin', 'max_items', fallback=100)

    logger.info(f"Plugin initialized: endpoint={api_endpoint}, timeout={timeout}")

    return jsonify({"status": "initialized"})
```

### Best Practices

1. **Use descriptive section names** - `[plugin_name]`
2. **Provide fallback values** - Handle missing configuration
3. **Validate configuration** - Check values at startup
4. **Log configuration** - For debugging (not secrets!)
5. **Don't store secrets in config** - Use environment variables

---

## Complete Plugin Example

```python
#!/usr/bin/env python3
"""
My Plugin for KubeDash

This plugin demonstrates all standard components.
"""

from flask import Blueprint, render_template, request, session, jsonify
from flask_login import login_required

from lib.helper_functions import get_logger, ErrorHandler
from lib.opentelemetry import get_tracer
from lib.components import cache, short_cache_time, db, csrf
from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespaceListGet

from .models import MyPluginModel

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
tracer = get_tracer()

##############################################################
## Routes
##############################################################

@my_plugin_bp.route('/my-plugin')
@login_required
@cache.memoize(timeout=short_cache_time)
def my_plugin_view():
    """
    Main plugin view with caching and tracing.
    """
    with tracer.start_as_current_span("my_plugin.view") as span:
        user_token = get_user_token(session)
        user_role = session['user_role']
        namespace = session.get('ns_select', 'default')

        span.set_attribute("user.role", user_role)
        span.set_attribute("namespace", namespace)

        # Get namespaces for dropdown
        namespaces, error = k8sNamespaceListGet(user_role, user_token)
        if error:
            logger.error(f"Failed to get namespaces: {error}")
            namespaces = []

        # Get plugin data from database
        items = MyPluginModel.query.filter_by(namespace=namespace).all()

        logger.info(f"Plugin view accessed: {len(items)} items")

        return render_template('my_plugin/view.html.j2',
                             namespaces=namespaces,
                             items=items)

@my_plugin_bp.route('/my-plugin/api/data', methods=['POST'])
@csrf.exempt  # API endpoint
@login_required
def api_data():
    """
    API endpoint for data operations.
    """
    with tracer.start_as_current_span("my_plugin.api.data") as span:
        try:
            data = request.json
            user_token = get_user_token(session)

            span.set_attribute("operation.type", "create")
            span.set_attribute("data.size", len(str(data)))

            # Process data
            result = process_data(data, user_token)

            span.set_attribute("operation.status", "success")
            logger.info(f"Data processed successfully")

            return jsonify(result)

        except Exception as e:
            logger.error(f"Data processing failed: {e}", exc_info=True)
            ErrorHandler(logger, e, "my_plugin data processing")

            span.set_attribute("operation.status", "error")
            return jsonify({
                'error': 'Processing failed',
                'message': str(e)
            }), 500

##############################################################
## Helper Functions
##############################################################

@cache.memoize(timeout=long_cache_time)
def process_data(data, user_token):
    """
    Process data with caching.
    """
    # Expensive operation
    result = do_expensive_operation(data, user_token)
    return result
```

---

## Checklist for Plugin Developers

Before submitting your plugin, ensure you've used all required components:

- [ ] **Logger** - Using `get_logger()` for all logging
- [ ] **OpenTelemetry** - Using `get_tracer()` for tracing
- [ ] **Authentication** - All routes protected with `@login_required`
- [ ] **User Token** - Using `get_user_token()` for K8s calls
- [ ] **Error Handling** - Using `ErrorHandler()` for K8s errors
- [ ] **Caching** - Using `@cache.memoize()` where appropriate
- [ ] **CSRF** - Forms protected, APIs exempted
- [ ] **Database** - Using migrations for schema changes
- [ ] **Configuration** - Reading from `kubedash.ini`
- [ ] **Documentation** - README.md with usage instructions

---

## Support

For questions about standard components:
- Review existing plugins: `plugins/helm/`, `plugins/flux/`, `plugins/trivy_operator/`
- Check source code: `lib/helper_functions.py`, `lib/opentelemetry.py`, `lib/components.py`
- Read documentation: `docs/development/`
