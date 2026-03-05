# Plugin reference (structure & config)

This page is the **technical reference** for all KubeDash plugins: structure, configuration, and API endpoints. For **user-facing guides** (how to use a feature), see the **Integrations** section in the nav; the table below links to those guides where available.

## Available Plugins

| Plugin | Reference (structure/config) | User guide (Integrations) |
|--------|------------------------------|---------------------------|
| Application Catalog | [application_catalog.md](application_catalog.md) | [Application Catalog](../integrations/application-catalog.md) |
| Cert Manager | [cert_manager.md](cert_manager.md) | [Cert Manager](../integrations/cert-manager.md) |
| External LoadBalancer | [external_loadbalancer.md](external_loadbalancer.md) | [External LoadBalancer](../integrations/external-load-balancer.md) |
| FluxCD | [flux.md](flux.md) | — |
| Gateway API | [gateway_api.md](gateway_api.md) | — |
| Helm | [helm.md](helm.md) | [Helm Chart](../integrations/helm.md) |
| iframe Proxy | [iframe_proxy.md](iframe_proxy.md) | (used by Application Catalog) |
| MCP Integration | [mcp_integration.md](mcp_integration.md) | (same doc linked from Integrations) |
| Registry | [registry.md](registry.md) | [Docker Registry](../integrations/docker-registry.md) |
| Trivy Operator | [trivy_operator.md](trivy_operator.md) | [Trivy Operator](../integrations/trivy-operator.md) |

## Plugin Structure

```
plugins/<name>/
├── __init__.py            # Blueprint registration & main routes
├── config.py              # Plugin-specific configuration (optional)
├── api.py                 # REST API endpoints (optional)
├── services/              # Business logic layer (optional)
├── models.py              # Database models (optional)
├── templates/             # UI templates (optional)
├── static/                # Plugin-specific assets (optional)
└── README.md              # Link to docs/plugins/<name>.md
```

## Enabling Plugins

Plugins are enabled in `kubedash.ini`:

```ini
[plugin_settings]
plugin_name = true
```

## Development

See [Plugin Development Guide](../development/plugin-development.md) for detailed development guidelines.

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```
