# MCP Integration Plugin for KubeDash

Provides an in-app AI chatbot backed by MCP (Model Context Protocol) servers for natural-language cluster queries and actions.

## Features

- AI-powered chatbot for Kubernetes cluster queries
- MCP server integration for context-aware responses
- Cluster resource discovery and mapping
- Natural language to Kubernetes operations

## Structure

```
mcp_integration/
├── __init__.py          # Blueprint registration & resource discovery
├── api.py               # REST API endpoints for chat
├── mcp_client.py        # MCP client implementation
├── mcp_session.py       # MCP session management
├── mcp_tools.py         # MCP tool definitions
├── k8s_operations.py    # Kubernetes operations via MCP
├── helm_operations.py   # Helm operations via MCP
├── models.py            # Database models
├── resource_yaml.py     # Resource YAML handling
└── README.md            # This file
```

## Configuration

Enable in `kubedash.ini`:

```ini
[plugin_settings]
mcp_integration = true
```

## API Endpoints

- `GET /plugins/mcp-chat` - MCP Chat main page

## Development

Run tests with:

```bash
cd src/kubedash
poetry run pytest tests/ -v
```

## References

- See `docs/prd/mcp-integration.md` for requirements
- MCP Server documentation: https://modelcontextprotocol.io/
