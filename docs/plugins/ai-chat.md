# AI Chat Plugin for KubeDash

An AI-powered chat interface for KubeDash that allows users to query and manage Kubernetes clusters using natural language. Cluster operations use **lib/k8s** (same stack and auth as the rest of the dashboard); no external MCP server is required.

## Features

- **Natural language commands**: List pods, describe resources, get logs, list deployments/services/configmaps/secrets, helm list, and more
- **Session-based access**: Uses the same KubeDash auth (Admin → kubeconfig; SSO User → access token) so RBAC matches the logged-in user
- **Multiple LLM providers**: Optional support for OpenAI, Ollama, Gemini, and Azure OpenAI
- **Air-gapped mode**: Works without an LLM using a pattern-based minimal provider (no external API calls)
- **Helm support**: List Helm releases
- **Conversation history**: Conversations and messages stored per user in the KubeDash database
- **Read-only mode**: Optional restriction to block create/delete operations
- **OpenTelemetry tracing**: Integrated with KubeDash monitoring

## Quick Start

### 1. Enable the Plugin

Add to your `kubedash.ini`:

```ini
[plugin_settings]
ai_chat = true
```

### 2. Configure AI Chat

For **air-gapped mode** (pattern-based commands only, no LLM), no further config is needed. Omit or leave empty `llm_base_url`.

For **LLM mode**, add an LLM provider under `[ai_chat]`:

```ini
[ai_chat]
read_only = false

# Optional LLM (omit for air-gapped)
llm_provider = ollama
llm_base_url = http://ollama:11434/v1
llm_model = llama3.1:8b
# llm_api_key =
llm_timeout = 60
llm_max_tokens = 2000
```

### 3. Run Database Migration

```bash
cd src/kubedash
flask db upgrade
```

### 4. Access the Chat

Open KubeDash and go to **Plugins → AI Chat**, or: `http://localhost:8000/plugins/ai-chat`

## Usage Examples

### Basic Queries

```
# List resources
list namespaces
list pods in default
list deployments in kube-system
list services in default
list configmaps in kube-system
list secrets
list daemonsets
list statefulsets

# Get details (pod and deployment supported)
describe pod nginx-12345 in default
describe deployment my-app in default

# View logs
show logs for pod nginx-12345
get logs for pod my-pod in default

# Helm
helm list
list releases in production
```

### Create/Delete (minimal provider path only)

When the **minimal provider** handles the message (air-gapped mode or LLM fallback), these are supported:

```
create namespace my-namespace
delete pod broken-pod in default
delete deployment old-app in default
```

When an LLM is configured, free-form text like "delete pod x" is sent to the LLM and is **not** executed as a K8s operation.

## Architecture

```
User → Chat UI → Chat API → Intent parser (list/describe/logs/helm/greeting/help)
                           ↓
                    run_k8s_intent_sync → minimal_provider + k8s_adapter → lib/k8s
                           ↓
                    Optional LLM (or minimal provider fallback)
```

- **lib/k8s**: Same Kubernetes client and credentials as the rest of KubeDash (Admin: kubeconfig; User: SSO token).
- **k8s_adapter**: Thin adapter over lib/k8s used by the minimal provider.
- **Write intents** (create/delete) are executed only when the minimal provider handles the message (air-gapped or fallback).

## Configuration Options

| Setting | Description | Default | Required |
|---------|-------------|---------|----------|
| `read_only` | If true, block create/delete intents | false | No |
| `llm_provider` | openai, ollama, gemini, azure | openai | No* |
| `llm_base_url` | LLM API base URL (e.g. Ollama `http://host:11434/v1`) | - | No* |
| `llm_model` | Model name | - | No |
| `llm_api_key` | API key (where needed) | - | No |
| `llm_timeout` | Request timeout (seconds) | 30 | No |
| `llm_max_tokens` | Max response tokens | 1000 | No |

\* Required only when using an LLM. If `llm_base_url` is empty, air-gapped mode (minimal provider only) is used.

## Air-Gapped Mode

When no LLM is configured (`llm_base_url` empty or omitted):

- Pattern-based intent detection
- No external LLM API calls
- All cluster operations via **lib/k8s** (same as dashboard)
- Supports list/describe/logs, helm list, create namespace, delete pod/deployment, greeting, help

A yellow **Air-Gapped Mode** badge is shown in the UI.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/plugins/ai-chat/chat/message` | POST | Send message; returns assistant reply |
| `/api/v1/plugins/ai-chat/chat/conversations` | GET | List current user's conversations |
| `/api/v1/plugins/ai-chat/chat/conversations/<id>` | GET | Get conversation and messages |
| `/api/v1/plugins/ai-chat/chat/conversations/<id>` | DELETE | Delete conversation (200 + `{ "status": "deleted" }`) |
| `/api/v1/plugins/ai-chat/provider/info` | GET | Provider info (air_gapped, model, base_url) |
| `/api/v1/plugins/ai-chat/provider/health` | GET | Provider health |

## Troubleshooting

### Permission denied / 403

- AI Chat uses the same session token and role as the rest of KubeDash. Check the user's RBAC and namespace permissions.

### LLM timeout or 404

- Verify `llm_base_url` (e.g. Ollama: `http://host:11434/v1`). Increase `llm_timeout` if needed.
- For Ollama, ensure the model is pulled: `ollama pull llama3.1:8b`

### "I didn't understand"

- Use supported phrasings (e.g. "list pods in &lt;namespace&gt;", "describe pod &lt;name&gt; in &lt;namespace&gt;") or configure an LLM for free-form questions.

## Development

### Project Structure

```
plugins/ai_chat/
├── __init__.py           # Blueprint, initialize_llm_provider
├── api.py                # Chat API: message, conversations, provider info/health
├── intent_parser.py      # Pattern-based intent detection (parse_intent)
├── k8s_adapter.py        # Adapter over lib/k8s (session creds, list_*, describe_*, get_pod_logs, etc.)
├── helm_operations.py     # Helm CLI (list_releases, …)
├── minimal_provider.py   # Air-gapped chatbot, format + dispatch to k8s_adapter
├── llm_provider.py       # LLM implementations (OpenAI, Ollama, Gemini, Azure)
├── provider_registry.py  # Provider selection, fallback to minimal
├── model.py              # DB models (McpConversation, McpMessage; tables: ai_chat_conversations, ai_chat_messages)
├── diagnostics.py        # Stub (K8sGPT diagnostics not configured)
└── templates/
    └── ai-chat.html.j2   # Chat UI
```

### Testing

```bash
cd src/kubedash

# Test minimal provider
poetry run python -c "
from plugins.ai_chat.minimal_provider import MinimalChatbotProvider
import asyncio
provider = MinimalChatbotProvider()
messages = [{'role': 'user', 'content': 'list pods in default'}]
response = asyncio.run(provider.chat(messages))
print(response.content)
"

# Test intent parser
poetry run python -c "
from plugins.ai_chat.intent_parser import parse_intent
for msg in ['list pods in default', 'describe pod x in kube-system', 'hello']:
    intent = parse_intent(msg)
    print(f'{msg!r} -> {intent}')
"
```

## Security Considerations

- **Read-only mode**: Enable for untrusted users to block create/delete.
- **Namespace access**: Respects KubeDash RBAC (same session and token as dashboard).
- **API keys**: Store securely (e.g. environment variables); do not commit to version control.
- **Audit**: All operations use lib/k8s with the same audit trail as the rest of KubeDash.
- **OpenTelemetry**: Full tracing integration.

## Standards Compliance

The AI Chat plugin follows KubeDash plugin development standards:

- Uses standard logger (`lib.helper_functions.get_logger()`)
- OpenTelemetry tracing (`lib.opentelemetry.get_tracer()`)
- Authentication (`flask_login.login_required`)
- User token for K8s API (`lib.sso.get_user_token()`)
- Error handling (`lib.helper_functions.ErrorHandler()`)
- Database (`lib.components.db`)
- CSRF exemption on API blueprint (`lib.components.csrf.exempt()`)

See [AI Chat PRD](../prd/ai-chat.md) for full architecture and implementation details.

## License

Apache 2.0
