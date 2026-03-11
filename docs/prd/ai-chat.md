# AI Chat Plugin – Product Requirements Document

**Version:** 2.0  
**Date:** March 2026  
**Status:** Implemented (lib/k8s–based; no MCP)

---

## 1. Overview

### 1.1 Purpose

The AI Chat plugin adds an in-app chat interface to KubeDash so users can:

- Run Kubernetes operations via natural-language commands (list pods, describe pod, get logs, list deployments, etc.)
- Optionally use an LLM (OpenAI, Ollama, Gemini, Azure) for general questions when configured
- Work in air-gapped mode with a pattern-based “minimal” provider when no LLM is configured

Cluster operations use the **same KubeDash stack** as the rest of the dashboard: **lib/k8s** with session-based auth (Admin → kubeconfig; SSO User → access token).

### 1.2 Goals

- **No external MCP server** – Kubernetes operations go through **lib/k8s** (k8s_adapter).
- **Session-based access** – Use `user_role` and `get_user_token(session)` so RBAC matches the logged-in user (Admin vs User/SSO).
- **Intent-first** – Recognized commands (e.g. “list pods in kube-system”) are executed directly; unrecognized messages can be sent to an optional LLM.
- **Conversation history** – Conversations and messages stored in the KubeDash database per user.

---

## 2. Architecture

### 2.1 High-Level

```
┌─────────────────────────────────────────────────────────────────┐
│                        KubeDash Application                     │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌─────────────────┐    │
│  │   Chat UI    │◄──►│   Chat API   │◄──►│  LLM Provider   │    │
│  │  (Frontend)  │    │   (Flask)    │    │  (optional)     │    │
│  └──────────────┘    └──────┬───────┘    └─────────────────┘    │
│                             │                                   │
│                             ▼                                   │
│                    ┌─────────────────┐                          │
│                    │  Intent Parser  │                          │
│                    │  (pattern-based)│                          │
│                    └────────┬────────┘                          │
│                             │                                   │
│              ┌──────────────┴──────────────┐                    │
│              ▼                              ▼                   │
│     ┌─────────────────┐            ┌─────────────────┐          │
│     │ Minimal Provider│            │  k8s_adapter    │          │
│     │ (format/route)  │            │  (lib/k8s)      │          │
│     └────────┬────────┘            └────────┬────────┘          │
│              │                              │                   │
└──────────────┼──────────────────────────────┼───────────────────┘
               │                              │
               ▼                              ▼
     ┌─────────────────────────────────────────────┐
     │           lib/k8s (KubeDash)                │
     │  k8sClientConfigGet(user_role, user_token)  │
     └─────────────────────┬───────────────────────┘
                           │
                           ▼
     ┌─────────────────────────────────────────────┐
     │           Kubernetes API Server             │
     └─────────────────────────────────────────────┘
```

### 2.2 Data Flow

1. **User sends message** → Chat UI → `POST /api/v1/plugins/ai-chat/chat/message`.
2. **Chat API** first tries **intent_parser** (`parse_intent`). If a known intent is detected:
   - **Read-only K8s intents** (list namespaces/pods/deployments/…, describe pod, get logs, helm list, diagnose_*): run via **run_k8s_intent_sync** → minimal provider `_execute_intent` + **k8s_adapter** → **lib/k8s** (with session `user_role` and `user_token`).
   - **Greeting/help**: minimal provider returns static text.
3. **Write intents** (create namespace, delete pod, delete deployment) are **not** in intent_parser. They are executed only when the **minimal provider** handles the message: in **air-gapped mode** (no LLM), or when the LLM path is not used (e.g. fallback). When an LLM is configured, free-form text like “delete pod x” is sent to the LLM as text and is **not** executed as a K8s operation.
4. If no intent is detected: optional **LLM** is called; on failure or if not configured, **minimal provider** fallback message is returned (and minimal provider may then detect create/delete from its own patterns).
5. **Response** and **messages** are stored in the DB and returned to the client.

### 2.3 Authentication (Same as Dashboard)

- **Admin:** `user_role == "Admin"` → **lib.k8s.server.k8sClientConfigGet** uses kubeconfig / incluster config (no token).
- **User (SSO):** `user_role == "User"` → token from **lib.sso.get_user_token(session)** (OAuth access token) is passed to **k8sClientConfigGet** for Bearer auth to the Kubernetes API.

All k8s operations in AI Chat use this same pattern so RBAC and audit match the rest of KubeDash.

---

## 3. Configuration

### 3.1 Plugin Enable

```ini
[plugin_settings]
ai_chat = true
```

### 3.2 AI Chat Section

```ini
[ai_chat]
# Kubernetes operations use lib/k8s (same cluster as KubeDash). No MCP server.

# Read-only mode: only list/describe/logs; no create/delete
read_only = false

# ----- Optional LLM (omit for air-gapped / minimal-only) -----
llm_provider = ollama
llm_base_url = http://ollama:11434/v1
llm_model = llama3.1:8b
llm_api_key =
llm_timeout = 60
llm_max_tokens = 2000
```

| Setting          | Description                                           | Default | Required |
|------------------|-------------------------------------------------------|---------|----------|
| `read_only`      | If true, block create/delete intents                  | false   | No       |
| `llm_provider`   | openai, ollama, gemini, azure                         | openai  | No*      |
| `llm_base_url`   | LLM API base URL (e.g. Ollama `http://host:11434/v1`) | -       | No*      |
| `llm_model`      | Model name                                            | -       | No       |
| `llm_api_key`    | API key (where needed)                                | -       | No       |
| `llm_timeout`    | Request timeout (seconds)                             | 30      | No       |
| `llm_max_tokens` | Max response tokens                                   | 1000    | No       |

\* Required only when using an LLM for non-intent messages. If `llm_base_url` is empty, air-gapped mode (minimal provider only) is used.

---

## 4. API Endpoints

All API routes are under the plugin API blueprint; full path prefix is `/api/v1/plugins/ai-chat`. The Chat UI page is served by the main plugin blueprint at `/plugins/ai-chat`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/plugins/ai-chat` | GET | Chat UI page (plugin blueprint) |
| `/api/v1/plugins/ai-chat/chat/message` | POST | Send message; returns assistant reply |
| `/api/v1/plugins/ai-chat/chat/conversations` | GET | List current user’s conversations |
| `/api/v1/plugins/ai-chat/chat/conversations/<id>` | GET | Get conversation and messages |
| `/api/v1/plugins/ai-chat/chat/conversations/<id>` | DELETE | Delete conversation (200 + `{ "status": "deleted" }`) |
| `/api/v1/plugins/ai-chat/provider/info` | GET | Provider info (air_gapped, model, base_url, etc.) |
| `/api/v1/plugins/ai-chat/provider/health` | GET | Provider health |

**POST /chat/message** body: `{ "content": "...", "conversation_id": "<optional>" }`.  
Response: `{ "conversation_id": "...", "message": { "role": "assistant", "content": "..." } }`.

---

## 5. Supported Commands (Intents)

Pattern-based intents are executed via **k8s_adapter** (lib/k8s) or **helm_operations**. Namespace defaults to `default` when not specified.

**Intent source:** List/describe/logs/helm/greeting/help are detected by **intent_parser** and executed in the sync path. Create/delete are detected only by the **minimal provider** (its own patterns) when it handles the message (air-gapped mode or LLM fallback).

| Intent | Example | Backend |
|--------|---------|---------|
| list namespaces | “list namespaces” | lib/k8s namespace |
| list pods | “list pods in kube-system” | lib/k8s workload |
| describe pod | “describe pod my-pod in default” | lib/k8s workload |
| get logs | “logs for pod my-pod in default” | lib/k8s (read_namespaced_pod_log) |
| list deployments / daemonsets / statefulsets / services / configmaps / secrets | “list deployments in kube-system” | lib/k8s (workload, network, storage, security) |
| describe deployment | “describe deployment my-dep in default” | lib/k8s (AppsV1Api); describe for other resource kinds not implemented |
| helm list | “helm list”, “list helm in kube-system” | helm_operations (subprocess) |
| create namespace | “create namespace my-ns” | lib/k8s namespace (minimal provider path only) |
| delete pod | “delete pod my-pod in default” | lib/k8s workload (minimal provider path only) |
| delete deployment | “delete deployment my-dep in default” | kubernetes client AppsV1Api (minimal provider path only) |

| greeting | “hi”, “hello” | minimal provider |
| help | “help”, “what can you do” | minimal provider |

Diagnose intents (e.g. “diagnose cluster”, “diagnose pod X”) are recognized by intent_parser; execution is handled by minimal_provider and returns a message that K8sGPT diagnostics are not configured.

---

## 6. Implementation Layout

### 6.1 Plugin Structure

```
src/kubedash/plugins/ai_chat/
├── __init__.py           # Blueprint, initialize_llm_provider
├── api.py                # Chat API: run_k8s_intent_sync, chat_message, conversations, provider info/health
├── intent_parser.py     # Intent parser only (parse_intent)
├── k8s_adapter.py       # Adapter over lib/k8s (session creds, list_*, describe_*, get_pod_logs, etc.)
├── helm_operations.py   # Helm CLI (list_releases, install, uninstall, …)
├── minimal_provider.py  # Format responses, dispatch to k8s_adapter / helm_operations
├── llm_provider.py      # LLM implementations (OpenAI, Ollama, Gemini, Azure)
├── provider_registry.py # Provider selection, fallback to minimal
├── model.py             # McpConversation, McpMessage (tables: ai_chat_conversations, ai_chat_messages)
├── diagnostics.py      # Stub (no MCP; “not configured” message)
└── templates/
    └── ai-chat.html.j2  # Chat UI
```

### 6.2 Key Flows

- **Intent execution:** `api.run_k8s_intent_sync` → `parse_intent` (intent_parser) → if intent, map list_* to resources_list and build `params` → minimal_provider.`_execute_intent` → **k8s_adapter** or helm_operations → formatted reply. Create/delete intents are not in intent_parser; they are executed only when the message is handled by minimal_provider.chat() (air-gapped or LLM fallback).
- **Credentials:** **k8s_adapter._session_creds()** → `(user_role, user_token)` from Flask session and **lib.sso.get_user_token(session)**; every lib/k8s call uses these.

### 6.3 Standards

- Logger: `lib.helper_functions.get_logger()`
- Tracing: `lib.opentelemetry.get_tracer()`
- Auth: `flask_login.login_required`
- DB: `lib.components.db`
- CSRF: `lib.components.csrf.exempt()` on API blueprint

---

## 7. Phases and Status

### Phase 1 – Foundation ✅

- Plugin structure, blueprint, config
- DB models (conversations, messages) and migrations
- Intent parser (pattern-based)
- k8s_adapter using lib/k8s with session auth
- Minimal provider (format + dispatch)
- Helm operations (subprocess)
- Chat API (message, conversations CRUD, provider info/health)
- Chat UI (single-page, no streaming)

### Phase 2 – LLM Integration ✅

- LLM provider abstraction and registry
- OpenAI-compatible, Ollama, Gemini, Azure providers
- Fallback to minimal provider on LLM failure or when unconfigured

### Phase 3 – Behavioural / Cleanup ✅

- MCP removed; all cluster operations via lib/k8s
- Session-based auth (Admin / User) aligned with dashboard
- Read-only mode for write intents
- List/describe (pod, deployment; list for configmaps/secrets/daemonsets/statefulsets/services) supported; k8s_adapter.resources_get implements describe for pod and deployment only

### Phase 4 – Future

- Optional: K8sGPT or other diagnostics (e.g. separate integration, no MCP)
- Stronger intent detection / NLP if desired
- Chat analytics / usage tracking
- Security review and production runbook

---

## 8. Appendix

### A. Configuration Reference

See [Configuration](#32-ai-chat-section) for `[ai_chat]` options. There is no `mcp_server_url`; cluster access is via lib/k8s only.

### B. API Quick Reference

- **POST /chat/message:** `{ "content": "list pods in default", "conversation_id": "123" }` → `{ "conversation_id": "123", "message": { "role": "assistant", "content": "..." } }`
- **GET /chat/conversations:** List of `{ id, title, created_at, updated_at, message_count }`
- **GET /chat/conversations/<id>:** `{ conversation, messages[] }`
- **DELETE /chat/conversations/<id>:** 200 with `{ "status": "deleted" }` or error

### C. Troubleshooting

- **Permission denied / 403:** Check user’s RBAC; AI Chat uses the same session token/role as the rest of KubeDash.
- **LLM 404 / timeout:** Verify `llm_base_url` (e.g. Ollama `http://host:11434`); provider appends `/v1/chat/completions`. Increase `llm_timeout` if needed.
- **“I didn’t understand”:** Use supported phrasings (e.g. “list pods in &lt;namespace&gt;”, “describe pod &lt;name&gt; in &lt;namespace&gt;”) or configure an LLM for free-form questions.

### D. References

- KubeDash lib/k8s: `src/kubedash/lib/k8s/`
- SSO / token: `lib.sso.get_user_token`, `lib.k8s.server.k8sClientConfigGet`
- Plugin docs: `docs/plugins/ai-chat.md`

---

**Document Version:** 2.0  
**Last Updated:** March 2026
