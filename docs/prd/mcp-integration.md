# Product Requirements Document: MCP Integration (AI Chatbot)

**Document Version**: 1.2  
**Last Updated**: February 2026  
**Product**: KubeDash  
**Feature Area**: MCP Integration & AI Chatbot  
**Status**: Draft  

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for **MCP (Model Context Protocol) integration** and an **in-app AI chatbot** in KubeDash. The feature enables users to interact with their Kubernetes cluster using natural language through a persistent chat interface. The chatbot uses MCP servers (e.g. Kubernetes MCP server) to execute cluster operations in response to user messages, providing a single-pane experience where dashboard and conversational AI are unified.

**Current implementation (v1)**: The plugin uses **intent-based parsing** (pattern matching on the user message) to map phrases to MCP tool calls. There is **no LLM in the loop**: the backend parses the message, selects a tool, calls the MCP server, and formats the response. This delivers fast, predictable answers for a defined set of queries. **LLM integration** (open-ended questions, multi-turn reasoning) is listed as a future enhancement.

### 1.2 Background

- **Model Context Protocol (MCP)** is an open protocol that allows AI assistants to call tools and access structured data from external servers. MCP servers expose capabilities (e.g. list pods, get logs, run Helm operations) that an LLM can invoke during a conversation.
- **Kubernetes MCP servers** expose cluster operations as MCP tools, so an AI can answer questions like “Which pods are not ready in namespace X?” or “Show me recent events in the cluster” by calling those tools.
- **In-app chatbot** patterns in operational UIs provide a persistent chat panel (sidebar or slide-out) so users can ask questions and run actions without leaving the dashboard. Messages are shown in a clear thread (user vs. assistant), with support for markdown and code in responses.

Integrating MCP into KubeDash allows platform and DevOps users to query and, where permitted, act on the cluster via natural language while staying inside the same UI they use for browsing resources.

### 1.3 Goals

1. **Unified experience**: Chat available from anywhere in KubeDash (global chat panel or entry point).
2. **MCP-backed intelligence**: Chatbot uses at least one MCP server (e.g. Kubernetes MCP server) so answers and actions are grounded in real cluster data and safe, tool-defined operations. **Target**: multi-MCP infrastructure—**containers/kubernetes-mcp-server** for Kubernetes and Helm CRUD, **k8sgpt-ai/k8sgpt** for diagnosing problems (see §7.4).
3. **Familiar chat UX**: A dedicated chat UI with message history, user/assistant distinction, and input area, consistent with common in-app AI chat interfaces.
4. **Security and consistency**: Reuse KubeDash authentication and RBAC; no exposure of LLM/MCP credentials to the browser; optional read-only or non-destructive mode for MCP tools.
5. **Operational clarity**: Clear loading/error states, optional streaming, and audit-friendly logging for tool use.

---

## 2. User Personas

### 2.1 Platform Engineer

- **Role**: Manages cluster configuration and platform tooling.
- **Goals**: Ask “What’s using the most CPU in namespace Y?” or “List Helm releases that failed” without switching to CLI or multiple UIs.
- **Frustrations**: Context switching between dashboard and terminal or external AI tools.

### 2.2 DevOps Engineer

- **Role**: Deploys and troubleshoots applications.
- **Goals**: Use natural language to inspect pods, logs, events, and deployments from one place.
- **Frustrations**: Remembering exact kubectl/Helm commands for every question.

### 2.3 SRE / On-Call Engineer

- **Role**: Monitors cluster health and responds to incidents.
- **Goals**: Quickly ask “Show me failing pods” or “Recent errors in namespace X” and get answers in the same UI as the resource browser.
- **Frustrations**: Copy-pasting between dashboard and external chat or runbooks.

### 2.4 Developer

- **Role**: Develops and debugs applications on the cluster.
- **Goals**: Ask “What’s the status of deployment/myapp?” or “Logs for pod X” in plain language.
- **Frustrations**: Needing terminal access for simple queries.

---

## 3. User Stories

### 3.1 Chat UI

#### US-CHAT-001: Open and close the chat panel
**As a** logged-in user  
**I want to** open and close a dedicated chat panel from anywhere in KubeDash  
**So that** I can start or resume a conversation without leaving the current page  

**Acceptance Criteria**:
- A persistent entry point (e.g. floating button or header icon) opens the chat panel.
- The chat panel is a distinct, clearly visible area (e.g. sidebar or slide-over panel).
- The panel can be closed/collapsed so the main dashboard has full width.
- Panel state (open/closed) can be remembered for the session (optional: persisted per user).

**Priority**: P0 (Critical)  
**Status**: ⚠️ Partial — Dedicated page `/plugins/mcp-chat`; no global panel from main layout

---

#### US-CHAT-002: Send a message and see a response
**As a** user  
**I want to** type a message and receive an AI-generated response in the chat  
**So that** I can get answers about my cluster in natural language  

**Acceptance Criteria**:
- A text input is available at the bottom (or logical end) of the chat panel.
- User can send a message (Enter or Send button).
- The user message appears immediately in the thread with clear visual distinction (e.g. user messages on one side, assistant on the other).
- The assistant response appears after the backend responds; loading indicator is shown while waiting.
- Empty or whitespace-only messages are not sent.

**Priority**: P0 (Critical)  
**Status**: ✅ Implemented

---

#### US-CHAT-003: View conversation history in the session
**As a** user  
**I want to** see the current conversation (user and assistant messages) in order  
**So that** I can follow the thread and refer back to earlier answers  

**Acceptance Criteria**:
- Messages are displayed in chronological order.
- User and assistant messages are visually distinct (layout, color, or label).
- The thread scrolls so the latest message is in view when new content is added.
- At least the current session’s messages are retained for the duration of the session.

**Priority**: P0 (Critical)  
**Status**: ✅ Implemented — Conversation history persisted per user in DB; on load the most recent conversation and its messages are restored.

---

#### US-CHAT-004: Read formatted assistant responses (markdown and code)
**As a** user  
**I want to** see assistant responses with markdown and code blocks rendered  
**So that** I can read structured answers, lists, and copy commands or snippets  

**Acceptance Criteria**:
- Markdown in assistant messages is rendered (headings, lists, bold, links, etc.).
- Code blocks are rendered with syntax highlighting where applicable.
- Plain text remains readable when no markdown is used.
- Copy action for code blocks is available (optional but recommended).

**Priority**: P1 (High)  
**Status**: ✅ Implemented

---

#### US-CHAT-005: Start a new conversation
**As a** user  
**I want to** start a new conversation thread  
**So that** I can separate topics or clear context  

**Acceptance Criteria**:
- A “New conversation” (or equivalent) action is available in the chat UI.
- Starting a new conversation clears or archives the current thread and shows an empty state.
- Previous thread is no longer shown in the active view (implementation may keep history server-side for audit).

**Priority**: P1 (High)  
**Status**: ✅ Implemented — "New" clears the view and conversation_id; next send creates a new conversation (persisted). Previous threads remain in DB for the user.

---

#### US-CHAT-006: See errors and empty states
**As a** user  
**I want to** see clear feedback when the chatbot is unavailable or returns an error  
**So that** I know when to retry or contact support  

**Acceptance Criteria**:
- If the backend or MCP is unreachable, an explicit error message is shown in the chat or in the panel.
- Empty state when there are no messages (e.g. short hint or suggested first questions).
- Optional: retry control for failed requests.

**Priority**: P1 (High)  
**Status**: ✅ Implemented

---

### 3.2 MCP Integration

#### US-MCP-001: Chatbot uses Kubernetes cluster context via MCP
**As a** user  
**I want** the chatbot to answer questions using live cluster data (pods, events, logs, etc.)  
**So that** answers are accurate and up to date  

**Acceptance Criteria**:
- KubeDash backend (or a dedicated service) connects to at least one MCP server (e.g. Kubernetes MCP server).
- The LLM can invoke MCP tools (e.g. list pods, get logs, list events) during the conversation.
- Tool calls use the same cluster access as KubeDash (e.g. in-cluster config or kubeconfig) and respect RBAC.
- Responses that depend on cluster state reflect the state at the time of the tool call.

**Priority**: P0 (Critical)  
**Status**: ✅ Implemented — Intent-based tool invocation; cluster data via MCP (no LLM)

---

#### US-MCP-002: Configurable MCP server endpoint
**As a** platform administrator  
**I want to** configure the MCP server URL (and optionally auth) for the chatbot  
**So that** we can point to our own Kubernetes MCP server or other MCP servers  

**Acceptance Criteria**:
- Configuration (e.g. MCP server URL, transport: HTTP/SSE) is stored in server-side config or environment.
- Chat backend uses this configuration to connect to the MCP server.
- Invalid or unreachable MCP configuration results in clear error state in the UI or logs (no silent failure).

**Priority**: P1 (High)  
**Status**: ✅ Implemented

---

#### US-MCP-003: Optional read-only or non-destructive mode for MCP
**As a** platform administrator  
**I want to** restrict the chatbot to read-only or non-destructive MCP tools  
**So that** we can offer chat in sensitive environments without allowing mutations  

**Acceptance Criteria**:
- Configuration option (e.g. “read-only” or “non-destructive”) is available.
- When enabled, only tools that do not create/update/delete resources are exposed to the LLM (or the MCP server is started with equivalent flags).
- Documentation describes how to enable and what is allowed.

**Priority**: P2 (Medium)  
**Status**: ✅ Implemented — `read_only` in `[mcp_integration]` in kubedash.ini; when true, only read intents (list, describe, logs, Helm list) are executed; write intents receive a message that write operations are disabled.

---

### 3.3 Authentication and Authorization

#### US-AUTH-001: Chat uses KubeDash session
**As a** logged-in user  
**I want** the chatbot to use my existing KubeDash session  
**So that** I am not prompted to log in again and my permissions are consistent  

**Acceptance Criteria**:
- Chat API requests are authenticated with the same session (e.g. cookie) as the rest of KubeDash.
- Unauthenticated requests to the chat API receive 401 and no response body that leaks internals.
- Session timeout behavior is consistent with the rest of the application.

**Priority**: P0 (Critical)  
**Status**: ✅ Implemented

---

#### US-AUTH-002: Chat respects cluster RBAC
**As a** platform administrator  
**I want** chatbot-initiated cluster operations to respect Kubernetes RBAC  
**So that** users only see and do what they are allowed to do in the cluster  

**Acceptance Criteria**:
- MCP/backend uses the same identity or impersonation as the KubeDash user when calling the cluster (or MCP server uses kubeconfig that reflects user access).
- If the user has no access to a resource or namespace, tool results and answers reflect that (e.g. empty list or “access denied”) and do not expose other users’ data.
- No privilege escalation: the chatbot cannot act with higher permissions than the logged-in user.

**Priority**: P0 (Critical)  
**Status**: ✅ Implemented

---

### 3.4 Experience and Operations

#### US-EXP-001: Streaming responses (optional)
**As a** user  
**I want** long answers to stream into the chat as they are generated  
**So that** I see progress and can read earlier parts while the rest is still generating  

**Acceptance Criteria**:
- Optional: backend supports streaming (e.g. SSE or WebSocket) for assistant messages.
- UI shows incremental updates in the assistant message area until the response is complete.
- If streaming is not implemented, a single response after completion is acceptable for v1.

**Priority**: P2 (Medium)  
**Status**: ❌ Not implemented

---

#### US-EXP-002: Suggested or example prompts
**As a** user  
**I want** optional suggested questions or example prompts when the chat is empty  
**So that** I can quickly try useful queries  

**Acceptance Criteria**:
- When there are no messages (or in a “welcome” state), one or more suggested prompts are shown (e.g. “List pods not ready”, “Show recent events in default namespace”).
- Clicking a suggestion sends that message as the user message.
- Suggestions are configurable or curated for Kubernetes/KubeDash (no reference to external products).

**Priority**: P2 (Medium)  
**Status**: ❌ Not implemented

---

## 4. Functional Requirements

### 4.1 Chat UI

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-CHAT-01 | Provide a persistent chat panel (sidebar or slide-over) accessible from the main layout | P0 | ⚠️ Partial — Dedicated page `/plugins/mcp-chat`; no global sidebar from main layout |
| FR-CHAT-02 | Display user and assistant messages in a single, ordered thread with clear visual distinction | P0 | ✅ Implemented |
| FR-CHAT-03 | Provide a text input and send control (Enter or button) to submit user messages | P0 | ✅ Implemented |
| FR-CHAT-04 | Show a loading state while waiting for the assistant response | P0 | ✅ Implemented |
| FR-CHAT-05 | Render assistant messages with markdown and code blocks | P1 | ✅ Implemented |
| FR-CHAT-06 | Support starting a new conversation (clear or archive current thread) | P1 | ✅ Implemented — "New" clears thread and conversation_id; history persisted per user |
| FR-CHAT-07 | Show explicit error and empty states when the service is unavailable or no messages exist | P1 | ✅ Implemented |
| FR-CHAT-08 | Optional: support streaming of assistant responses | P2 | ❌ Not implemented |
| FR-CHAT-09 | Optional: show suggested prompts when the conversation is empty | P2 | ❌ Not implemented |

### 4.2 MCP Integration

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-MCP-01 | Backend connects to at least one MCP server (e.g. Kubernetes MCP server) over HTTP/SSE | P0 | ✅ Implemented |
| FR-MCP-02 | LLM receives tool definitions from MCP and can invoke tools during a turn | P0 | ⚠️ Partial — Intent-based tool invocation (no LLM); tools invoked directly from parsed intent |
| FR-MCP-03 | MCP server endpoint (URL, transport) is configurable (server-side config or env) | P1 | ✅ Implemented — `kubedash.ini` [mcp_integration] mcp_server_url, helm_list_tool |
| FR-MCP-04 | Optional: read-only or non-destructive mode to restrict which MCP tools are used | P2 | ✅ Implemented — `read_only` in `[mcp_integration]`; when true, only read intents are allowed; write intents return a message that write operations are disabled |

### 4.3 Authentication and Authorization

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-AUTH-01 | Chat API accepts only authenticated requests (e.g. KubeDash session cookie) | P0 | ✅ Implemented — @login_required on chat endpoint |
| FR-AUTH-02 | Cluster access used by MCP/backend is scoped to the logged-in user's RBAC | P0 | ✅ Implemented — SubjectAccessReview before namespace-scoped MCP calls |
| FR-AUTH-03 | LLM and MCP credentials (API keys, tokens) are not exposed to the browser | P0 | ✅ Implemented — MCP URL server-side only; no LLM in v1 |

### 4.4 Backend and API

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-API-01 | Expose a chat API (e.g. POST for send message, optional GET/SSE for streaming) | P0 | ✅ Implemented — POST /api/v1/plugins/mcp-integration/chat/message |
| FR-API-02 | Request/response format supports conversation id, message content, and optional metadata | P0 | ✅ Implemented |
| FR-API-03 | Log or audit tool invocations (which tools, which user, timestamp) for security and debugging | P1 | ⚠️ Partial — Intent and tool success logged; warning on unmatched intent; tracing span attributes |

---

## 5. UI/UX Requirements (Chatbot Interface)

The following describes the target behavior and layout of the in-app chatbot so that it is consistent, accessible, and recognizable as a chat interface.

### 5.1 Layout and Entry

- **Entry point**: A global, persistent way to open the chat (e.g. floating action button, header icon, or sidebar item) that is visible across main application views.
- **Chat panel**: A dedicated area that does not replace the whole screen: either a **collapsible sidebar** (e.g. right or left) or a **slide-over panel** that overlays part of the content. When open, the panel has a clear boundary and the main content area may resize or be partially obscured.
- **Panel state**: Users can close/collapse the panel to reclaim space; state can be remembered for the session (or per user) so reopening shows the same thread.

### 5.2 Message Display

- **Thread**: Messages are shown in a single, chronological thread. New messages appear at the bottom.
- **User vs. assistant**: User messages and assistant messages are visually distinct (e.g. different alignment, background color, or avatar/label). Common patterns: user on the right, assistant on the left; or both left-aligned with different styles.
- **Scrolling**: The message list is scrollable. When a new message is added or the user sends a message, the view scrolls so the latest content is visible.
- **Formatting**: Assistant messages support markdown (headings, lists, bold, links) and code blocks with syntax highlighting. Code blocks have a copy option where feasible.

### 5.3 Input and Actions

- **Input area**: A text input (single or multi-line) is fixed at the bottom (or logical end) of the chat panel. Placeholder text can suggest the user ask a question (e.g. “Ask about your cluster…”).
- **Send**: Submit via a dedicated Send button and/or Enter (with optional Shift+Enter for new line). Submit is disabled when the input is empty or only whitespace, and optionally while a response is in progress.
- **New conversation**: A clear “New conversation” (or similar) control is available (e.g. in the panel header or as an icon) to start a fresh thread.

### 5.4 States and Feedback

- **Loading**: While the assistant is generating a response, a loading indicator (e.g. spinner or skeleton) is shown in the assistant message area or next to the last user message.
- **Error**: If the request fails or the service is unavailable, an error message is shown in the thread or in a banner in the panel, with optional retry.
- **Empty state**: When there are no messages, show a short welcome line and optionally 2–4 suggested prompts the user can click to send.

### 5.5 Accessibility and Responsiveness

- **Keyboard**: Chat panel and input are focusable and operable via keyboard (Tab, Enter, Escape to close if applicable).
- **Screen readers**: Message roles (user/assistant) and loading/error states are exposed to assistive technologies.
- **Responsive**: On smaller viewports, the chat panel can expand to full width or a large overlay so the thread and input remain usable.

---

## 6. Non-Functional Requirements

### 6.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Time to first token (if streaming) or first byte of response | < 5 s under normal load |
| NFR-PERF-02 | Chat panel open/close and message append | Feels instant (< 200 ms) |
| NFR-PERF-03 | MCP tool call round-trip | Depends on cluster; target < 10 s for typical list/get |

### 6.2 Security

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-SEC-01 | LLM API keys and MCP credentials only on server | Never sent to frontend |
| NFR-SEC-02 | Chat API requires valid KubeDash session | Enforced on every request |
| NFR-SEC-03 | Audit log for MCP tool invocations | Log tool name, user, timestamp (no sensitive args in log) |
| NFR-SEC-04 | Optional read-only mode | Configurable to disable write tools |

### 6.3 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | MCP transport | At least HTTP + SSE (e.g. Kubernetes MCP server /mcp or /sse) |
| NFR-COMP-02 | Browsers | Same as KubeDash (modern evergreen) |
| NFR-COMP-03 | Kubernetes | Same as KubeDash (e.g. 1.25+) |

---

## 7. Technical Considerations

### 7.1 Architecture (High Level)

- **Frontend**: New chat UI component(s) in the existing KubeDash frontend (Jinja2 + JS or existing stack). Renders the chat panel, message list, input, and optional suggestions; calls the chat API.
- **Backend**: New KubeDash routes (or a small sidecar service) that:
  - Accept chat requests (session-authenticated).
  - Maintain conversation context (session or DB).
  - Call the configured LLM API with conversation history and available tools.
  - Act as MCP client: discover tools from the MCP server(s), send tool calls, and return results to the LLM.
  - Return (or stream) the assistant reply to the client.
- **MCP server**: At least one MCP server (e.g. Kubernetes MCP server) running and reachable from the backend (same cluster or configured URL). Backend uses the same cluster identity (or user-impersonated identity) when the MCP server talks to the API server.

### 7.2 MCP Client

- Backend implements an MCP client that can:
  - Connect to an MCP server over HTTP/SSE (e.g. Kubernetes MCP server’s `/mcp` or `/sse` endpoint).
  - Fetch the list of tools (and optionally prompts) from the server.
  - Execute tool calls and return structured results to the LLM.
- Configuration: MCP server URL (and optionally transport) in config file or environment; no MCP credentials in frontend.

### 7.3 Kubernetes MCP Server

- The existing Kubernetes MCP server (e.g. in `containers/kubernetes-mcp-server` or `deploy/docker-compose`) can be used as the first MCP server.
- It exposes tools for pods, events, namespaces, resources, Helm, etc. Backend passes the user’s cluster access (in-cluster or kubeconfig) so that RBAC is respected.
- Optional: run the server with `--read-only` or `--disable-destructive` when the platform requires a safe default.

### 7.4 Multi-MCP infrastructure (target)

A **multi-MCP** setup is the target architecture: different MCP servers for different responsibilities, with the backend routing requests by intent or tool category.

| Responsibility | MCP server | Purpose |
|----------------|------------|---------|
| **Kubernetes & Helm object CRUD** | [containers/kubernetes-mcp-server](https://github.com/containers/kubernetes-mcp-server) | List/get/create/update/delete cluster resources (pods, deployments, namespaces, etc.), pod logs, describe, and Helm release operations. Single, well-supported server for all cluster and Helm tooling. |
| **Diagnose problems** | [k8sgpt-ai/k8sgpt](https://github.com/k8sgpt-ai/k8sgpt) | AI-assisted cluster diagnostics: analyze cluster state, surface issues (e.g. failing pods, image pull errors, resource limits), and suggest fixes. Used when the user asks to diagnose, troubleshoot, or explain problems. |

**Routing**: The backend (or an LLM orchestrator) decides which MCP server to call based on intent or tool discovery—e.g. list/get/log/describe/Helm → kubernetes-mcp-server; diagnose/troubleshoot/why is X failing → k8sgpt. Configuration will expose at least two URLs (e.g. `mcp_server_url` for Kubernetes, `mcp_diagnostics_url` for k8sgpt) and optional tool-to-server mapping.

**Benefits**: Separation of concerns; use of specialized diagnostics (k8sgpt) without overloading the general-purpose Kubernetes server; ability to add more MCP servers later (e.g. security, cost) with the same routing pattern.

### 7.5 Data and Privacy

- Conversation content and tool calls may be sent to the LLM provider and to the MCP server(s). Document this in the privacy/security documentation and ensure configuration (e.g. which LLM, which MCP servers) is under platform control.
- In a multi-MCP setup, diagnostics (k8sgpt) may receive cluster metadata and resource state; ensure compliance with data and access policies for each server.
- Avoid logging full message bodies or sensitive tool arguments; log tool name, server (when multiple), user, and timestamp for audit.

---

## 8. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| LLM cost and rate limits | Medium | High | Configurable model and limits; optional usage caps; consider caching for repeated queries |
| MCP server latency or downtime | High | Medium | Clear error UI; retry; health check for MCP endpoint; optional fallback message |
| RBAC or identity misuse | High | Low | Strict use of KubeDash user identity for MCP; read-only option; audit logging |
| Chat UI complexity | Medium | Medium | Reuse existing design system; start with a single panel and minimal features |
| Vendor lock-in to one LLM | Low | Medium | Abstract LLM behind an interface; support at least one open or replaceable provider |

---

## 9. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Chat available and usable | Panel opens, messages send, responses render | Manual/automated smoke test |
| MCP tools invoked successfully | Tool calls return without error for allowed operations | Logs / metrics |
| Session and RBAC alignment | No privilege escalation; 401 for unauthenticated | Security review and tests |
| User adoption (optional) | N/A in v1 | Future: track chat opens and messages per user |

---

## 10. Future Considerations

### 10.1 Potential Enhancements

1. **Multi-MCP infrastructure (target)**: Support multiple MCP servers with role-based routing:
   - **Kubernetes & Helm CRUD**: [containers/kubernetes-mcp-server](https://github.com/containers/kubernetes-mcp-server) for all cluster and Helm object operations (list, get, logs, describe, Helm releases, etc.).
   - **Diagnose problems**: [k8sgpt-ai/k8sgpt](https://github.com/k8sgpt-ai/k8sgpt) for diagnostics and troubleshooting (e.g. "why are my pods failing?", "diagnose cluster issues"). The backend routes diagnose/troubleshoot intents to k8sgpt and resource/list/log/Helm intents to kubernetes-mcp-server. See §7.4.
2. **Conversation persistence**: Save conversation history per user and allow resuming past threads.
3. **Streaming**: Full streaming of assistant responses for better perceived performance.
4. **Suggested prompts**: Configurable or admin-defined suggested questions.
5. **Multi-cluster**: Allow user to choose cluster/context in chat when multiple clusters are configured.
6. **Slash commands**: Optional commands (e.g. `/clear`, `/new`) for power users.

### 10.2 Out of Scope (This Version)

- Voice input or output.
- Embedding third-party chat widgets or iframes.
- Client-side LLM or MCP connection (all server-side).
- Public reference to any specific third-party product in docs or UI.

---

## 11. Appendix

### 11.1 Chat API (Implemented)

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/plugins/mcp-integration/chat/message | Send a user message; return assistant reply (JSON). Persists user and assistant messages when conversation_id is provided or created. |
| GET | /api/v1/plugins/mcp-integration/chat/conversations | List conversations for the current user (query: `limit`, default 20, max 100). |
| GET | /api/v1/plugins/mcp-integration/chat/conversations/<id>/messages | Get messages for a conversation (must belong to current user). |

**POST message request body**: `{ "content": "user message text", "conversation_id": "optional" }`.  
**POST message response**: `{ "conversation_id": "...", "message": { "role": "assistant", "content": "..." } }`.  
**Authentication**: KubeDash session (login required). Unauthenticated requests receive 401.

Optional (not implemented in v1): GET /chat/stream/{id} for SSE streaming.

### 11.2 Supported intents and MCP tool mapping (v1)

The backend parses the user message and maps it to one of the following intents. Namespace can be specified with phrases like “in \<namespace\> namespace”.

| Intent | Example user phrases | MCP tool(s) tried | Notes |
|--------|----------------------|-------------------|--------|
| **list_namespaces** | “List all namespaces”, “Show namespaces” | `namespaces_list` | No namespace filter. |
| **list_resource** | “List pods in balazs-paldi namespace”, “List deployments”, “Get PodMetrics in \<ns\> namespace” | `resources_list` (apiVersion, kind, namespace) | Resource list from cluster discovery; core resources (e.g. Pod) preferred over extension (e.g. PodMetrics) when names collide. |
| **PodMetrics** (special) | “List PodMetrics in \<namespace\>” | — | Fetched via cluster metrics API (CPU, MEMORY, WINDOW); not MCP. |
| **pods** (list in ns) | “How many pods in \<ns\>?”, “List pods in \<ns\> namespace” (when not matching list_resource) | `pods_list_in_namespace` | Table with NAMESPACE, NAME, READY, STATUS, AGE. |
| **pod_logs** | “Get logs of \<pod\> pod in \<ns\> namespace” | `pods_log` (args: `name`, `namespace`), then `pod_logs`, `show_logs`, `get_pod_logs`, `get_logs_for_pod_and_container` | Log output is collapsed: consecutive duplicate lines shown once with “… (repeated N more times)”. |
| **describe_pod** | “Describe \<pod\>”, “Describe \<pod\> in \<ns\> namespace” | `describe_pod`, `get_pod`, `pod_describe`, `describe_resource` | Uses `namespace` (default if omitted) and `pod_name`. |
| **helm_releases** | “List Helm releases”, “List Helm releases in \<ns\>” | `helm_list` (or configurable `helm_list_tool`) | Params: `all_namespaces`, `namespace`. |

**Write intents** (create, update, delete, helm install, helm uninstall) are only executed when `read_only = false` in `[mcp_integration]`. When `read_only = true`, the assistant replies that write operations are disabled.

| **create_resource** | "Create namespace \<name\>", "Create deployment \<name\> in namespace \<ns\>" | `namespace_create` / `create_namespace` (namespace only); `resource_create` / `create_resource` / `kubectl_create` (kind+name+ns) | Write. |
| **update_resource** | "Update deployment \<name\> [in namespace \<ns\>]", "Patch pod \<name\> in \<ns\>" | `resource_update` / `kubectl_patch` / `patch_resource` | Write; some servers require a patch body. |
| **delete_resource** | "Delete pod \<name\> [in namespace \<ns\>]", "Delete deployment \<name\> in \<ns\>" | `resource_delete` / `delete_resource` / `kubectl_delete` | Write. |
| **helm_install** | "Install helm chart \<chart\> [as \<release\>] [in namespace \<ns\>]", "Helm install \<release\> \<chart\>" | `helm_install` / `install_helm_chart` / `helm_install_chart` | Write. |
| **helm_uninstall** | "Uninstall helm release \<name\> [in namespace \<ns\>]", "Helm uninstall \<name\>" | `helm_uninstall` / `uninstall_helm_chart` / `helm_uninstall_release` | Write. |

Unmatched or unsupported messages receive a fallback reply listing supported question types and a **warning** in server logs (for observability).

### 11.3 Configuration (kubedash.ini)

**Current** — Under `[mcp_integration]`:

| Option | Description | Default |
|--------|-------------|---------|
| `mcp_server_url` | Base URL of the MCP server (e.g. `http://127.0.0.1:8082`). Empty disables chat MCP. | (empty) |
| `read_only` | If **true**, only read operations are allowed (list, describe, logs, Helm list, diagnose). When **false**, create/delete/update intents are allowed when implemented. When true and the user asks for a write operation, the assistant replies that write operations are disabled. | false |
| `helm_list_tool` | Tool name for listing Helm releases (e.g. `helm_list`). | helm_list |
| `mcp_diagnostics_url` | Base URL of **k8sgpt-ai/k8sgpt** MCP server for error diagnosing. Empty disables diagnostics. Example: `http://127.0.0.1:8089` (k8sgpt serve --mcp --mcp-http --mcp-port 8089). | (empty) |
| `mcp_diagnostics_intent_keywords` | Comma-separated keywords that route to diagnostics (for future use; intent is currently pattern-based). | diagnose,troubleshoot,why,failing,issues,problems |

### 11.4 Related Documentation

- [containers/kubernetes-mcp-server](https://github.com/containers/kubernetes-mcp-server) — MCP server for Kubernetes and Helm CRUD (target: primary MCP for cluster operations).
- [k8sgpt-ai/k8sgpt](https://github.com/k8sgpt-ai/k8sgpt) — AI-assisted Kubernetes diagnostics; target MCP for "diagnose problems" (see §7.4).
- [Deploy docker-compose (dc-mcp-server)](../../deploy/docker-compose/dc-mcp-server.yaml) — Kubernetes MCP server as part of the dev stack.
- [KubeDash Product Requirements](./kubedash-product-requirements.md) — Overall product and feature areas (if present).
- [Authentication & User Management](./authentication-user-management.md) — Session and RBAC context for chat (if present).

### 11.5 Glossary

- **MCP (Model Context Protocol)**: Protocol for AI assistants to discover and invoke tools and resources from MCP servers.
- **MCP server**: A service that exposes tools (and optionally prompts) over MCP (e.g. HTTP/SSE). Example: Kubernetes MCP server for cluster operations.
- **Chat panel**: The dedicated UI region (sidebar or slide-over) that shows the conversation and input.
- **Tool**: An MCP capability (e.g. “list pods”) that the backend or LLM can call with parameters; the MCP server executes it and returns a result.
- **Intent**: A structured interpretation of the user message (e.g. list_resource, pod_logs) used in v1 to select which MCP tool to call without an LLM.
- **Multi-MCP**: Target architecture with multiple MCP servers: **containers/kubernetes-mcp-server** for K8s/Helm CRUD and **k8sgpt-ai/k8sgpt** for diagnostics (see §7.4).

---

## 12. Current implementation (as-built)

This section describes the implemented behavior of the MCP Integration plugin as of the last update.

### 12.1 Architecture

- **UI**: Dedicated chat page at `/plugins/mcp-chat` (GET). Renders a chat thread (user / assistant bubbles), text input, and send action. Calls `POST /api/v1/plugins/mcp-integration/chat/message` with `{ "content": "..." }`. Markdown and code blocks in assistant content are rendered.
- **Backend**: Plugin blueprint `mcp_integration_api_bp` registered under `/api/v1/plugins` (prefix `mcp-integration`). Single endpoint: `POST /chat/message` (MethodView `post()`). No LLM: message is parsed with a single intent parser, then one of several code paths runs (list namespaces, list resource, pod logs, describe pod, Helm releases, list pods in namespace). Each path calls the MCP server via `query_mcp_tool(url, tool_name, arguments)` and formats the tool output for the reply.
- **MCP client**: HTTP JSON-RPC to `{mcp_server_url}/mcp` (method `tools/call`). Also supports Streamable HTTP handshake (initialize, notifications/initialized, tools/call) and SSE where available. Implemented in `mcp_client.py` and `mcp_session.py`.
- **RBAC**: Before namespace-scoped MCP calls, the backend checks namespace access via SubjectAccessReview (when extension_api is available). On failure, returns 403 with a clear message.
- **Read-only**: If `[mcp_integration]` `read_only = true`, only intents in `READ_ONLY_INTENT_TYPES` (list_namespaces, pods, describe_pod, pod_logs, helm_releases, list_resource, diagnose) are executed. Any other (e.g. future create/delete) intent returns an assistant message that write operations are disabled.
- **K8sGPT diagnostics**: When `mcp_diagnostics_url` is set and the user message matches the diagnose intent (e.g. "diagnose cluster", "troubleshoot", "why are my pods failing"), the backend calls the K8sGPT MCP server's `analyze` tool (Streamable HTTP) with `explain: true` and optional `namespace`. Result is formatted as **Cluster diagnostics (K8sGPT)** or **Diagnostics for namespace \<ns\> (K8sGPT)**. Namespace-scoped diagnose is subject to RBAC (SubjectAccessReview).

### 12.2 Intent parsing

- **Module**: `plugins.mcp_integration.mcp_client.parse_intent(text)`.
- **Order**: Pattern-driven intents first (list_namespaces, diagnose, helm_releases, pod_logs, describe_pod, helm_uninstall, helm_install, create_resource, delete_resource, update_resource), then list_resource (using cluster discovery resource list map, longer keys first so "list pods" matches Pod not PodMetrics), then pods fallback (whole-word pod/pods and namespace).
- **Namespace extraction**: Phrases like "in X namespace", "in namespace X", "in X" at end of sentence. Default namespace for pod_logs and describe_pod when not specified: default.

### 12.3 Resource list map

- Built from Kubernetes API discovery at plugin load (`plugins.mcp_integration.__init__`). Core API resources (e.g. pods, pod) are not overwritten by extension API resources (e.g. metrics.k8s.io pods for PodMetrics). Kind name is also registered as a key (e.g. podmetrics) so "list podmetrics" works.

### 12.4 Pod logs

- Tool candidates: pods_log (with args name, namespace), then pod_logs, show_logs, get_pod_logs, get_logs_for_pod_and_container (with pod_name, namespace). First successful tool wins.
- Log output is passed through _format_pod_log_output(): consecutive duplicate lines are collapsed to one line plus "... (repeated N more times)".

### 12.5 PodMetrics

- For "list PodMetrics in namespace", the backend does not call MCP for the list. It fetches PodMetrics from the cluster metrics API (metrics.k8s.io/v1beta1 pods), aggregates per pod (sum CPU/memory across containers), and formats a table with columns NAME, CPU, MEMORY, WINDOW. If the metrics API fails, the implementation falls back to MCP resources_list for PodMetrics (which may return only NAMESPACE/NAME).

### 12.6 Write operations (create, update, delete, Helm install/uninstall)

- **delete_resource**: Resource kind is resolved via `get_resource_list_map()` (e.g. "pod" → Pod). MCP tools tried: `resource_delete`, `delete_resource`, `kubectl_delete`, `resources_delete`. Namespace defaults to `default` if omitted.
- **create_resource**: Two forms: (1) "Create namespace X" → `namespace_create` / `create_namespace` / `namespaces_create` with `name`; (2) "Create deployment Y in namespace Z" → kind resolved from resource map, then `resource_create` / `create_resource` / `kubectl_create` with namespace, kind, name (and optional apiVersion). Some servers require a YAML manifest for non-namespace resources.
- **update_resource**: Kind resolved from resource map. MCP tools tried: `resource_update`, `kubectl_patch`, `patch_resource` with namespace, kind, name. Many servers require a patch body; the API may return an error suggesting `kubectl patch` if the server rejects the call.
- **helm_install**: Chart name and optional release name, namespace (default `default`). Tools tried: `helm_install`, `install_helm_chart`, `helm_install_chart` with params `chart`, `namespace`, and optionally `release` or `name`.
- **helm_uninstall**: Release name and optional namespace (default `default`). Tools tried: `helm_uninstall`, `uninstall_helm_chart`, `helm_uninstall_release` with `release` and `namespace` (or `name` for uninstall_helm_chart).
- All write intents are blocked when `read_only = true` (intent types are not in `READ_ONLY_INTENT_TYPES`). Namespace access is validated with SubjectAccessReview before each write call.

### 12.7 Observability

- Unmatched or unsupported user messages trigger a warning log: "MCP chat: no intent matched or not supported, returning fallback reply" with content snippet. Intent type and key params are recorded in span attributes when tracing is enabled.

### 12.8 Conversation persistence

- **Models**: `McpConversation` (user_id, created_at, updated_at) and `McpMessage` (conversation_id, role, content, created_at). Stored in `mcp_conversations` and `mcp_messages` (migration `a1b2c3d4e5f6`).
- **POST /chat/message**: Accepts optional `conversation_id`. If missing or invalid for the user, a new conversation is created. User message and assistant reply are persisted; response includes `conversation_id` for the thread.
- **GET /chat/conversations**: Lists conversations for the current user (most recent first; optional `limit`, max 100).
- **GET /chat/conversations/<id>/messages**: Returns messages for a conversation (404 if not found or not owned by user).
- **UI**: On load, fetches the latest conversation and its messages and restores the thread. "New" clears the view and resets conversation_id; the next send creates a new conversation.

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Platform, DevOps*
