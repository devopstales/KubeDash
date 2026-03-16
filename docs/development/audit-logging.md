# Audit logging

KubeDash records sensitive and destructive user actions in an **audit log** for compliance and security review. Events are stored in a database table and can be queried and exported by Admins via the UI or API. This document describes how audit logging works and how to use it.

## Overview

- **What is recorded**: Login/logout, user and group lifecycle (create, delete, update, privilege changes), configuration changes (K8s cluster config, registry, SSO), destructive operations (delete pod, namespace, deployment, project, application, conversation, registry image tag), application create/update, project create, Helm install/uninstall, role create, and audit log export. Each event includes user identity, timestamp, action, resource, and outcome (success/failure/denied).
- **Storage**: Events are written to the `audit_log` table via a non-blocking queue and background worker so request latency is not impacted.
- **Access**: Only users with the **Admin** role can view and export the audit log (Settings → Audit Log, or `/api/v1/audit`).

## Configuration

In `kubedash.ini`:

```ini
[audit]
enabled = true
```

Set `enabled = false` to disable writing audit events (no events are written; existing UI/API still require Admin).

## Viewing and exporting the audit log

### UI (Admin only)

1. Open **Settings** in the sidebar (Admin role only).
2. Click **Audit Log**.
3. Use filters: User, Action, Resource, Result, and date range. Click **Apply** or **Reset**.
4. Use **Export CSV** or **Export JSON** to download the filtered data (up to 10,000 rows). Each export is itself recorded as an `audit_export` event.

### API (Admin only)

- **List**: `GET /api/v1/audit?page=1&per_page=50&user_id=...&action=...&resource=...&result=...&date_from=...&date_to=...`  
  Returns `{ "data": [ {...} ], "metadata": { "total", "page", "per_page", "pages" } }`.
- **Export CSV**: `GET /api/v1/audit/export?format=csv&...` (same query params as filters). Returns `audit-log.csv` attachment.
- **Export JSON**: `GET /api/v1/audit/export?format=json&...`. Returns JSON body; the UI may trigger a file download.

Non-Admin requests receive `403 Forbidden`.

## Emitting audit events in code

Use `log_audit_event()` from `lib.audit` after a sensitive or destructive operation:

```python
from lib.audit import log_audit_event

# After successful login, user delete, etc.
log_audit_event(
    user_id=actor_username,       # who performed the action
    action="user_delete",           # action type (e.g. login, user_delete, delete_k8s_pod)
    resource="user:jane",          # affected resource (e.g. user:jane, pod:default/my-pod)
    result="success",              # success | failure | denied
    trace_id=getattr(g, "correlation_id", None),
    details={"key": "value"},      # optional dict for extra context
)
```

- **user_id**: Username or identifier of the actor (use `session.get("user_name", "unknown")` or similar).
- **action**: Verb or label (e.g. `login`, `user_create`, `user_update`, `sso_config_create`, `registry_image_delete`, `helm_install`, `project_create`, `audit_export`).
- **resource**: Affected resource; use a consistent pattern (e.g. `user:<name>`, `pod:<namespace>/<name>`).
- **result**: `success`, `failure`, or `denied`.
- **trace_id**: Optional; from `g.correlation_id` when in a request context.
- **details**: Optional dict; avoid storing large or highly sensitive data.

Events are queued and written asynchronously; do not rely on them for request flow control.

## Schema (database)

The `audit_log` table has: `id`, `created_at`, `trace_id`, `user_id`, `action`, `resource`, `result`, `details` (JSON), `message`.

## Key files

| File | Purpose |
|------|---------|
| `lib/audit.py` | `log_audit_event()`, queue, background worker, `AuditLog` model. |
| `blueprint/api/audit.py` | List and export API endpoints (`/api/v1/audit`, `/api/v1/audit/export`). |
| `blueprint/settings/settings.py` | Route `/settings/audit-log`. |
| `templates/settings/audit-log.html.j2` | Audit log page (table, filters, export). |
| `migrations/versions/f8a1b2c3d4e5_audit_log_table.py` | Creates `audit_log` table. |

## References

- [Logging](logging.md) – Application log format and trace ID (audit events are separate from application logs).
