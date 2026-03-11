# Audit Logging – Product Requirements Document

**Version:** 1.0  
**Date:** March 2026  
**Status:** Draft

---

## 1. Overview

### 1.1 Purpose

This PRD defines the audit logging strategy for KubeDash so that:

- **Sensitive and destructive user actions** are recorded with user identity, timestamp, action, resource, and outcome for compliance and security review.
- **Audit entries** use a consistent schema (aligned with the application log format where applicable) and are stored in a queryable store.
- **Performance** is preserved via non-blocking writes so request latency is not impacted.

### 1.2 Goals

- **Audit trail**: Record login/logout, user and group lifecycle, privilege changes, configuration changes, and destructive operations (K8s resources, registry, applications, etc.).
- **Storage**: Persist audit events in a dedicated store (e.g. database table) with retention considerations; support query/export for compliance.
- **Format**: Use a consistent event schema with required fields (user_id, action, resource, result) and optional details; align with logging PRD canonical/JSON format when writing to log streams.
- **Non-blocking**: Emit audit events asynchronously (e.g. queue + background worker) so that request handling is not delayed.

---

## 2. Audit Event Schema

### 2.1 Required Fields

Every audit event MUST include:

| Field      | Description                          | Example                    |
|------------|--------------------------------------|----------------------------|
| user_id    | Actor (username or identifier)       | `admin`, `unknown`         |
| action     | Action type (verb or label)          | `login`, `user_delete`     |
| resource   | Affected resource (type:id or path)  | `user:jane`, `pod:default/my-pod` |
| result     | Outcome                              | `success`, `failure`, `denied` |
| timestamp  | Event time (ISO UTC preferred)       | `2026-03-11T13:21:45.246Z` |

Optional: `trace_id`, `details` (dict), `message`. When emitting to the same pipeline as application logs, include `event_type: audit` or `audit: true` so entries can be filtered.

### 2.2 Storage

- **Primary store**: Database table `audit_log` (id, created_at, trace_id, user_id, action, resource, result, details, message).
- **Write path**: Non-blocking (in-memory queue + daemon thread with app context) so request latency is not impacted.
- **Configuration**: `[audit] enabled = true|false` in `kubedash.ini`; when disabled, no events are written.

### 2.3 Requirements (summary)

1. **Audit events**: Record at least login success/failure, logout, user/group/privilege changes, and destructive or sensitive operations with user identity, timestamp, action, resource, and outcome.
2. **Storage**: Use a dedicated audit log store (e.g. database table) with retention considerations; support query/export for compliance reviews.
3. **Format**: Audit entries use a consistent schema with required fields (user_id, action, resource, result). When emitting to the same pipeline as application logs, use the same canonical or JSON format (see Logging PRD) with an `audit: true` or `event_type: audit` marker.
4. **Performance**: Audit logging MUST be non-blocking (e.g. async write or fire-and-forget) so that request latency is not significantly impacted.

---

## 3. Implemented Actions (Current)

The following actions are instrumented with `log_audit_event()` and written to the audit log:

| Category    | Action                  | Resource pattern        | Where |
|-------------|-------------------------|-------------------------|--------|
| **Auth**    | login                    | session                 | Auth (local + SSO callback), success/failure |
|             | logout                   | session                 | Auth |
| **Users**   | user_create              | user:\<name\>           | API, web add user |
|             | user_delete              | user:\<name\>           | API, web delete user |
|             | password_change          | user:\<name\>           | API, success/failure |
|             | user_privilege_update    | user:\<name\>           | API (K8s RBAC) |
|             | auth_cert_generate       | user:\<name\>           | User create/update (non-Local) |
| **Groups**  | group_create             | group:\<name\>          | SSOGroupsCreate (sso_sync) |
|             | group_delete             | group:\<name\>          | API DELETE SSO group |
|             | group_privilege_update   | group:\<name\>          | API (K8s RBAC) |
| **K8s**     | delete_k8s_pod           | pod:\<ns\>/\<name\>     | Workloads API, workload blueprint, AI Chat |
|             | delete_k8s_namespace     | namespace:\<name\>      | Namespaces API, cluster blueprint |
|             | delete_k8s_deployment    | deployment:\<ns\>/\<name\> | AI Chat k8s_adapter |
|             | delete_project           | project:\<name\>       | Extension API |
| **Config**  | k8s_config_create       | k8s_config:\<context\>  | Settings API |
|             | k8s_config_update       | k8s_config:\<context\>  | Settings API |
|             | k8s_config_delete        | k8s_config:\<context\>  | Settings API |
| **Apps**    | delete_application      | application:\<name\>    | Application Catalog API |
| **AI Chat** | delete_conversation     | conversation:\<id\>     | AI Chat API |
| **Registry**| registry_create         | registry:\<url\>        | Registry API |
|             | registry_update         | registry:\<url\>        | Registry API |
|             | registry_delete         | registry:\<url\>        | Registry API |
|             | registry_image_delete   | registry_image:\<url\>/\<image\>:\<tag\> | Registry plugin (image tag delete) |
| **Config**  | sso_config_create        | sso_config              | Settings API (SSO POST create) |
|             | sso_config_update       | sso_config              | Settings API (SSO POST edit) |
| **Users**   | user_update             | user:\<name\>            | API PUT user, web user list POST |
| **Apps**    | application_create      | application:\<name\>    | Application Catalog API |
|             | application_update      | application:\<name\>    | Application Catalog API |
| **K8s**     | project_create          | project:\<name\>        | Extension API (create project) |
| **Helm**    | helm_install            | helm_release:\<ns\>/\<name\> | AI Chat helm_operations |
|             | helm_uninstall          | helm_release:\<ns\>/\<name\> | AI Chat helm_operations |
| **Roles**   | role_create             | role:\<name\>            | lib.user.RoleCreate (bootstrap, auth, etc.) |
| **Admin**   | audit_export             | audit_log                | Audit API (CSV/JSON export) |

---

## 4. Audit Log UI and API (Implemented)

Admins can query and export the audit log for compliance reviews.

### 4.1 UI

- **Location**: **Settings → Audit Log** (sidebar; Admin role only).
- **Page**: `templates/settings/audit-log.html.j2`. Table shows time (UTC), user, action, resource, result, and details.
- **Filters**: User, action, resource, result (success/failure/denied), date range. Apply / Reset.
- **Pagination**: Configurable page size (default 50); total count and page navigation.
- **Export**: **Export CSV** (downloads filtered data as `audit-log.csv`); **Export JSON** (downloads as `audit-log.json`). Export is limited to 10,000 rows and is itself recorded as an `audit_export` event.

### 4.2 API

- **Base path**: `/api/v1/audit`. All endpoints require authentication and **Admin** role (403 otherwise).
- **GET `/api/v1/audit`** – List audit events with optional filters and pagination.
  - Query params: `page`, `per_page` (default 50, max 500), `user_id`, `action`, `resource`, `result`, `date_from`, `date_to` (ISO date or datetime).
  - Response: `{ "data": [ {...} ], "metadata": { "total", "page", "per_page", "pages" } }`. Each item has `id`, `created_at`, `trace_id`, `user_id`, `action`, `resource`, `result`, `details`, `message`.
- **GET `/api/v1/audit/export?format=csv|json`** – Export audit log. Same filter params as list. CSV returns `Content-Disposition: attachment; filename=audit-log.csv`. JSON returns a JSON body (UI may trigger a file download). Export limited to 10,000 rows. Each export is audited (`audit_export`, resource `audit_log`).

---

## 5. Ideas: Additional Actions to Audit

The following are recommended for future implementation to improve coverage and compliance.

### 5.1 Lower Priority (optional / future)

Previously listed high/medium items (sso_config_create/update, user_update, registry_image_delete, helm_install, helm_uninstall, role_create, application_create/update, project_create) are implemented; see §3.

Remaining ideas:

| Action                    | Where / trigger                              | Why |
|---------------------------|-----------------------------------------------|-----|
| **session_invalidate**  | Admin “invalidate all sessions” (if added) | Security and compliance. |
| **kubectl_config_export** | Settings export (kubeconfig generation) | Access to credentials. |

---

## 6. Implementation Notes

### 6.1 Components

| Component        | Responsibility |
|------------------|----------------|
| `lib/audit.py`   | `log_audit_event()`, queue, background worker, `AuditLog` model and DB write. |
| `blueprint/api/audit.py` | Audit API: list and export endpoints (Admin only). |
| `blueprint/settings/settings.py` | Route `/settings/audit-log`; Admin-only audit log page. |
| `templates/settings/audit-log.html.j2` | Audit log UI: table, filters, pagination, export CSV/JSON. |
| `kubedash.ini`   | `[audit] enabled = true`. |
| Call sites       | After sensitive or destructive operations; pass `user_id`, `action`, `resource`, `result`, optional `trace_id` (e.g. from `g.correlation_id`) and `details`. |

### 6.2 References

- Logging PRD: `docs/prd/logging.md` (canonical format, trace_id, JSON schema).
- Audit logging (developer doc): `docs/development/audit-logging.md`
- Implementation: `src/kubedash/lib/audit.py`
- Migration: `migrations/versions/f8a1b2c3d4e5_audit_log_table.py`

### 6.3 Future work

- **Retention**: Configurable retention or archival for the `audit_log` table (e.g. delete or archive events older than N days).
- **OpenTelemetry**: Optionally export audit events to trace/span attributes or log pipeline with `event_type: audit` for correlation.

---

**Document Version:** 1.0  
**Last Updated:** March 2026
