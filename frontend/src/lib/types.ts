/**
 * Frontend API types — derived from the backend OpenAPI contract
 * (openapi.json, dumped from Flask-Smorest via the backend test client;
 * `pnpm exec openapi-typescript openapi.json` generated the raw schema,
 * these are the view-facing extracts of its components).
 */
export interface ErrorEnvelope {
  error: { code: string; message: string }
}

export interface Me {
  sub: string
  email: string | null
  display_name: string | null
  groups: string[]
  role: string
  // MeOut growth (TICKET-16, re-dumped openapi.json): the Profile page's
  // identity fields. auth_source is a plain string in the schema (no
  // enum), so it stays un-unioned; kubeconfig_source/last_login_at are
  // nullable.
  auth_source: string
  kubeconfig_source: string | null
  last_login_at: string | null
}

export interface Cluster {
  id: number
  name: string
  api_server?: string
  context?: string | null
  status?: string
  last_probe_at?: string | null
  // ClusterOut growth (TICKET-16): 'registry' on every real row, 'admin' on
  // the synthetic id-0 row the list prepends for admins. Plain string in the
  // schema (no enum) — added for contract completeness; no view reads it yet.
  source?: string
}

export interface ClusterIn {
  name: string
  api_server: string
  kubeconfig: string
  context: string
}

export interface Health {
  status: string
}

/** A Pod item as returned by /api/v1/clusters/<id>/resources/pods. */
export interface Pod {
  metadata?: {
    name?: string
    namespace?: string
    [key: string]: unknown
  }
  status?: {
    phase?: string
    [key: string]: unknown
  }
  [key: string]: unknown
}

export interface ResourceList {
  kind?: string
  cluster?: string
  items: Pod[]
}

export interface RefreshPair {
  access: string
  refresh?: string
}

/** A row of GET /api/v1/permissions/my-access — the caller's own bindings. */
export interface MyAccessBinding {
  cluster: string
  namespace: string | null
  template: string | null
  created_at: string
}

// --- Admin (TICKET-07) — shapes mirror backend/app/schemas/permissions.py ---

/** A row of GET /api/v1/admin/users (UserOut). */
export interface AdminUser {
  id: number
  sub: string
  email: string | null
  display_name: string | null
  groups: string[]
  role: string
  status: string
  /** `oidc` renders as OpenID, `local` as Local (4.1 Type column). */
  auth_source?: string
  cluster_count: number
  last_login_at: string | null
  /** The main-branch "Type" column: "Local" (auth_source=local) or "OIDC". */
  user_type: string
}

/** A row of GET /api/v1/admin/groups (group → member_count). */
export interface GroupOut {
  group: string
  member_count: number
}

/** One {api_groups, resources, verbs} row of an RBAC template (R2). */
export interface RoleRule {
  api_groups: string[]
  resources: string[]
  verbs: string[]
}

/** A row of GET /api/v1/admin/permissions/templates (TemplateOut). */
export interface RBACTemplate {
  id: number
  name: string
  description: string
  scope: 'namespace' | 'cluster'
  rules: RoleRule[]
  builtin: boolean
  created_by: string | null
  created_at: string | null
}

/**
 * A permission audit row — the documented shape of `audit_log` (AuditOut /
 * app/models/audit.py). GET /api/v1/audit still 501s (base-structure stub);
 * the Audit tab renders an empty state until the read route lands.
 */
export interface AuditEntry {
  id: number
  action: string
  actor_sub: string
  target: string
  cluster: string | null
  namespace: string | null
  template: string | null
  at: string
}
