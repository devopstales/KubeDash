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
