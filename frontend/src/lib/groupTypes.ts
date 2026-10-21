// --- Groups (4.1 /user/group parity) — shapes mirror backend/app/schemas/groups.py ---

/** A row of GET /api/v1/admin/groups (GroupOut). */
export interface GroupRow {
  id: number
  name: string
  display_name: string
  source: 'oidc' | 'manual'
  member_count: number
  created_at: string
}

/** A member of GET /api/v1/admin/groups/<name> (detail payload). */
export interface GroupMember {
  sub: string
  display_name: string | null
  email: string | null
  auth_source: string
}

/** The group detail payload (GroupOut + members). */
export interface GroupDetail extends GroupRow {
  members: GroupMember[]
}

/** A row of GET /api/v1/admin/groups/<name>/privileges (GroupPrivilegeOut). */
export interface GroupBinding {
  cluster: string
  namespace: string | null
  template: string | null
  created_at: string
}

/** POST /api/v1/admin/groups/sync result. */
export interface GroupSyncResult {
  created_members: number
}
