import React, { useState } from 'react'
import { CCard, CCardBody, CCardHeader, CCardTitle, CTable } from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AdminUser, GroupOut } from '../../lib/types'

/**
 * Groups (left-menu admin surface): list every distinct user group with
 * its member count (GET /api/v1/admin/groups); clicking a row shows the
 * members of that group (filtered from the /admin/users list — no extra
 * endpoint; the users query carries each user's groups claim). Reachable
 * at /groups, wrapped in ProtectedRoute + AdminRoute (role === 'admin';
 * non-admins redirect to /). API errors surface as text-danger messages.
 */
const GroupsView = () => {
  const groupsQuery = useQuery<GroupOut[]>({
    queryKey: ['admin', 'groups'],
    queryFn: async () => {
      const r = await apiFetch<GroupOut[]>('/api/v1/admin/groups')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const usersQuery = useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      const r = await apiFetch<AdminUser[]>('/api/v1/admin/users')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const [selected, setSelected] = useState<string | null>(null)

  if (groupsQuery.isLoading) {
    return <div>Loading groups…</div>
  }

  if (groupsQuery.error) {
    return (
      <div className="text-danger">
        {groupsQuery.error instanceof Error ? groupsQuery.error.message : 'Failed to load groups'}
      </div>
    )
  }

  const groups = groupsQuery.data ?? []
  const users = usersQuery.data ?? []
  const members = selected ? users.filter((u) => u.groups.includes(selected)) : []

  return (
    <div>
      {groups.length === 0 ? (
        <div>No groups.</div>
      ) : (
        <CTable striped hover>
          <thead>
            <tr>
              <th>Group</th>
              <th>Members</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr
                key={g.group}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelected(g.group === selected ? null : g.group)}
              >
                <td>{g.group}</td>
                <td>{g.member_count}</td>
              </tr>
            ))}
          </tbody>
        </CTable>
      )}

      {selected && (
        <CCard className="mt-3">
          <CCardHeader>
            <CCardTitle>Members of {selected}</CCardTitle>
          </CCardHeader>
          <CCardBody>
            {usersQuery.isLoading ? (
              <div>Loading members…</div>
            ) : usersQuery.error ? (
              <div className="text-danger">
                {usersQuery.error instanceof Error
                  ? usersQuery.error.message
                  : 'Failed to load members'}
              </div>
            ) : members.length === 0 ? (
              <div>No members (count drifts only between the two queries).</div>
            ) : (
              <CTable striped hover>
                <thead>
                  <tr>
                    <th>Display name</th>
                    <th>Sub</th>
                    <th>Email</th>
                    <th>Role</th>
                  </tr>
                </thead>
                <tbody>
                  {members.map((u) => (
                    <tr key={u.id}>
                      <td>{u.display_name ?? '—'}</td>
                      <td>{u.sub}</td>
                      <td>{u.email ?? '—'}</td>
                      <td>{u.role}</td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            )}
          </CCardBody>
        </CCard>
      )}
    </div>
  )
}

export default GroupsView
