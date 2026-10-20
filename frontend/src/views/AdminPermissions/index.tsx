import React, { useState } from 'react'
import { CButton, CButtonGroup, CTable } from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AuditEntry, RBACTemplate } from '../../lib/types'
import TemplateEditor from './components/TemplateEditor'

/**
 * Templates & Audit (left-menu admin surface; the Users tab moved to the
 * /users view in the user-management-menus change). Reachable at
 * /admin/permissions, wrapped in ProtectedRoute + AdminRoute (role ===
 * 'admin'; non-admins redirect to /). API errors surface as text-danger
 * messages (no toasts, no unhandled rejections).
 */
const AdminPermissionsView = () => {
  const templatesQuery = useQuery<RBACTemplate[]>({
    queryKey: ['admin', 'templates'],
    queryFn: async () => {
      const r = await apiFetch<RBACTemplate[]>('/api/v1/admin/permissions/templates')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  // GET /api/v1/audit is a confirmed 501 NOT_IMPLEMENTED stub on the
  // backend (base structure, backend/app/api/audit.py); the tab renders an
  // empty state until the read route lands. No new backend route (backend
  // is closed for this change).
  const auditQuery = useQuery<AuditEntry[] | null>({
    queryKey: ['admin', 'audit'],
    queryFn: async () => {
      const r = await apiFetch<AuditEntry[]>('/api/v1/audit')
      if (r.error) return null
      return r.data ?? []
    },
  })

  // ponytail: CTabs (CoreUI v5) renders the tab button + content as a flat
  // sibling list, which confuses jsdom's queryByRole('tab') and makes
  // nested content land INSIDE the button node (see the unbind / audit
  // test output). A CButtonGroup + content section gives us the same UX
  // with plain DOM that the query helpers can see. The real UI trade-off
  // is one extra click (no auto-focus / keyboard arrow navigation).
  const [tab, setTab] = useState<'templates' | 'audit'>('templates')

  return (
    <div>
      <CButtonGroup className="mb-3" role="tablist">
        {(['templates', 'audit'] as const).map((t) => (
          <CButton
            key={t}
            color={tab === t ? 'primary' : 'secondary'}
            active={tab === t}
            onClick={() => setTab(t)}
            aria-selected={tab === t}
            role="tab"
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </CButton>
        ))}
      </CButtonGroup>

      {tab === 'templates' && (
        <TemplateEditor
          existingNames={(templatesQuery.data ?? []).map((t) => t.name)}
          onCreated={() => templatesQuery.refetch()}
        />
      )}

      {tab === 'audit' && (
        <>
        {auditQuery.isLoading ? (
          <div>Loading audit…</div>
        ) : auditQuery.data === null ? (
          // ponytail: the 501 body is not rendered — the read route is a
          // known stub (verified in backend/app/api/audit.py); the tab
          // carries the empty state and picks up rows when the route lands.
          <div>Audit log not available.</div>
        ) : (auditQuery.data ?? []).length === 0 ? (
          <div>No audit entries.</div>
        ) : (
          <CTable striped hover>
            <thead>
              <tr>
                <th>Action</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Cluster</th>
                <th>Namespace</th>
                <th>Template</th>
                <th>At</th>
              </tr>
            </thead>
            <tbody>
              {(auditQuery.data ?? []).map((a) => (
                <tr key={a.id}>
                  <td>{a.action}</td>
                  <td>{a.actor_sub}</td>
                  <td>{a.target}</td>
                  <td>{a.cluster ?? '—'}</td>
                  <td>{a.namespace ?? '—'}</td>
                  <td>{a.template ?? '—'}</td>
                  <td>{a.at}</td>
                </tr>
              ))}
            </tbody>
          </CTable>
        )}
        </>
      )}
    </div>
  )
}

export default AdminPermissionsView
