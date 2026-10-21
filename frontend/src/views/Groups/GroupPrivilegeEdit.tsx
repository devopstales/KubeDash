import React, { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CForm,
  CFormInput,
  CFormLabel,
  CFormSelect,
} from '@coreui/react'
import { useNavigate, useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { RBACTemplate } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

type NamespaceRow = { template: string; namespaces: string }

/**
 * 4.1 group privilege editor (`users/group-privilege-edit.html.j2`) at
 * `/user/group/privilege/edit?group=<name>`. The cluster is the header
 * selection. A cluster-scoped template has no namespace; each namespaced
 * row takes comma-separated namespace names (there is no namespace-list
 * API yet — mirrors the user privilege editor). Save binds the template to
 * the GROUP (a k8s ``Group`` subject), so every member inherits the access.
 */
const GroupPrivilegeEditView = () => {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const group = params.get('group') ?? ''
  const selected = useClusterStore((s) => s.selectedCluster)

  const templatesQuery = useQuery<RBACTemplate[]>({
    queryKey: ['admin', 'templates'],
    queryFn: async () => {
      const r = await apiFetch<RBACTemplate[]>('/api/v1/admin/permissions/templates')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const templates = templatesQuery.data ?? []
  const clustered = templates.filter((t) => t.scope === 'cluster')
  const namespaced = templates.filter((t) => t.scope === 'namespace')

  const [clusterTemplate, setClusterTemplate] = useState('')
  const [rows, setRows] = useState<NamespaceRow[]>([{ template: '', namespaces: '' }])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const bind = async (template: string, namespace?: string) => {
    const r = await apiFetch(
      `/api/v1/admin/groups/${encodeURIComponent(group)}/privileges`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cluster: selected?.name,
          template,
          ...(namespace ? { namespace } : {}),
        }),
      }
    )
    if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
  }

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selected) {
      setError('Select a cluster in the header')
      return
    }
    setBusy(true)
    setError(null)
    try {
      if (clusterTemplate) await bind(clusterTemplate)
      for (const row of rows) {
        if (!row.template) continue
        const names = row.namespaces.split(',').map((s) => s.trim()).filter(Boolean)
        if (names.length === 0) {
          setError('A namespaced template needs at least one namespace')
          return
        }
        for (const namespace of names) await bind(row.template, namespace)
      }
      navigate(`/user/group/privilege?group=${encodeURIComponent(group)}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bind failed')
      setBusy(false)
    }
  }

  const updateRow = (index: number, patch: Partial<NamespaceRow>) => {
    setRows((prev) => prev.map((row, i) => (i === index ? { ...row, ...patch } : row)))
  }

  return (
    <CCard>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/user/group">Groups</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{group ? `Edit privileges — ${group}` : 'Edit privileges'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <h6 className="m-0 fw-bold text-primary">Group: {group || '…'}</h6>
      </CCardHeader>
      <CCardBody>
        <CForm onSubmit={save}>
          <div className="bg-light border rounded py-3 px-4 mb-3">
            <h6 className="modal-title mt-2 mb-2">Privileges</h6>
            <div className="d-flex flex-row gap-3">
              <div className="form-group col-md-4">
                <CFormLabel htmlFor="group-cluster-template">TEMPLATE</CFormLabel>
                <CFormSelect
                  id="group-cluster-template"
                  aria-label="Select cluster template"
                  value={clusterTemplate}
                  onChange={(e) => setClusterTemplate(e.target.value)}
                >
                  <option value="">None</option>
                  {clustered.map((t) => (
                    <option key={t.id} value={t.name}>
                      {t.name}
                    </option>
                  ))}
                </CFormSelect>
                <div className="small text-muted mt-1">
                  Cluster-scoped access for every member of this group.
                </div>
              </div>
            </div>
            <hr id="hiddenHR" hidden />
            {rows.map((row, index) => (
              <div className="d-flex flex-row gap-3 mt-2" key={index}>
                <div className="form-group col-md-4">
                  <CFormLabel htmlFor={`group-namespaced-role-${index + 1}`}>TEMPLATE</CFormLabel>
                  <CFormSelect
                    id={`group-namespaced-role-${index + 1}`}
                    aria-label="Select namespaced template"
                    value={row.template}
                    onChange={(e) => updateRow(index, { template: e.target.value })}
                  >
                    <option value="">None</option>
                    {namespaced.map((t) => (
                      <option key={t.id} value={t.name}>
                        {t.name}
                      </option>
                    ))}
                  </CFormSelect>
                </div>
                <div className="form-group col-md-4">
                  <CFormLabel htmlFor={`group-namespaces-${index + 1}`}>NAMESPACES</CFormLabel>
                  <CFormInput
                    id={`group-namespaces-${index + 1}`}
                    value={row.namespaces}
                    placeholder="comma-separated namespace names"
                    onChange={(e) => updateRow(index, { namespaces: e.target.value })}
                  />
                </div>
              </div>
            ))}
            <hr />
            <CButton
              color="secondary"
              type="button"
              onClick={() => setRows((prev) => [...prev, { template: '', namespaces: '' }])}
            >
              add
            </CButton>
          </div>
          {error && <div className="text-danger mb-3">{error}</div>}
          <CButton type="submit" color="primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save'}
          </CButton>
        </CForm>
      </CCardBody>
    </CCard>
  )
}

export default GroupPrivilegeEditView
