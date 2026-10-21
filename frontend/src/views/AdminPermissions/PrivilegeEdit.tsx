import React, { useState } from 'react'
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CForm,
  CFormInput,
  CFormLabel,
  CFormSelect,
} from '@coreui/react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { RBACTemplate } from '../../lib/types'
import { useCluster } from '../../hooks/useCluster'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

type NamespaceRow = { template: string; namespaces: string }

/**
 * 4.1 privilege editor (`privilege-edit.html.j2`) at `/user/privilege/edit`.
 * `?user=` selects someone else; with no query the page is the caller.
 * The cluster is the header selection. A cluster-scoped template has no
 * namespace. Each namespaced row takes comma-separated namespace names
 * (there is no namespace-list API yet) and Save calls bind once per name.
 * "all Namespaces" stays disabled until that list exists.
 */
const PrivilegeEditView = () => {
  const [params] = useSearchParams()
  const { search } = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { me } = useCluster()
  const user = params.get('user') ?? me?.sub ?? ''
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
    const r = await apiFetch('/api/v1/admin/permissions/bind', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user,
        cluster: selected?.name,
        template,
        ...(namespace ? { namespace } : {}),
      }),
    })
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
      queryClient.invalidateQueries({ queryKey: ['permissions', 'my-access'] })
      navigate(`/user/privilege${search}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bind failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <CCard>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/user/list">Users</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to={`/user/privilege${search}`}>Privileges</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>Edit</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader>
        <CCardTitle>Edit privileges — {user}</CCardTitle>
      </CCardHeader>
      <CCardBody>
        <div className="mb-3">
          <strong>Cluster:</strong> {selected?.name ?? 'none selected'}
        </div>

        <CForm onSubmit={save}>
          <div className="mb-2 text-uppercase fw-bold">access to namespaced resources</div>
          {rows.map((row, i) => (
            <div key={i} className="d-flex flex-wrap gap-3 mb-3">
              <div>
                <CFormLabel htmlFor={`ns-template-${i}`}>Template</CFormLabel>
                <CFormSelect
                  id={`ns-template-${i}`}
                  value={row.template}
                  onChange={(e) =>
                    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, template: e.target.value } : r)))
                  }
                >
                  <option value="">None</option>
                  {namespaced.map((t) => (
                    <option key={t.name} value={t.name}>
                      {t.name}
                    </option>
                  ))}
                </CFormSelect>
              </div>
              <div>
                <CFormLabel htmlFor={`ns-namespaces-${i}`}>Namespaces</CFormLabel>
                <CFormInput
                  id={`ns-namespaces-${i}`}
                  value={row.namespaces}
                  placeholder="team-a, team-b"
                  onChange={(e) =>
                    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, namespaces: e.target.value } : r)))
                  }
                />
              </div>
              <div className="form-check align-self-end">
                <input className="form-check-input" id={`all-ns-${i}`} type="checkbox" disabled />
                <label className="form-check-label" htmlFor={`all-ns-${i}`}>
                  all Namespaces
                </label>
              </div>
            </div>
          ))}
          <CButton
            type="button"
            color="secondary"
            className="mb-3"
            onClick={() => setRows((rs) => [...rs, { template: '', namespaces: '' }])}
          >
            add
          </CButton>

          <div className="mb-2 text-uppercase fw-bold">access to cluster resources</div>
          <div className="mb-3">
            <CFormLabel htmlFor="cluster-template">Cluster template</CFormLabel>
            <CFormSelect
              id="cluster-template"
              value={clusterTemplate}
              onChange={(e) => setClusterTemplate(e.target.value)}
            >
              <option value="">None</option>
              {clustered.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.name}
                </option>
              ))}
            </CFormSelect>
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

export default PrivilegeEditView
