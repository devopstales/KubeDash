import React, { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
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
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { MyAccessBinding, RBACTemplate } from '../../lib/types'
import { useCluster } from '../../hooks/useCluster'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'

type NamespaceRow = { template: string; namespaces: string }

/**
 * 4.1 privilege editor (`privilege-edit.html.j2`) for one user.
 * The cluster is the header selection. A cluster-scoped template has no
 * namespace. Each namespaced row takes comma-separated namespace names
 * (there is no namespace-list API yet) and Save calls bind once per name.
 * "all Namespaces" stays disabled until that list exists.
 */
const PrivilegesView = () => {
  const params = useParams()
  const user = decodeURIComponent(params.sub ?? '')
  const { me } = useCluster()
  const selected = useClusterStore((s) => s.selectedCluster)

  const templatesQuery = useQuery<RBACTemplate[]>({
    queryKey: ['admin', 'templates'],
    queryFn: async () => {
      const r = await apiFetch<RBACTemplate[]>('/api/v1/admin/permissions/templates')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const bindingsQuery = useQuery<MyAccessBinding[]>({
    queryKey: ['permissions', 'my-access'],
    queryFn: async () => {
      const r = await apiFetch<MyAccessBinding[]>('/api/v1/permissions/my-access')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
    enabled: me?.sub === user,
  })

  const templates = templatesQuery.data ?? []
  const clustered = templates.filter((t) => t.scope === 'cluster')
  const namespaced = templates.filter((t) => t.scope === 'namespace')
  const bindings = (bindingsQuery.data ?? []).filter((b) => !selected || b.cluster === selected.name)

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
          setBusy(false)
          return
        }
        for (const namespace of names) await bind(row.template, namespace)
      }
      bindingsQuery.refetch()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bind failed')
    } finally {
      setBusy(false)
    }
  }

  const unbind = async (b: MyAccessBinding) => {
    const r = await apiFetch('/api/v1/admin/permissions/bind', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, cluster: b.cluster, namespace: b.namespace }),
    })
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    bindingsQuery.refetch()
  }

  return (
    <CCard>
      <CCardHeader>
        <CCardTitle>Privileges — {user}</CCardTitle>
      </CCardHeader>
      <CCardBody>
        <div className="mb-3">
          <Link to="/admin/permissions">Back to User List</Link>
          {' · '}
          <strong>Cluster:</strong> {selected?.name ?? 'none selected'}
        </div>

        {me?.sub !== user ? (
          <div className="mb-3">
            Bindings for other users are not listed (the API returns only the caller&apos;s access).
            You can still bind a template below.
          </div>
        ) : bindingsQuery.isLoading ? (
          <div>Loading bindings…</div>
        ) : bindingsQuery.error ? (
          <div className="text-danger">
            {bindingsQuery.error instanceof Error ? bindingsQuery.error.message : 'Failed to load bindings'}
          </div>
        ) : bindings.length === 0 ? (
          <div className="mb-3">No bindings on this cluster.</div>
        ) : (
          <KubeDataTable data={bindings}>
            <Column title="Cluster" data="cluster" />
            <Column title="Namespace" data="namespace">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Template" data="template">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Action" data={null}>
              {(_data: unknown, _type: string, row: MyAccessBinding) => (
                <CButton size="sm" color="danger" onClick={() => unbind(row)}>
                  Unbind
                </CButton>
              )}
            </Column>
          </KubeDataTable>
        )}

        <CForm onSubmit={save} className="mt-4">
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

export default PrivilegesView
