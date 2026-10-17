import React, { useState } from 'react'
import {
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CCol,
  CForm,
  CFormInput,
  CFormLabel,
  CFormTextarea,
  CRow,
  CTable,
} from '@coreui/react'
import { useClusterStore } from '../../store/cluster'
import { useCluster, type ClusterItem } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'
import type { ClusterIn } from '../../lib/types'

/**
 * Bound-cluster registry: table of the caller's clusters (R3) + a register
 * form posting to POST /api/v1/clusters (name, api_server, kubeconfig,
 * context). Clicking a cluster selects it in the store.
 */
const ClustersView = () => {
  const { clusters, clustersLoading } = useCluster()
  const setSelectedCluster = useClusterStore((s) => s.setSelectedCluster)

  const [name, setName] = useState('')
  const [apiServer, setApiServer] = useState('')
  const [kubeconfig, setKubeconfig] = useState('')
  const [context, setContext] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [formOk, setFormOk] = useState(false)

  const openCluster = (c: ClusterItem) => {
    setSelectedCluster({ id: c.id, name: c.name })
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setFormError(null)
    setFormOk(false)
    const payload: ClusterIn = {
      name,
      api_server: apiServer,
      kubeconfig,
      context,
    }
    const r = await apiFetch('/api/v1/clusters', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    setBusy(false)
    if (r.error) {
      setFormError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setName('')
    setApiServer('')
    setKubeconfig('')
    setContext('')
    setFormOk(true)
  }

  return (
    <CRow>
      <CCol xs={12} lg={6}>
        <CCard>
          <CCardHeader>
            <CCardTitle>Bound clusters</CCardTitle>
          </CCardHeader>
          <CCardBody>
            {clustersLoading ? (
              <div>Loading clusters…</div>
            ) : clusters.length === 0 ? (
              <div>No clusters bound yet.</div>
            ) : (
              <CTable striped hover>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>API server</th>
                    <th>Context</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {clusters.map((c) => (
                    <tr
                      key={c.id}
                      style={{ cursor: 'pointer' }}
                      onClick={() => openCluster(c)}
                    >
                      <td>{c.name}</td>
                      <td>{c.api_server ?? ''}</td>
                      <td>{c.context ?? ''}</td>
                      <td>{c.status ?? 'unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            )}
          </CCardBody>
        </CCard>
      </CCol>
      <CCol xs={12} lg={6}>
        <CCard>
          <CCardHeader>
            <CCardTitle>Register cluster</CCardTitle>
          </CCardHeader>
          <CCardBody>
            <CForm onSubmit={submit} className="mb-3">
              <div className="mb-3">
                <CFormLabel htmlFor="cluster-name">Name</CFormLabel>
                <CFormInput
                  id="cluster-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="cluster-api-server">API server</CFormLabel>
                <CFormInput
                  id="cluster-api-server"
                  value={apiServer}
                  onChange={(e) => setApiServer(e.target.value)}
                  placeholder="https://api.example:6443"
                  required
                />
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="cluster-kubeconfig">Kubeconfig</CFormLabel>
                <CFormTextarea
                  id="cluster-kubeconfig"
                  rows={6}
                  value={kubeconfig}
                  onChange={(e) => setKubeconfig(e.target.value)}
                  placeholder={'apiVersion: v1\nkind: Config\n...'}
                  required
                />
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="cluster-context">Context</CFormLabel>
                <CFormInput
                  id="cluster-context"
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                  required
                />
              </div>
              {formError && <div className="text-danger mb-3">{formError}</div>}
              {formOk && <div className="text-success mb-3">Cluster registered.</div>}
              <CButton type="submit" disabled={busy}>
                {busy ? 'Registering…' : 'Register'}
              </CButton>
            </CForm>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  )
}

export default ClustersView
