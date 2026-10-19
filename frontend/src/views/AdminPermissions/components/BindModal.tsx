import React, { useState } from 'react'
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
import { apiFetch } from '../../../lib/api'
import type { RBACTemplate } from '../../../lib/types'
import type { ClusterItem } from '../../../hooks/useCluster'

interface BindModalProps {
  /** The user sub to bind. */
  user: string
  clusters: ClusterItem[]
  templates: RBACTemplate[]
  onClose: () => void
  onSuccess: () => void
}

/**
 * Bind a template to a user (POST /api/v1/admin/permissions/bind). Rendered
 * INLINE (not a CModal — a portal overlay is invisible to jsdom's default
 * queries, and the inline card carries the same fields). The namespace
 * field is HIDDEN when the selected template is cluster-scoped; on submit
 * `namespace: undefined` is sent (the backend's BindIn treats it as None).
 * API errors surface as a text-danger message; no unhandled rejections.
 */
const BindModal: React.FC<BindModalProps> = ({ user, clusters, templates, onClose, onSuccess }) => {
  const [cluster, setCluster] = useState('')
  const [namespace, setNamespace] = useState('')
  const [template, setTemplate] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selectedTemplate = templates.find((t) => t.name === template) ?? null
  const clusterScoped = selectedTemplate?.scope === 'cluster'

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const body: { user: string; cluster: string; template: string; namespace?: string } = {
      user,
      cluster,
      template,
    }
    if (!clusterScoped) body.namespace = namespace || undefined
    const r = await apiFetch('/api/v1/admin/permissions/bind', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    setBusy(false)
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setCluster('')
    setNamespace('')
    setTemplate('')
    onSuccess()
  }

  return (
    <CCard>
      <CCardHeader>
        <CCardTitle>Bind template — {user}</CCardTitle>
      </CCardHeader>
      <CCardBody>
        <CForm onSubmit={submit} className="mb-3">
          <div className="mb-3">
            <CFormLabel htmlFor="bind-cluster">Cluster</CFormLabel>
            <CFormSelect
              id="bind-cluster"
              value={cluster}
              onChange={(e) => setCluster(e.target.value)}
              required
            >
              <option value="">Select a cluster…</option>
              {clusters.map((c) => (
                <option key={c.id} value={c.name}>
                  {c.name}
                </option>
              ))}
            </CFormSelect>
          </div>

          {!clusterScoped && (
            <div className="mb-3">
              <CFormLabel htmlFor="bind-namespace">Namespace</CFormLabel>
              <CFormInput
                id="bind-namespace"
                value={namespace}
                onChange={(e) => setNamespace(e.target.value)}
                placeholder="team-a"
              />
            </div>
          )}

          <div className="mb-3">
            <CFormLabel htmlFor="bind-template">Template</CFormLabel>
            <CFormSelect
              id="bind-template"
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
              required
            >
              <option value="">Select a template…</option>
              {templates.map((t) => (
                <option key={t.id} value={t.name}>
                  {t.name} ({t.scope}
                  {t.builtin ? ', builtin' : ''})
                </option>
              ))}
            </CFormSelect>
          </div>

          {error && <div className="text-danger mb-3">{error}</div>}

          <div className="d-flex gap-2">
            <CButton type="submit" color="primary" disabled={busy}>
              {busy ? 'Binding…' : 'Submit'}
            </CButton>
            <CButton type="button" color="secondary" onClick={onClose}>
              Cancel
            </CButton>
          </div>
        </CForm>
      </CCardBody>
    </CCard>
  )
}

export default BindModal
