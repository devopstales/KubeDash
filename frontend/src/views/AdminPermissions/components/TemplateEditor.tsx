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
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../../lib/api'
import type { RBACTemplate, RoleRule } from '../../../lib/types'

interface TemplateEditorProps {
  /** Existing template names — the editor's list section is seeded from
   *  this so it works standalone (in tests) and inside the view (where the
   *  parent's template query is the source of truth and the editor reads
   *  the same ['admin','templates'] cache key). */
  existingNames: string[]
  /** Called after a successful create so the parent's list refetches. */
  onCreated: () => void
}

const EMPTY_RULE = (): RoleRule => ({ api_groups: [''], resources: [''], verbs: [''] })

/**
 * Template list + rule editor + Role/ClusterRole YAML preview for
 * /api/v1/admin/permissions/templates. Create POSTs the new template;
 * Delete sends DELETE .../templates/<name> (built-in rows are disabled —
 * the backend 409s them). The YAML preview is a client-side render of the
 * current rule rows in a <pre> — it updates as the rows change and the
 * scope selector switches the kind (Role vs ClusterRole).
 */
const TemplateEditor: React.FC<TemplateEditorProps> = ({ existingNames, onCreated }) => {
  // ponytail: the editor fetches the template list itself (same queryKey as
  // the view's templates query, so TanStack dedupes in the real app); the
  // existingNames seed keeps the list section working standalone in tests.
  const templatesQuery = useQuery<RBACTemplate[]>({
    queryKey: ['admin', 'templates'],
    queryFn: async () => {
      const r = await apiFetch<RBACTemplate[]>('/api/v1/admin/permissions/templates')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scope, setScope] = useState<'namespace' | 'cluster'>('namespace')
  const [rules, setRules] = useState<RoleRule[]>([EMPTY_RULE()])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [standaloneRows] = useState<RBACTemplate[]>(() =>
    existingNames.map((n, i) => ({
      id: -(i + 1),
      name: n,
      description: '',
      scope: 'namespace',
      rules: [],
      builtin: true,
      created_by: null,
      created_at: null,
    })),
  )
  const templates: RBACTemplate[] = templatesQuery.data ?? standaloneRows

  const setRuleCell = (i: number, field: keyof RoleRule, value: string) => {
    setRules((rs) =>
      rs.map((r, j) => (j === i ? { ...r, [field]: value.split(',').map((s) => s.trim()).filter(Boolean) } : r)),
    )
  }
  const addRule = () => setRules((rs) => [...rs, EMPTY_RULE()])
  const removeRule = (i: number) => setRules((rs) => rs.filter((_, j) => j !== i))

  // Client-side Role/ClusterRole YAML render of the current rule rows.
  const yaml = renderRoleYaml(name || 'template', scope, rules)

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const r = await apiFetch('/api/v1/admin/permissions/templates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, scope, rules }),
    })
    setBusy(false)
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setName('')
    setDescription('')
    setRules([EMPTY_RULE()])
    onCreated()
  }

  const del = async (t: RBACTemplate) => {
    setBusy(true)
    setError(null)
    const r = await apiFetch(`/api/v1/admin/permissions/templates/${encodeURIComponent(t.name)}`, {
      method: 'DELETE',
    })
    setBusy(false)
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    templatesQuery.refetch()
  }

  return (
    <div>
      {templatesQuery.isLoading ? (
        <div>Loading templates…</div>
      ) : templatesQuery.error ? (
        <div className="text-danger">
          {templatesQuery.error instanceof Error ? templatesQuery.error.message : 'Failed to load templates'}
        </div>
      ) : (
        <CTable striped hover className="mb-3">
          <thead>
            <tr>
              <th>Name</th>
              <th>Scope</th>
              <th>Rules</th>
              <th>Description</th>
              <th>Built-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {templates.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td>{t.scope}</td>
                <td>{t.rules.length}</td>
                <td>{t.description || '\u2014'}</td>
                <td>{t.builtin ? 'builtin' : ''}</td>
                <td>
                  <CButton
                    size="sm"
                    color="danger"
                    disabled={t.builtin || busy}
                    onClick={() => del(t)}
                  >
                    Delete
                  </CButton>
                </td>
              </tr>
            ))}
          </tbody>
        </CTable>
      )}

      <CCard>
        <CCardHeader>
          <CCardTitle>Create template</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <CForm onSubmit={create} className="mb-3">
            <div className="mb-3">
              <CFormLabel htmlFor="tpl-name">Name</CFormLabel>
              <CFormInput
                id="tpl-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div className="mb-3">
              <CFormLabel htmlFor="tpl-description">Description</CFormLabel>
              <CFormInput
                id="tpl-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div className="mb-3">
              <CFormLabel htmlFor="tpl-scope">Scope</CFormLabel>
              <CFormSelect
                id="tpl-scope"
                value={scope}
                onChange={(e) => setScope(e.target.value as 'namespace' | 'cluster')}
              >
                <option value="namespace">namespace</option>
                <option value="cluster">cluster</option>
              </CFormSelect>
            </div>

            {rules.map((r, i) => (
              <div key={i} className="mb-3 d-flex gap-2">
                <div className="flex-fill">
                  <CFormLabel>API groups</CFormLabel>
                  <CFormInput
                    value={r.api_groups.join(',')}
                    onChange={(e) => setRuleCell(i, 'api_groups', e.target.value)}
                    placeholder="*, apps"
                  />
                </div>
                <div className="flex-fill">
                  <CFormLabel>Resources</CFormLabel>
                  <CFormInput
                    value={r.resources.join(',')}
                    onChange={(e) => setRuleCell(i, 'resources', e.target.value)}
                    placeholder="pods, pods/log"
                  />
                </div>
                <div className="flex-fill">
                  <CFormLabel>Verbs</CFormLabel>
                  <CFormInput
                    value={r.verbs.join(',')}
                    onChange={(e) => setRuleCell(i, 'verbs', e.target.value)}
                    placeholder="get,list,watch"
                  />
                </div>
                <CButton
                  type="button"
                  color="secondary"
                  onClick={() => removeRule(i)}
                  disabled={rules.length === 1}
                >
                  Remove
                </CButton>
              </div>
            ))}
            <CButton type="button" color="secondary" onClick={addRule} className="mb-3">
              Add rule
            </CButton>

            <div className="mb-3">
              <CFormLabel>Role YAML preview</CFormLabel>
              <pre style={{ background: 'var(--c-tertiary-bg)', padding: '0.75rem' }}>{yaml}</pre>
            </div>

            {error && <div className="text-danger mb-3">{error}</div>}

            <CButton type="submit" color="primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create'}
            </CButton>
          </CForm>
        </CCardBody>
      </CCard>
    </div>
  )
}

/** Client-side Role/ClusterRole YAML render of the rule rows. */
function renderRoleYaml(name: string, scope: 'namespace' | 'cluster', rules: RoleRule[]): string {
  const kind = scope === 'cluster' ? 'ClusterRole' : 'Role'
  const lines: string[] = ['apiVersion: rbac.authorization.k8s.io/v1', `kind: ${kind}`, 'metadata:', `  name: ${name}`, 'rules:']
  if (rules.length === 0) {
    lines.push('  []')
    return lines.join('\n')
  }
  for (const r of rules) {
    lines.push(`  - apiGroups: [${r.api_groups.map((s) => (s === '' ? "''" : s)).join(', ')}]`)
    lines.push(`    resources: [${r.resources.join(', ')}]`)
    lines.push(`    verbs: [${r.verbs.join(', ')}]`)
  }
  return lines.join('\n')
}

export default TemplateEditor
