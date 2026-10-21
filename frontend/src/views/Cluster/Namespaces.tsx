import React, { useState } from 'react'
import {
  CBadge,
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
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CModalTitle,
} from '@coreui/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { useCluster } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'
import type { K8sNamespace, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

const PROTECTED = new Set(['default', 'kube-system', 'kube-public', 'kube-node-lease'])
const NAME_RE = /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/
const REPOSITORY = 'kubedash.io/repository'
const PIPELINE = 'kubedash.io/pipeline'

type NamespaceRow = {
  status: string
  name: string
  repository: string | null
  pipeline: string | null
  created: string
}

const safeHttpUrl = (value: string | undefined): string | null => {
  if (!value) return null
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
  } catch {
    return null
  }
}

const toRow = (namespace: K8sNamespace): NamespaceRow => {
  const annotations = namespace.metadata?.annotations ?? {}
  return {
    status: namespace.status?.phase ?? 'Unknown',
    name: namespace.metadata?.name ?? '',
    repository: safeHttpUrl(annotations[REPOSITORY]),
    pipeline: safeHttpUrl(annotations[PIPELINE]),
    created: namespace.metadata?.creation_timestamp ?? '',
  }
}

const NamespacesView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  const setSelectedNamespace = useClusterStore((s) => s.setSelectedNamespace)
  const { role } = useCluster()
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [name, setName] = useState('')

  const query = useQuery<K8sNamespace[]>({
    queryKey: ['namespaces', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sNamespace>>(
        `/api/v1/clusters/${cluster!.id}/resources/namespaces`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['namespaces', cluster!.id] })

  const createMutation = useMutation({
    mutationFn: async (namespace: string) => {
      const r = await apiFetch(`/api/v1/clusters/${cluster!.id}/resources/namespaces`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: namespace }),
      })
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
    },
    onSuccess: async () => {
      setModalOpen(false)
      setName('')
      await refresh()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (namespace: string) => {
      const r = await apiFetch(
        `/api/v1/clusters/${cluster!.id}/resources/namespaces/${encodeURIComponent(namespace)}`,
        { method: 'DELETE' },
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return namespace
    },
    onSuccess: async (deleted) => {
      if (selectedNamespace === deleted) setSelectedNamespace(null)
      await refresh()
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (NAME_RE.test(name)) createMutation.mutate(name)
  }

  const remove = (namespace: string) => {
    if (window.confirm(`Delete namespace ${namespace}?`)) {
      deleteMutation.mutate(namespace)
    }
  }

  const rows = (query.data ?? []).map(toRow)
  const externalLink = (label: string) => (url: string | null) =>
    url ? (
      <a href={url} target="_blank" rel="noreferrer">
        {label}
      </a>
    ) : (
      '\u2014'
    )

  return (
    <>
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Cluster</CBreadcrumbItem>
            <CBreadcrumbItem active>Namespaces</CBreadcrumbItem>
          </CBreadcrumb>
          {role === 'admin' ? (
            <CButton color="primary" onClick={() => setModalOpen(true)}>
              Add Namespace
            </CButton>
          ) : null}
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Namespace List</CCardTitle>
        </CCardHeader>
        <CCardBody>
          {!cluster ? (
            <div>No cluster selected.</div>
          ) : query.isLoading ? (
            <div>Loading namespaces...</div>
          ) : query.error ? (
            <div className="text-danger">Error loading namespaces: {query.error.message}</div>
          ) : rows.length === 0 ? (
            <div className="text-center text-muted">No namespaces found</div>
          ) : (
            <KubeDataTable data={rows}>
              <Column title="Status" data="status">
                {(status: string) => (
                  <CBadge color={status === 'Active' ? 'success' : 'secondary'}>{status}</CBadge>
                )}
              </Column>
              <Column title="Namespace" data="name" />
              <Column title="Repository" data="repository">
                {externalLink('Repository')}
              </Column>
              <Column title="Pipeline" data="pipeline">
                {externalLink('Pipeline')}
              </Column>
              <Column title="Created" data="created" />
              <Column title="Action" data={null}>
                {(row: NamespaceRow) =>
                  role === 'admin' && !PROTECTED.has(row.name) ? (
                    <CButton
                      color="danger"
                      size="sm"
                      aria-label={`Delete ${row.name}`}
                      onClick={() => remove(row.name)}
                    >
                      Delete
                    </CButton>
                  ) : null
                }
              </Column>
            </KubeDataTable>
          )}
          {createMutation.error ? (
            <div className="text-danger mt-3">{createMutation.error.message}</div>
          ) : null}
          {deleteMutation.error ? (
            <div className="text-danger mt-3">{deleteMutation.error.message}</div>
          ) : null}
        </CCardBody>
      </CCard>

      <CModal visible={modalOpen} onClose={() => setModalOpen(false)}>
        <CForm onSubmit={submit}>
          <CModalHeader>
            <CModalTitle>New Namespace</CModalTitle>
          </CModalHeader>
          <CModalBody>
            <CFormLabel htmlFor="namespace-name">Namespace</CFormLabel>
            <CFormInput
              id="namespace-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              invalid={name.length > 0 && !NAME_RE.test(name)}
            />
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" onClick={() => setModalOpen(false)}>
              Close
            </CButton>
            <CButton
              color="primary"
              type="submit"
              disabled={!NAME_RE.test(name) || createMutation.isPending}
            >
              Add Namespace
            </CButton>
          </CModalFooter>
        </CForm>
      </CModal>
    </>
  )
}

export default NamespacesView
