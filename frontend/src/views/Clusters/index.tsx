import React, { useState } from 'react'
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
  CFormTextarea,
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CModalTitle,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilPencil, cilPlus, cilTrash } from '@coreui/icons'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { useCluster, type ClusterItem } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'
import type { ClusterIn, ClusterUpdateIn } from '../../lib/types'

/**
 * Cluster registry — 4.1 `settings/cluster-config.html.j2` parity:
 * the "Kubernetes Server List" card with Context / URL / Action columns, an
 * admin-only add action in the header, and per-row Edit + Delete.
 *
 * The registry API is kubeconfig-based (ADR-0002): the create body carries
 * name / api_server / context / kubeconfig; an edit leaves kubeconfig empty
 * to keep the stored encrypted document (PUT /api/v1/clusters/<id>).
 */

type ClusterForm = {
  name: string
  apiServer: string
  context: string
  kubeconfig: string
}

const EMPTY_FORM: ClusterForm = { name: '', apiServer: '', context: '', kubeconfig: '' }

const emDash = (value: string | null | undefined) => (value ? value : '\u2014')

// ADR-0021: the synthetic local cluster is not a registry row — the backend
// refuses to edit/delete id 0, so the row renders without actions.
const LOCAL_CLUSTER_ID = 0

const ClustersView = () => {
  const { clusters, clustersLoading, clustersError, role } = useCluster()
  const queryClient = useQueryClient()
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<ClusterItem | null>(null)
  const [form, setForm] = useState<ClusterForm>(EMPTY_FORM)

  const isAdmin = role === 'admin'
  const isEditing = editing !== null
  const valid =
    form.name.trim() !== '' &&
    form.apiServer.trim() !== '' &&
    form.context.trim() !== '' &&
    (isEditing || form.kubeconfig.trim() !== '')

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['clusters'] })

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body: ClusterIn | ClusterUpdateIn = {
        name: form.name.trim(),
        api_server: form.apiServer.trim(),
        context: form.context.trim(),
      }
      if (form.kubeconfig.trim() !== '') body.kubeconfig = form.kubeconfig
      const path = isEditing ? `/api/v1/clusters/${editing!.id}` : '/api/v1/clusters'
      const r = await apiFetch(path, {
        method: isEditing ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
    },
    onSuccess: async () => {
      setModalOpen(false)
      setForm(EMPTY_FORM)
      setEditing(null)
      await refresh()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (cluster: ClusterItem) => {
      const r = await apiFetch(`/api/v1/clusters/${cluster.id}`, { method: 'DELETE' })
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
    },
    onSuccess: async () => {
      await refresh()
    },
  })

  const openAdd = () => {
    saveMutation.reset()
    setEditing(null)
    setForm(EMPTY_FORM)
    setModalOpen(true)
  }

  const openEdit = (cluster: ClusterItem) => {
    saveMutation.reset()
    setEditing(cluster)
    setForm({
      name: cluster.name,
      apiServer: cluster.api_server ?? '',
      context: cluster.context ?? '',
      kubeconfig: '',
    })
    setModalOpen(true)
  }

  const closeModal = () => setModalOpen(false)

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (valid) saveMutation.mutate()
  }

  const remove = (cluster: ClusterItem) => {
    if (window.confirm(`Delete cluster configuration "${cluster.name}"?`)) {
      deleteMutation.mutate(cluster)
    }
  }

  const setField = (field: keyof ClusterForm) => (event: React.ChangeEvent<HTMLInputElement>) =>
    setForm((current) => ({ ...current, [field]: event.target.value }))

  return (
    <>
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Settings</CBreadcrumbItem>
            <CBreadcrumbItem active>Kubernetes Cluster</CBreadcrumbItem>
          </CBreadcrumb>
          {isAdmin ? (
            <CButton
              color="link"
              className="header-toggler ms-auto"
              type="button"
              aria-label="Add Cluster"
              title="Add Cluster"
              onClick={openAdd}
            >
              <CIcon icon={cilPlus} size="lg" />
            </CButton>
          ) : null}
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Kubernetes Server List</CCardTitle>
        </CCardHeader>
        <CCardBody>
          {clustersLoading ? (
            <div>Loading cluster configurations...</div>
          ) : clustersError ? (
            <div className="text-danger">
              Error loading cluster configurations: {clustersError.message}
            </div>
          ) : clusters.length === 0 ? (
            <div className="text-center text-muted">No cluster configurations found</div>
          ) : (
            <KubeDataTable data={clusters}>
              <Column title="Context" data="context">
                {(context: string | null, _type: unknown, row: ClusterItem) => (
                  <>
                    <div>{emDash(context)}</div>
                    <div className="small text-muted">{row.name}</div>
                  </>
                )}
              </Column>
              <Column title="URL" data="api_server">
                {(apiServer: string | null | undefined) => emDash(apiServer)}
              </Column>
              <Column title="Action" data={null}>
                {(row: ClusterItem) =>
                  isAdmin && row.id !== LOCAL_CLUSTER_ID ? (
                    <div className="d-flex flex-row gap-1">
                      <CButton
                        color="success"
                        size="sm"
                        type="button"
                        aria-label={`Edit ${row.name}`}
                        title="Edit"
                        onClick={() => openEdit(row)}
                      >
                        <CIcon icon={cilPencil} />
                      </CButton>
                      <CButton
                        color="danger"
                        size="sm"
                        type="button"
                        aria-label={`Delete ${row.name}`}
                        title="Delete"
                        onClick={() => remove(row)}
                      >
                        <CIcon icon={cilTrash} />
                      </CButton>
                    </div>
                  ) : null
                }
              </Column>
            </KubeDataTable>
          )}
          {saveMutation.error ? (
            <div className="text-danger mt-3">{saveMutation.error.message}</div>
          ) : null}
          {deleteMutation.error ? (
            <div className="text-danger mt-3">{deleteMutation.error.message}</div>
          ) : null}
        </CCardBody>
      </CCard>

      <CModal
        visible={modalOpen}
        alignment="center"
        onClose={closeModal}
        aria-labelledby="cluster-modal-title"
      >
        <CForm onSubmit={submit}>
          <CModalHeader>
            <CModalTitle id="cluster-modal-title">
              {isEditing ? 'Update Cluster' : 'Create Cluster'}
            </CModalTitle>
          </CModalHeader>
          <CModalBody>
            <div className="mb-3">
              <CFormLabel htmlFor="cluster-name">Name</CFormLabel>
              <CFormInput
                id="cluster-name"
                value={form.name}
                onChange={setField('name')}
                required
              />
            </div>
            <div className="mb-3">
              <CFormLabel htmlFor="cluster-context">Kubernetes Config Context</CFormLabel>
              <CFormInput
                id="cluster-context"
                value={form.context}
                onChange={setField('context')}
                placeholder="Server Context"
                required
              />
            </div>
            <div className="mb-3">
              <CFormLabel htmlFor="cluster-api-server">Kubernetes API URL</CFormLabel>
              <CFormInput
                id="cluster-api-server"
                value={form.apiServer}
                onChange={setField('apiServer')}
                placeholder="https://api.example:6443"
                required
              />
            </div>
            <div className="mb-3">
              <CFormLabel htmlFor="cluster-kubeconfig">Kubeconfig</CFormLabel>
              <CFormTextarea
                id="cluster-kubeconfig"
                rows={6}
                value={form.kubeconfig}
                onChange={(event) =>
                  setForm((current) => ({ ...current, kubeconfig: event.target.value }))
                }
                placeholder={'apiVersion: v1\nkind: Config\n...'}
                required={!isEditing}
              />
              {isEditing ? (
                <div className="small text-muted">Leave empty to keep the stored kubeconfig.</div>
              ) : null}
            </div>
          </CModalBody>
          <CModalFooter>
            <CButton color="secondary" type="button" onClick={closeModal}>
              Close
            </CButton>
            <CButton color="primary" type="submit" disabled={!valid || saveMutation.isPending}>
              {saveMutation.isPending ? 'Saving…' : isEditing ? 'Update Cluster' : 'Add Cluster'}
            </CButton>
          </CModalFooter>
        </CForm>
      </CModal>
    </>
  )
}

export default ClustersView
