import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { K8sClusterRoleBinding, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type RoleRef = { kind: string; name: string }
type ServiceAccountSubject = { name: string; namespace: string }

type ClusterRoleBindingRow = {
  name: string
  roles: RoleRef[]
  users: string[]
  groups: string[]
  serviceAccounts: ServiceAccountSubject[]
}

const toRow = (binding: K8sClusterRoleBinding): ClusterRoleBindingRow => {
  const roleRef = binding.role_ref
  const roles = roleRef?.name ? [{ kind: roleRef.kind ?? '', name: roleRef.name }] : []
  const users: string[] = []
  const groups: string[] = []
  const serviceAccounts: ServiceAccountSubject[] = []
  for (const subject of binding.subjects ?? []) {
    const name = subject.name ?? ''
    if (subject.kind === 'User') users.push(name)
    else if (subject.kind === 'Group') groups.push(name)
    else if (subject.kind === 'ServiceAccount') {
      serviceAccounts.push({ name, namespace: subject.namespace ?? '' })
    }
  }
  return {
    name: binding.metadata?.name ?? '',
    roles,
    users,
    groups,
    serviceAccounts,
  }
}

/** 4.1 prints one value per line (`cluster-role-binding.html.j2`). */
const lines = (items: string[]) => {
  const values = items.filter((item) => item.length > 0)
  if (values.length === 0) return ' '
  return (
    <>
      {values.map((item, i) => (
        <span key={`${item}-${i}`}>
          {i > 0 ? <br /> : null}
          {item}
        </span>
      ))}
    </>
  )
}

const roleLink = (role: RoleRef) => {
  if (role.kind === 'Role') {
    return (
      <Link to={`/cluster-permission/role/data?name=${encodeURIComponent(role.name)}`}>
        {role.name}
      </Link>
    )
  }
  if (role.kind === 'ClusterRole') {
    return (
      <Link to={`/cluster-permission/cluster-role/data?name=${encodeURIComponent(role.name)}`}>
        {role.name}
      </Link>
    )
  }
  return role.name
}

/**
 * 4.1 `cluster-permission/cluster-role-binding.html.j2`: ClusterRoleBindings
 * on the header-selected cluster. A ClusterRole opens its rules, a Role opens
 * the namespaced rule list, and a ServiceAccount opens that account
 * (switching the header namespace to the account's namespace). `?crb_name=`
 * marks the row 4.1 highlights when a group privilege links here.
 */
const ClusterRoleBindingView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const setSelectedNamespace = useClusterStore((s) => s.setSelectedNamespace)
  const [params] = useSearchParams()
  const selectedName = params.get('crb_name') ?? ''

  const query = useQuery<ClusterRoleBindingRow[]>({
    queryKey: ['clusterrolebindings', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sClusterRoleBinding>>(
        `/api/v1/clusters/${cluster!.id}/resources/clusterrolebindings`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  const nameCell = (name: string) =>
    name ? (
      <span className={name === selectedName ? 'selected fw-bold' : undefined}>{name}</span>
    ) : null

  const roleCell = (roles: RoleRef[]) => {
    if (roles.length === 0) return ' '
    return (
      <>
        {roles.map((role, i) => (
          <span key={`${role.kind}-${role.name}-${i}`}>
            {i > 0 ? <br /> : null}
            {roleLink(role)}
          </span>
        ))}
      </>
    )
  }

  const serviceAccountCell = (accounts: ServiceAccountSubject[]) => {
    const items = accounts.filter((account) => account.name.length > 0)
    if (items.length === 0) return ' '
    return (
      <>
        {items.map((account, i) => (
          <span key={`${account.namespace}-${account.name}-${i}`}>
            {i > 0 ? <br /> : null}
            <Link
              to={`/cluster-permission/service-account/data?name=${encodeURIComponent(account.name)}&namespace=${encodeURIComponent(account.namespace)}`}
              onClick={() => {
                if (account.namespace) setSelectedNamespace(account.namespace)
              }}
            >
              {account.name}
            </Link>
          </span>
        ))}
      </>
    )
  }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster Permissions</CBreadcrumbItem>
          <CBreadcrumbItem active>Cluster Role Bindings</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Cluster Role Binding List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading cluster role bindings...</div>
        ) : query.error ? (
          <div className="text-danger">
            Error loading cluster role bindings: {query.error.message}
          </div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No cluster role bindings found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {nameCell}
            </Column>
            <Column title="Role" data="roles">
              {roleCell}
            </Column>
            <Column title="User" data="users">
              {lines}
            </Column>
            <Column title="Group" data="groups">
              {lines}
            </Column>
            <Column title="ServiceAccount" data="serviceAccounts">
              {serviceAccountCell}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ClusterRoleBindingView
