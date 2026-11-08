import { useNavigate } from 'react-router-dom'
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
import { openObject } from '../../lib/objectRef'
import type { K8sRoleBinding, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040 TICKET-04: registry kinds + clean list routes for the cross-kind
// targets (role / clusterrole / serviceaccount). The binding's own row is a
// plain column (the kind is list-only; only its targets are openable).
const ROLE_ROUTE = '/cluster-permission/role'
const CLUSTER_ROLE_ROUTE = '/cluster-permission/cluster-role'
const SERVICE_ACCOUNT_ROUTE = '/cluster-permission/service-account'

type RoleRef = { kind: string; name: string }
type ServiceAccountSubject = { name: string; namespace: string }

type RoleBindingRow = {
  name: string
  roles: RoleRef[]
  users: string[]
  groups: string[]
  serviceAccounts: ServiceAccountSubject[]
}

const toRow = (binding: K8sRoleBinding): RoleBindingRow => {
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

/** 4.1 prints one value per line (`role-binding.html.j2`). */
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

/**
 * ADR-0040 TICKET-04: a bound role opens the TARGET kind's detail via
 * openObject (role → namespaced rule list; clusterrole → cluster rule
 * list). The URL never carries object identity (R1).
 */
const roleCell = (role: RoleRef, namespace: string, navigate: (path: string) => void) => {
  if (role.kind === 'Role') {
    return (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject('role', role.name, namespace, ROLE_ROUTE, navigate)}
      >
        {role.name}
      </button>
    )
  }
  if (role.kind === 'ClusterRole') {
    return (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject('clusterrole', role.name, undefined, CLUSTER_ROLE_ROUTE, navigate)}
      >
        {role.name}
      </button>
    )
  }
  return role.name
}

/**
 * 4.1 `cluster-permission/role-binding.html.j2`: RoleBindings in the
 * header-selected namespace. A Role opens its rules, a ClusterRole opens
 * the cluster-role rule list, and a ServiceAccount opens that account
 * (switching the header namespace to the account's namespace) — all via
 * openObject with the TARGET kind (ADR-0040).
 */
const RoleBindingView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const setSelectedNamespace = useClusterStore((s) => s.setSelectedNamespace)
  const navigate = useNavigate()

  const query = useQuery<RoleBindingRow[]>({
    queryKey: ['rolebindings', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sRoleBinding>>(
        `/api/v1/clusters/${cluster!.id}/resources/rolebindings?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  const roleLinks = (roles: RoleRef[]) => {
    if (roles.length === 0) return ' '
    return (
      <>
        {roles.map((role, i) => (
          <span key={`${role.kind}-${role.name}-${i}`}>
            {i > 0 ? <br /> : null}
            {roleCell(role, namespace, navigate)}
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
            <button
              type="button"
              className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
              onClick={() => {
                // The header namespace follows the account's namespace (4.1
                // behavior); the ref carries the account's namespace (R8).
                if (account.namespace) setSelectedNamespace(account.namespace)
                openObject('serviceaccount', account.name, account.namespace, SERVICE_ACCOUNT_ROUTE, navigate)
              }}
            >
              {account.name}
            </button>
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
          <CBreadcrumbItem active>Role Bindings</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Role Bindings List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading role bindings...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading role bindings: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No role bindings found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name" />
            <Column title="Role" data="roles">
              {roleLinks}
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

export default RoleBindingView
