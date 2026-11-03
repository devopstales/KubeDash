import React from 'react'
import { BrowserRouter, Navigate, Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CSpinner } from '@coreui/react'

import DefaultLayout from './layout/DefaultLayout'
import { AdminRoute, ProtectedRoute } from './routes'
import ObjectRoute, { registerNavigate } from './components/ObjectRoute'
import { clearActiveRef, getActiveRef, sweepRelay } from './lib/objectRef'
import { useClusterStore } from './store/cluster'
import StubView from './views/Stub'
import { stubRoutes } from './views/Stub/routes'
import './scss/style.scss'

// ponytail: the template's demo views are demo material, not KubeDash.
// Login/Clusters/Cluster are lazy below; the R5 surface (workflows,
// settings, docs) will add views to this file when it lands.
const LoginView = React.lazy(() => import('./views/Login'))
const ClustersView = React.lazy(() => import('./views/Clusters'))
const ClusterView = React.lazy(() => import('./views/Cluster'))
const ClusterDashboardView = React.lazy(() => import('./views/Cluster/Dashboard'))
const NamespacesView = React.lazy(() => import('./views/Cluster/Namespaces'))
const NamespaceDataView = React.lazy(() => import('./views/Cluster/NamespaceData'))
const NodesView = React.lazy(() => import('./views/Cluster/Nodes'))
const NodeDataView = React.lazy(() => import('./views/Cluster/NodeData'))
const CrdsView = React.lazy(() => import('./views/Cluster/CRDs'))
const CrdDataView = React.lazy(() => import('./views/Cluster/CrdData'))
const ProfileView = React.lazy(() => import('./views/Profile'))
const PermissionsView = React.lazy(() => import('./views/Permissions'))
const KubeconfigView = React.lazy(() => import('./views/Kubeconfig'))
const AdminPermissionsView = React.lazy(() => import('./views/AdminPermissions'))
const PrivilegesView = React.lazy(() => import('./views/AdminPermissions/Privileges'))
const PrivilegeEditView = React.lazy(() => import('./views/AdminPermissions/PrivilegeEdit'))
const ServiceAccountsView = React.lazy(() => import('./views/ClusterPermission/ServiceAccounts'))
const ServiceAccountDataView = React.lazy(
  () => import('./views/ClusterPermission/ServiceAccountData'),
)
const RoleView = React.lazy(() => import('./views/ClusterPermission/Role'))
const RoleDataView = React.lazy(() => import('./views/ClusterPermission/RoleData'))
const ClusterRoleView = React.lazy(() => import('./views/ClusterPermission/ClusterRole'))
const ClusterRoleDataView = React.lazy(() => import('./views/ClusterPermission/ClusterRoleData'))
const RoleBindingView = React.lazy(() => import('./views/ClusterPermission/RoleBinding'))
const ClusterRoleBindingView = React.lazy(
  () => import('./views/ClusterPermission/ClusterRoleBinding'),
)
const SecretView = React.lazy(() => import('./views/Security/Secret'))
const SecretDataView = React.lazy(() => import('./views/Security/SecretData'))
const NetworkPolicyView = React.lazy(() => import('./views/Security/NetworkPolicy'))
const NetworkPolicyDataView = React.lazy(() => import('./views/Security/NetworkPolicyData'))
const PriorityClassView = React.lazy(() => import('./views/OtherResource/PriorityClass'))
const PriorityClassDataView = React.lazy(() => import('./views/OtherResource/PriorityClassData'))
const RuntimeClassView = React.lazy(() => import('./views/OtherResource/RuntimeClass'))
const RuntimeClassDataView = React.lazy(() => import('./views/OtherResource/RuntimeClassData'))
const ResourceQuotaView = React.lazy(() => import('./views/OtherResource/ResourceQuota'))
const ResourceQuotaDataView = React.lazy(() => import('./views/OtherResource/ResourceQuotaData'))
const PodDisruptionBudgetView = React.lazy(() => import('./views/OtherResource/PodDisruptionBudget'))
const PodDisruptionBudgetDataView = React.lazy(() => import('./views/OtherResource/PodDisruptionBudgetData'))
const VerticalPodAutoscalerView = React.lazy(() => import('./views/OtherResource/VerticalPodAutoscaler'))
const VerticalPodAutoscalerDataView = React.lazy(() => import('./views/OtherResource/VerticalPodAutoscalerData'))
const HorizontalPodAutoscalerView = React.lazy(
  () => import('./views/OtherResource/HorizontalPodAutoscaler'),
)
const HorizontalPodAutoscalerDataView = React.lazy(
  () => import('./views/OtherResource/HorizontalPodAutoscalerData'),
)
const LimitRangeView = React.lazy(() => import('./views/OtherResource/LimitRange'))
const LimitRangeDataView = React.lazy(() => import('./views/OtherResource/LimitRangeData'))
const GroupsView = React.lazy(() => import('./views/Groups'))
const GroupPrivilegesView = React.lazy(() => import('./views/Groups/GroupPrivileges'))
const GroupPrivilegeEditView = React.lazy(() => import('./views/Groups/GroupPrivilegeEdit'))

/**
 * KubeDash SPA root: QueryClientProvider (TanStack Query) wraps the
 * router. The backend serves the bundle at / and the OIDC callback
 * delivers the JWT pair as a query string, so BrowserRouter (not the
 * template's HashRouter) is the right router.
 */
// ponytail: retry is off by default for this shell — the 401→refresh path
// in apiFetch is the real retry, and surfacing a persistent 403 (RBAC) is
// more honest than a spinner. Upgrade path: per-query retry for metrics.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false, refetchOnWindowFocus: false },
  },
})

const Fallback = () => <CSpinner color="primary" />

/**
 * ADR-0040 TICKET-02: the legacy /data route (kept for TICKET-07's contract
 * pass) reads the legacy ?name= param and hands it to the migrated data
 * view, which no longer reads useSearchParams itself.
 */
const LegacyPriorityClassData = () => {
  const [params] = useSearchParams()
  return <PriorityClassDataView name={params.get('name') ?? ''} />
}

/**
 * ADR-0040 TICKET-03: the legacy /security/secret/data route (kept for
 * TICKET-07's contract pass) reads the legacy ?name=/?namespace= params and
 * hands them to the migrated data view, which no longer reads
 * useSearchParams itself. The namespace falls back the way the old view did
 * (header's selectedNamespace, then 'default') — only the legacy path needs
 * it; the ObjectRoute path passes the ref's namespace (authoritative, R8).
 */
const LegacySecretData = () => {
  const [params] = useSearchParams()
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  return (
    <SecretDataView
      name={params.get('name') ?? ''}
      namespace={params.get('namespace') || selectedNamespace || 'default'}
    />
  )
}

/**
 * ADR-0040 TICKET-03: the legacy /security/network-policy/data route (kept
 * for TICKET-07's contract pass) reads the legacy ?name=/?kind=/?namespace=
 * params and hands them to the migrated data view. The cluster-scoped kind
 * carried no ?namespace= param before (the old view defaulted it to '').
 */
const LegacyNetworkPolicyData = () => {
  const [params] = useSearchParams()
  return (
    <NetworkPolicyDataView
      name={params.get('name') ?? ''}
      kind={params.get('kind') ?? ''}
      namespace={params.get('namespace') ?? ''}
    />
  )
}

/**
 * ADR-0040 TICKET-03: the network-policy list route dispatches on the active
 * ref's API kind. The registry kind IS the policy's API kind, so one ObjectRoute
 * per kind is the clean mapping — but that would render three `list` nodes
 * (and register the navigate seam three times). This dispatcher holds the
 * single seam + ref read and hands the detail to the view with its kind; the
 * list renders once. The legacy /data route (TICKET-07) is unchanged.
 */
const NetworkPolicyRoute = () => {
  const navigate = useNavigate()
  // Bumped by the registered navigate seam: openObject sets the active
  // pointer then navigates to the SAME list route this component renders,
  // so a plain location memo would not re-run. The seam bumps this state so
  // the ref is re-read and the detail renders — the same seam ObjectRoute uses.
  const [, bump] = React.useReducer((c: number) => c + 1, 0)
  const ref = React.useMemo(
    () => getActiveRef(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [bump],
  )
  const isPolicy =
    ref !== null &&
    (ref.kind === 'NetworkPolicy' ||
      ref.kind === 'CiliumNetworkPolicy' ||
      ref.kind === 'CiliumClusterwideNetworkPolicy')

  const seamRef = React.useRef(navigate)
  seamRef.current = navigate
  React.useEffect(() => {
    sweepRelay()
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])

  if (!isPolicy) return <NetworkPolicyView />
  return (
    <>
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary"
        onClick={() => {
          clearActiveRef()
          window.history.back()
        }}
      >
        &larr; back to list
      </button>
      <NetworkPolicyDataView
        name={ref!.name}
        kind={ref!.kind}
        namespace={ref!.namespace ?? ''}
      />
    </>
  )
}

/**
 * ADR-0040 TICKET-04: the legacy cluster-permission /data routes (kept for
 * TICKET-07's contract pass) read the legacy ?name=/?namespace= params and
 * hand them to the migrated data views, which no longer read
 * useSearchParams themselves. The namespaced views' namespace falls back
 * the way the old views did (header's selectedNamespace, then 'default') —
 * only the legacy paths need it; the ObjectRoute path passes the ref's
 * namespace (authoritative, R8).
 */
const LegacyServiceAccountData = () => {
  const [params] = useSearchParams()
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  return (
    <ServiceAccountDataView
      name={params.get('name') ?? ''}
      namespace={params.get('namespace') || selectedNamespace || 'default'}
    />
  )
}

const LegacyRoleData = () => {
  const [params] = useSearchParams()
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  return (
    <RoleDataView
      name={params.get('name') ?? ''}
      namespace={params.get('namespace') || selectedNamespace || 'default'}
    />
  )
}

const LegacyClusterRoleData = () => {
  const [params] = useSearchParams()
  return <ClusterRoleDataView name={params.get('name') ?? ''} />
}

/** Old per-user privilege URL. The page now lives at /user/privilege. */
const PrivilegeRedirect = () => {
  const { sub = '' } = useParams()
  const user = encodeURIComponent(sub)
  return <Navigate to={user ? `/user/privilege?user=${user}` : '/user/privilege'} replace />
}

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route
            path="/login"
            element={
              <React.Suspense fallback={<Fallback />}>
                <LoginView />
              </React.Suspense>
            }
          />
          <Route
            path="/*"
            element={
              <DefaultLayout>
                <React.Suspense fallback={<Fallback />}>
                  <Routes>
                    <Route
                      path="/clusters"
                      element={
                        <ProtectedRoute>
                          <ClustersView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/clusters/:id"
                      element={
                        <ProtectedRoute>
                          <ClusterView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/dashboard/cluster-metric"
                      element={
                        <ProtectedRoute>
                          <ClusterDashboardView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/profile"
                      element={
                        <ProtectedRoute>
                          <ProfileView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/permissions"
                      element={
                        <ProtectedRoute>
                          <PermissionsView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/settings/export"
                      element={
                        <ProtectedRoute>
                          <KubeconfigView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/privilege"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <PrivilegesView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/privilege/edit"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <PrivilegeEditView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/admin/permissions/users/:sub"
                      element={
                        <ProtectedRoute>
                          <PrivilegeRedirect />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/list"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <AdminPermissionsView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/group"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <GroupsView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/group/privilege"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <GroupPrivilegesView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/user/group/privilege/edit"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <GroupPrivilegeEditView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/admin/permissions"
                      element={
                        <ProtectedRoute>
                          <AdminRoute>
                            <AdminPermissionsView />
                          </AdminRoute>
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/service-account"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-04: ObjectRoute renders the list
                              or the ref-matched detail on the clean route.
                              The old /data route stays for TICKET-07's
                              contract pass (expand, not contract). */}
                          <ObjectRoute
                            kind="serviceaccount"
                            listRoute="/cluster-permission/service-account"
                            list={<ServiceAccountsView />}
                            detail={(p) => (
                              <ServiceAccountDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/service-account/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads its
                              identity from props, so it falls back to the
                              legacy ?name=/?namespace= params here. */}
                          <LegacyServiceAccountData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-04: ObjectRoute renders the list
                              or the ref-matched detail on the clean route.
                              The old /data route stays for TICKET-07's
                              contract pass (expand, not contract). */}
                          <ObjectRoute
                            kind="role"
                            listRoute="/cluster-permission/role"
                            list={<RoleView />}
                            detail={(p) => <RoleDataView name={p.name} namespace={p.namespace ?? ''} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads its
                              identity from props, so it falls back to the
                              legacy ?name=/?namespace= params here. */}
                          <LegacyRoleData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-04: ObjectRoute renders the list
                              or the ref-matched detail on the clean route.
                              The old /data route stays for TICKET-07's
                              contract pass (expand, not contract). */}
                          <ObjectRoute
                            kind="clusterrole"
                            listRoute="/cluster-permission/cluster-role"
                            list={<ClusterRoleView />}
                            detail={(p) => <ClusterRoleDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads
                              its name from the active ref, so it falls back
                              to the legacy ?name= param here. */}
                          <LegacyClusterRoleData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role-binding"
                      element={
                        <ProtectedRoute>
                          <RoleBindingView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role-binding"
                      element={
                        <ProtectedRoute>
                          <ClusterRoleBindingView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/namespace"
                      element={
                        <ProtectedRoute>
                          <NamespacesView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/namespace/data"
                      element={
                        <ProtectedRoute>
                          <NamespaceDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/node"
                      element={
                        <ProtectedRoute>
                          <NodesView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/node/data"
                      element={
                        <ProtectedRoute>
                          <NodeDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/crd"
                      element={
                        <ProtectedRoute>
                          <CrdsView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/crd/data"
                      element={
                        <ProtectedRoute>
                          <CrdDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/secret"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-03: ObjectRoute renders the list
                              or the ref-matched detail on the clean route.
                              The old /data route stays for TICKET-07's
                              contract pass (expand, not contract). */}
                          <ObjectRoute
                            kind="secret"
                            listRoute="/security/secret"
                            list={<SecretView />}
                            detail={(p) => <SecretDataView name={p.name} namespace={p.namespace ?? ''} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/secret/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads its
                              identity from props, so it falls back to the
                              legacy ?name=/?namespace= params here. */}
                          <LegacySecretData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/network-policy"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-03: the registry kind IS the
                              policy's API kind (NetworkPolicy /
                              CiliumNetworkPolicy /
                              CiliumClusterwideNetworkPolicy), so the route
                              dispatches on the active ref's kind — the
                              NetworkPolicyRoute dispatcher holds the single
                              seam + ref read and renders the list (no ref)
                              or the ref-matched detail (clean route). The
                              old /data route stays for TICKET-07's contract
                              pass (expand, not contract). */}
                          <NetworkPolicyRoute />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/network-policy/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads its
                              identity from props, so it falls back to the
                              legacy ?name=/?kind=/?namespace= params here. */}
                          <LegacyNetworkPolicyData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/priorityclass"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-02: template kind — ObjectRoute
                              renders the list or the ref-matched detail on
                              the clean route. The old /data route stays for
                              TICKET-07's contract pass (expand, not
                              contract). */}
                          <ObjectRoute
                            kind="priorityclass"
                            listRoute="/other-resource/priorityclass"
                            list={<PriorityClassView />}
                            detail={(p) => <PriorityClassDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/priorityclass/data"
                      element={
                        <ProtectedRoute>
                          {/* Legacy /data route (TICKET-07 keeps it working
                              until the contract pass): the view now reads
                              its name from the active ref, so it falls back
                              to the legacy ?name= param here. */}
                          <LegacyPriorityClassData />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/runtimeclass"
                      element={
                        <ProtectedRoute>
                          <RuntimeClassView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/runtimeclass/data"
                      element={
                        <ProtectedRoute>
                          <RuntimeClassDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/resource-quota"
                      element={
                        <ProtectedRoute>
                          <ResourceQuotaView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/resource-quota/data"
                      element={
                        <ProtectedRoute>
                          <ResourceQuotaDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/pod-disruption-budget"
                      element={
                        <ProtectedRoute>
                          <PodDisruptionBudgetView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/pod-disruption-budget/data"
                      element={
                        <ProtectedRoute>
                          <PodDisruptionBudgetDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/vertical-pod-autoscaler"
                      element={
                        <ProtectedRoute>
                          <VerticalPodAutoscalerView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/vertical-pod-autoscaler/data"
                      element={
                        <ProtectedRoute>
                          <VerticalPodAutoscalerDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/horizontal-pod-autoscaler"
                      element={
                        <ProtectedRoute>
                          <HorizontalPodAutoscalerView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/horizontal-pod-autoscaler/data"
                      element={
                        <ProtectedRoute>
                          <HorizontalPodAutoscalerDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/limit-range"
                      element={
                        <ProtectedRoute>
                          <LimitRangeView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/limit-range/data"
                      element={
                        <ProtectedRoute>
                          <LimitRangeDataView />
                        </ProtectedRoute>
                      }
                    />
                    {stubRoutes.map((route) => (
                      <Route
                        key={route.path}
                        path={route.path}
                        element={
                          <ProtectedRoute>
                            {route.admin ? (
                              <AdminRoute>
                                <StubView title={route.title} />
                              </AdminRoute>
                            ) : (
                              <StubView title={route.title} />
                            )}
                          </ProtectedRoute>
                        }
                      />
                    ))}
                    <Route path="/" element={<Navigate to="/clusters" replace />} />
                    <Route path="*" element={<Navigate to="/clusters" replace />} />
                  </Routes>
                </React.Suspense>
              </DefaultLayout>
            }
          />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
