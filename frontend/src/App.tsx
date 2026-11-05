import React from 'react'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CSpinner } from '@coreui/react'

import DefaultLayout from './layout/DefaultLayout'
import { AdminRoute, ProtectedRoute } from './routes'
import ObjectRoute, { registerNavigate } from './components/ObjectRoute'
import OldDataRedirect from './components/OldDataRedirect'
import { getActiveRef, sweepRelay } from './lib/objectRef'
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
const PodDisruptionBudgetView = React.lazy(
  () => import('./views/OtherResource/PodDisruptionBudget'),
)
const PodDisruptionBudgetDataView = React.lazy(
  () => import('./views/OtherResource/PodDisruptionBudgetData'),
)
const VerticalPodAutoscalerView = React.lazy(
  () => import('./views/OtherResource/VerticalPodAutoscaler'),
)
const VerticalPodAutoscalerDataView = React.lazy(
  () => import('./views/OtherResource/VerticalPodAutoscalerData'),
)
const HorizontalPodAutoscalerView = React.lazy(
  () => import('./views/OtherResource/HorizontalPodAutoscaler'),
)
const HorizontalPodAutoscalerDataView = React.lazy(
  () => import('./views/OtherResource/HorizontalPodAutoscalerData'),
)
const LimitRangeView = React.lazy(() => import('./views/OtherResource/LimitRange'))
const LimitRangeDataView = React.lazy(() => import('./views/OtherResource/LimitRangeData'))
const StorageClassView = React.lazy(() => import('./views/Storage/StorageClass'))
const StorageClassDataView = React.lazy(() => import('./views/Storage/StorageClassData'))
const ConfigMapView = React.lazy(() => import('./views/Storage/ConfigMap'))
const ConfigMapDataView = React.lazy(() => import('./views/Storage/ConfigMapData'))
const SnapshotClassView = React.lazy(() => import('./views/Storage/SnapshotClass'))
const SnapshotClassDataView = React.lazy(() => import('./views/Storage/SnapshotClassData'))
const VolumeSnapshotView = React.lazy(() => import('./views/Storage/VolumeSnapshot'))
const VolumeSnapshotDataView = React.lazy(() => import('./views/Storage/VolumeSnapshotData'))
const PvcView = React.lazy(() => import('./views/Storage/Pvc'))
const PvcDataView = React.lazy(() => import('./views/Storage/PvcData'))
const PvView = React.lazy(() => import('./views/Storage/Pv'))
const PvDataView = React.lazy(() => import('./views/Storage/PvData'))
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
 * ADR-0040 TICKET-03: the network-policy list route dispatches on the active
 * ref's API kind. The registry kind IS the policy's API kind, so one ObjectRoute
 * per kind is the clean mapping — but that would render three `list` nodes
 * (and register the navigate seam three times). This dispatcher holds the
 * single seam + ref read and hands the detail to the view with its kind; the
 * list renders once. The legacy /data route is an OldDataRedirect (R7).
 */
export const NetworkPolicyRoute = () => {
  const navigate = useNavigate()
  // useLocation (NOT the global window.location, which has a stable
  // identity and would make the memo dep inert): openObject sets the
  // active pointer then navigates to the SAME list route this component
  // renders — the router's location object is a fresh instance per
  // navigation, so the memo re-runs, the ref is re-read and the detail
  // renders. Mirrors ObjectRoute. The seam bump is the same backup
  // ObjectRoute uses for a navigate that leaves the location unchanged.
  const location = useLocation()
  const [, bump] = React.useReducer((c: number) => c + 1, 0)
  const ref = React.useMemo(
    () => getActiveRef(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [location, bump],
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
    <NetworkPolicyDataView name={ref!.name} kind={ref!.kind} namespace={ref!.namespace ?? ''} />
  )
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
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
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
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="serviceaccount"
                            listRoute="/cluster-permission/service-account"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-04: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
                          <ObjectRoute
                            kind="role"
                            listRoute="/cluster-permission/role"
                            list={<RoleView />}
                            detail={(p) => (
                              <RoleDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect kind="role" listRoute="/cluster-permission/role" />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-04: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
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
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect
                            kind="clusterrole"
                            listRoute="/cluster-permission/cluster-role"
                            clusterScoped
                          />
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
                          {/* ADR-0040 TICKET-05: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
                          <ObjectRoute
                            kind="namespace"
                            listRoute="/cluster/namespace"
                            list={<NamespacesView />}
                            detail={(p) => <NamespaceDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/namespace/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect
                            kind="namespace"
                            listRoute="/cluster/namespace"
                            clusterScoped
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/node"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-05: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
                          <ObjectRoute
                            kind="node"
                            listRoute="/cluster/node"
                            list={<NodesView />}
                            detail={(p) => <NodeDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/node/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect kind="node" listRoute="/cluster/node" clusterScoped />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/crd"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-05: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
                          <ObjectRoute
                            kind="crd"
                            listRoute="/cluster/crd"
                            list={<CrdsView />}
                            detail={(p) => <CrdDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster/crd/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect kind="crd" listRoute="/cluster/crd" clusterScoped />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/secret"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-03: ObjectRoute renders the list
                              or the ref-matched detail on the clean route;
                              the old /data URL is its R7 redirect (TICKET-07). */}
                          <ObjectRoute
                            kind="secret"
                            listRoute="/security/secret"
                            list={<SecretView />}
                            detail={(p) => (
                              <SecretDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/secret/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect kind="secret" listRoute="/security/secret" />
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
                              old /data URL is its R7 redirect (TICKET-07). */}
                          <NetworkPolicyRoute />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/network-policy/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?kind=/?namespace=
                              and lands on the clean route's detail. The
                              registry kind IS the policy's API kind, so the
                              ?kind= param names it (fallback: the route's
                              default kind). */}
                          <OldDataRedirect
                            kind="NetworkPolicy"
                            listRoute="/security/network-policy"
                            kindFromParam
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/priorityclass"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-02: template kind — ObjectRoute
                              renders the list or the ref-matched detail on
                              the clean route; the old /data URL is its R7
                              redirect (TICKET-07). */}
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
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect
                            kind="priorityclass"
                            listRoute="/other-resource/priorityclass"
                            clusterScoped
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/runtimeclass"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="runtimeclass"
                            listRoute="/other-resource/runtimeclass"
                            list={<RuntimeClassView />}
                            detail={(p) => <RuntimeClassDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/runtimeclass/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name= and lands on the
                              clean route's detail. Cluster-scoped: no
                              namespace. */}
                          <OldDataRedirect
                            kind="runtimeclass"
                            listRoute="/other-resource/runtimeclass"
                            clusterScoped
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/resource-quota"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="resourcequota"
                            listRoute="/other-resource/resource-quota"
                            list={<ResourceQuotaView />}
                            detail={(p) => (
                              <ResourceQuotaDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/resource-quota/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="resourcequota"
                            listRoute="/other-resource/resource-quota"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/pod-disruption-budget"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="poddisruptionbudget"
                            listRoute="/other-resource/pod-disruption-budget"
                            list={<PodDisruptionBudgetView />}
                            detail={(p) => (
                              <PodDisruptionBudgetDataView
                                name={p.name}
                                namespace={p.namespace ?? ''}
                              />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/pod-disruption-budget/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="poddisruptionbudget"
                            listRoute="/other-resource/pod-disruption-budget"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/vertical-pod-autoscaler"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="verticalpodautoscaler"
                            listRoute="/other-resource/vertical-pod-autoscaler"
                            list={<VerticalPodAutoscalerView />}
                            detail={(p) => (
                              <VerticalPodAutoscalerDataView
                                name={p.name}
                                namespace={p.namespace ?? ''}
                              />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/vertical-pod-autoscaler/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="verticalpodautoscaler"
                            listRoute="/other-resource/vertical-pod-autoscaler"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/horizontal-pod-autoscaler"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="horizontalpodautoscaler"
                            listRoute="/other-resource/horizontal-pod-autoscaler"
                            list={<HorizontalPodAutoscalerView />}
                            detail={(p) => (
                              <HorizontalPodAutoscalerDataView
                                name={p.name}
                                namespace={p.namespace ?? ''}
                              />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/horizontal-pod-autoscaler/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="horizontalpodautoscaler"
                            listRoute="/other-resource/horizontal-pod-autoscaler"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/limit-range"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-06: ObjectRoute renders the
                              list or the ref-matched detail on the clean
                              route; the old /data URL is its R7 redirect
                              (TICKET-07). */}
                          <ObjectRoute
                            kind="limitrange"
                            listRoute="/other-resource/limit-range"
                            list={<LimitRangeView />}
                            detail={(p) => (
                              <LimitRangeDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/other-resource/limit-range/data"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040 TICKET-07 (R7): the legacy /data URL is
                              a redirect, not a primary route — it hydrates
                              the ref from the legacy ?name=/?namespace= and
                              lands on the clean route's detail. */}
                          <OldDataRedirect
                            kind="limitrange"
                            listRoute="/other-resource/limit-range"
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/storage-class"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Cluster-scoped: no namespace. */}
                          <ObjectRoute
                            kind="storageclass"
                            listRoute="/storage/storage-class"
                            list={<StorageClassView />}
                            detail={(p) => <StorageClassDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/configmap"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Namespaced: the namespace rides
                              in the ref (R8). */}
                          <ObjectRoute
                            kind="configmap"
                            listRoute="/storage/configmap"
                            list={<ConfigMapView />}
                            detail={(p) => (
                              <ConfigMapDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/snapshot-class"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Cluster-scoped: no namespace. */}
                          <ObjectRoute
                            kind="snapshotclass"
                            listRoute="/storage/snapshot-class"
                            list={<SnapshotClassView />}
                            detail={(p) => <SnapshotClassDataView name={p.name} />}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/volumesnapshot"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Namespaced: the namespace rides
                              in the ref (R8). */}
                          <ObjectRoute
                            kind="volumesnapshot"
                            listRoute="/storage/volumesnapshot"
                            list={<VolumeSnapshotView />}
                            detail={(p) => (
                              <VolumeSnapshotDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/pvc"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Namespaced: the namespace rides
                              in the ref (R8). */}
                          <ObjectRoute
                            kind="pvc"
                            listRoute="/storage/pvc"
                            list={<PvcView />}
                            detail={(p) => (
                              <PvcDataView name={p.name} namespace={p.namespace ?? ''} />
                            )}
                          />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/storage/pv"
                      element={
                        <ProtectedRoute>
                          {/* ADR-0040: ObjectRoute renders the list or the
                              ref-matched detail on the clean route. First
                              build of this kind (it was a stub; the /data
                              URL never shipped) — NO legacy /data route, no
                              R7 redirect. Cluster-scoped: no namespace. */}
                          <ObjectRoute
                            kind="persistentvolume"
                            listRoute="/storage/pv"
                            list={<PvView />}
                            detail={(p) => <PvDataView name={p.name} />}
                          />
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
