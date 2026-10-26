import React from 'react'
import { BrowserRouter, Navigate, Route, Routes, useParams } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CSpinner } from '@coreui/react'

import DefaultLayout from './layout/DefaultLayout'
import { AdminRoute, ProtectedRoute } from './routes'
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
                          <ServiceAccountsView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/service-account/data"
                      element={
                        <ProtectedRoute>
                          <ServiceAccountDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role"
                      element={
                        <ProtectedRoute>
                          <RoleView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/role/data"
                      element={
                        <ProtectedRoute>
                          <RoleDataView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role"
                      element={
                        <ProtectedRoute>
                          <ClusterRoleView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/cluster-permission/cluster-role/data"
                      element={
                        <ProtectedRoute>
                          <ClusterRoleDataView />
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
                          <SecretView />
                        </ProtectedRoute>
                      }
                    />
                    <Route
                      path="/security/secret/data"
                      element={
                        <ProtectedRoute>
                          <SecretDataView />
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
