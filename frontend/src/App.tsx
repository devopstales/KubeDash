import React from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CSpinner, useColorModes } from '@coreui/react'

import DefaultLayout from './layout/DefaultLayout'
import { ProtectedRoute } from './routes'
import './scss/style.scss'

// ponytail: the template's demo views are demo material, not KubeDash.
// Login/Clusters/Cluster are lazy below; the R5 surface (workflows,
// settings, docs) will add views to this file when it lands.
const LoginView = React.lazy(() => import('./views/Login'))
const ClustersView = React.lazy(() => import('./views/Clusters'))
const ClusterView = React.lazy(() => import('./views/Cluster'))

/**
 * KubeDash SPA root: QueryClientProvider (TanStack Query) wraps the
 * router. The backend serves the bundle at / and the OIDC callback
 * delivers the JWT pair as a query string, so BrowserRouter (not the
 * template's HashRouter) is the right router.
 */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
})

const Fallback = () => <CSpinner color="primary" />

const App = () => {
  const { isColorModeSet, setColorMode } = useColorModes('kubedash-theme')
  if (!isColorModeSet()) {
    setColorMode('light')
  }

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
