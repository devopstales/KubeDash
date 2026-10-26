import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { expect, test } from 'vitest'
import { server } from '../msw'
import { navigation, type NavItem } from '../../src/_nav'
import { AdminRoute } from '../../src/routes'
import StubView from '../../src/views/Stub'
import { stubRoutes } from '../../src/views/Stub/routes'

function leaves(items: NavItem[]): { name: string; to?: string }[] {
  return items.flatMap((item) =>
    item.divider
      ? []
      : item.items
        ? leaves(item.items)
        : item.to
          ? [{ name: item.name, to: item.to }]
          : [],
  )
}

function expectedStubs() {
  const viewPaths = new Set([
    '/clusters',
    '/permissions',
    '/user/list',
    '/user/group',
    '/cluster-permission/service-account',
    '/cluster-permission/role',
    '/cluster-permission/role-binding',
    '/cluster-permission/cluster-role',
    '/cluster-permission/cluster-role-binding',
    '/security/secret',
    '/cluster/namespace',
    // Real view (cluster node route) — not a stub route. The nav leaf targets
    // the list at /cluster/node; the detail is /cluster/node/data.
    '/cluster/node',
    '/cluster/node/data',
    // Real view (CRD endpoint + views) — not a stub route. The nav leaf
    // targets the list at /cluster/crd; the detail is /cluster/crd/data.
    '/cluster/crd',
    '/cluster/crd/data',
    // Real view (2026-10-21-cluster-dashboard, Task 6) — not a stub route.
    '/dashboard/cluster-metric',
  ])
  const seen = new Map<string, string>()
  for (const isAdmin of [true, false]) {
    for (const leaf of leaves(navigation({ clusterId: 7, isAdmin }))) {
      if (
        !leaf.to ||
        viewPaths.has(leaf.to) ||
        leaf.to.startsWith('/admin/permissions') ||
        leaf.to.startsWith('/clusters/')
      ) {
        continue
      }
      seen.set(leaf.to, leaf.name)
    }
  }
  return [...seen.entries()]
    .map(([path, title]) => ({ path, title }))
    .sort((a, b) => a.path.localeCompare(b.path))
}

test('stub-page-names-the-entry', () => {
  render(
    <MemoryRouter initialEntries={['/workload/pods']}>
      <Routes>
        <Route path="/workload/pods" element={<StubView title="Pods" />} />
        <Route path="*" element={<p>redirected</p>} />
      </Routes>
    </MemoryRouter>,
  )
  expect(screen.getByRole('heading', { name: 'Pods' })).toBeTruthy()
  expect(screen.getByText('This view is not available yet.')).toBeTruthy()
  expect(screen.queryByText('redirected')).toBeNull()
})

test('every-stub-entry-has-a-page', () => {
  const expected = expectedStubs()
  const actual = stubRoutes
    .map((route) => ({ path: route.path, title: route.title }))
    .sort((a, b) => a.path.localeCompare(b.path))
  expect(actual).toEqual(expected)
  for (const route of stubRoutes) {
    expect(route.admin).toBe(route.path.startsWith('/settings/'))
  }
  for (const title of [
    'Workload',
    'Ingress',
    'VolumeClaims',
    'Network Policies',
    'Runtime Class',
  ]) {
    expect(stubRoutes.some((route) => route.title === title)).toBe(true)
  }
})

test('settings-url-rejects-non-admin', async () => {
  server.use(
    http.get('*/api/v1/auth/me', () =>
      HttpResponse.json({
        sub: 'u2',
        email: 'alice@example.com',
        display_name: 'Alice',
        groups: [],
        role: 'user',
      }),
    ),
  )
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/settings/sso-config']}>
        <Routes>
          <Route
            path="/settings/sso-config"
            element={
              <AdminRoute>
                <StubView title="Auth Provider" />
              </AdminRoute>
            }
          />
          <Route path="/" element={<div>Home page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  expect(await screen.findByText('Home page')).toBeTruthy()
  expect(screen.queryByRole('heading', { name: 'Auth Provider' })).toBeNull()
})

test('existing-views-still-open', () => {
  const paths = stubRoutes.map((route) => route.path)
  expect(paths).not.toContain('/permissions')
  expect(paths).not.toContain('/clusters')
})

test('unknown-path-still-redirects-to-cluster-list', () => {
  expect(stubRoutes.some((route) => route.path === '/not-a-menu-entry')).toBe(false)
})
