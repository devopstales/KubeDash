import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ServiceAccountsView from '../../src/views/ClusterPermission/ServiceAccounts'
import ServiceAccountDataView from '../../src/views/ClusterPermission/ServiceAccountData'
import SecretView from '../../src/views/Security/Secret'
import SecretDataView from '../../src/views/Security/SecretData'
import { useClusterStore } from '../../src/store/cluster'

vi.mock('../../src/components/KubeDataTable', () => {
  const React = require('react') as typeof import('react')
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (child as React.ReactElement<{ title: string; data: string; children?: unknown }>).props,
      )
    return (
      <table>
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col.title}>{col.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i}>
              {cols.map((col) => {
                const value = row[col.data]
                const node =
                  typeof col.children === 'function'
                    ? (col.children as (v: unknown) => React.ReactNode)(value)
                    : (value as React.ReactNode)
                return <td key={col.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/cluster-permission/service-account') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/cluster-permission/service-account"
            element={
              <ObjectRoute
                kind="serviceaccount"
                listRoute="/cluster-permission/service-account"
                list={<ServiceAccountsView />}
                detail={(p) => (
                  <ServiceAccountDataView name={p.name} namespace={p.namespace ?? ''} />
                )}
              />
            }
          />
          <Route
            path="/security/secret"
            element={
              <ObjectRoute
                kind="secret"
                listRoute="/security/secret"
                list={<SecretView />}
                detail={(p) => <SecretDataView name={p.name} namespace={p.namespace ?? ''} />}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string, namespace: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({
      [token]: { kind: 'serviceaccount', name, namespace, ts: Date.now(), origin: 'click' },
    }),
  )
  sessionStorage.setItem('kd_object_active', token)
}

// Render the data view directly (no ObjectRoute) for view-level state
// assertions; the legacy /data route and the ObjectRoute detail both feed it
// the same props.
const renderDataAt = (name: string, namespace: string, path = '/cluster-permission/service-account/data') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <ServiceAccountDataView name={name} namespace={namespace} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

test('lists-service-accounts-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'serviceaccounts',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'builder', namespace: 'team-a' },
            secrets: [{ name: 'builder-token' }],
            image_pull_secrets: [{ name: 'registry-cred' }],
          },
          {
            metadata: { name: 'default', namespace: 'team-a' },
            secrets: null,
            image_pull_secrets: null,
          },
        ],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ServiceAccountsView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref and navigates; the URL stays clean (R1, no ?selected= producer, R9).
  const nameButton = await screen.findByRole('button', { name: 'builder' })
  expect(requested).toBe('team-a')
  expect(screen.getByText('Service Accounts List')).toBeTruthy()
  expect(window.location.search).toBe('')
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Secret',
    'Pull Secret',
  ])
  expect(nameButton.closest('tr')?.textContent).not.toContain('?selected=')
  // the cross-kind secret cells are buttons (openObject with the secret kind)
  expect(screen.getByRole('button', { name: 'builder-token' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'registry-cred' })).toBeTruthy()
  expect(screen.getByText('default')).toBeTruthy()
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderAt(<ServiceAccountsView />)

  expect(await screen.findByText('No service accounts found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on serviceaccounts' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ServiceAccountsView />)

  expect(await screen.findByText(/RBAC_DENIED: list on serviceaccounts/)).toBeTruthy()
})

const builderAccount = {
  metadata: {
    name: 'builder',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { app: 'ci' },
    annotations: {
      owner: 'platform',
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"ServiceAccount"}',
    },
  },
  secrets: [{ name: 'builder-token' }, { name: 'builder-dockercfg' }],
  image_pull_secrets: [{ name: 'registry-cred' }],
}

test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ServiceAccountsView />)

  // Clicking the name button opens the detail via openObject; the URL never
  // carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'builder' })
  await user.click(nameButton)

  expect(await screen.findByText('Service Account Data')).toBeTruthy()
  // R1: the URL stays clean — no ?selected= (R9) and no identity.
  expect(window.location.search).toBe('')
  // the detail's Name row carries the account name (the breadcrumb item is
  // the other 'builder' on the page — scope to the Name row).
  const nameRow = screen.getByRole('rowheader', { name: 'Name:' }).closest('tr')
  expect(nameRow?.textContent).toContain('builder')
})

test('bolds-the-opened-account-from-the-active-ref', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  // The active ref (a click on builder in team-a) is what bolds the row now —
  // never a ?selected= param (R9). Render the list view directly (not through
  // ObjectRoute, which would swap in the detail for the seeded ref).
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  seedActiveRef('builder', 'team-a')
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/cluster-permission/service-account']}>
        <ServiceAccountsView />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  const opened = await screen.findByRole('button', { name: 'builder' })
  expect(opened.className).toContain('fw-bold')
  expect(opened.getAttribute('aria-current')).toBe('true')
})

test('secret-cell-opens-the-secret-detail', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
    http.get('*/api/v1/clusters/1/resources/secrets', () =>
      HttpResponse.json({
        kind: 'secrets',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'builder-token', namespace: 'team-a' },
            type: 'kubernetes.io/service-account-token',
            data: { token: btoa('s3cr3t') },
          },
        ],
      }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ServiceAccountsView />)

  // Cross-kind link: clicking a secret name opens the SECRET kind's detail
  // (R9: no ?selected= producer) on the secret's clean list route.
  const secretButton = await screen.findByRole('button', { name: 'builder-token' })
  await user.click(secretButton)

  // the secret's detail renders (cross-kind: the SECRET kind's detail, not
  // the serviceaccount's), on the secret kind's clean list route.
  expect(await screen.findByText('Secret Data', { selector: 'h5' })).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('shows-service-account-secrets', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('builder', 'team-a')

  // ADR-0040: secret names are buttons (openObject with the secret kind),
  // not Links — the URL never carries identity (R1).
  expect(await screen.findByRole('button', { name: 'builder-token' })).toBeTruthy()
  expect(screen.getByText('Service Account Data')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Service Accounts' }).getAttribute('href')).toBe(
    '/cluster-permission/service-account',
  )
  expect(screen.getByRole('rowheader', { name: 'Name:' })).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Namespace:' })).toBeTruthy()
  expect(screen.getByText('team-a')).toBeTruthy()
  expect(screen.getByText('2026-01-02T03:04:05Z')).toBeTruthy()
  expect(screen.getByText('owner')).toBeTruthy()
  expect(screen.getByText('platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByText('app')).toBeTruthy()
  expect(screen.getByText('ci')).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Secret:' })).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Pull Secret:' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'builder-token' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'builder-dockercfg' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'registry-cred' })).toBeTruthy()
  // R1: the URL stays clean even on the data view.
  expect(window.location.search).toBe('')
})

test('service-account-data-requires-a-name', async () => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderDataAt('', 'team-a')

  expect(await screen.findByText('Error: Service account name not provided')).toBeTruthy()
})
