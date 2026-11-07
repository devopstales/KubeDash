import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import CrdsView from '../../src/views/Cluster/CRDs'
import CrdDataView from '../../src/views/Cluster/CrdData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

const CRDS = {
  kind: 'crds',
  cluster: 'prod',
  items: [
    {
      metadata: { name: 'applications.argoproj.io', creationTimestamp: '2026-01-01T00:00:00Z' },
      spec: {
        group: 'argoproj.io',
        names: { kind: 'Application', plural: 'applications' },
        scope: 'Namespaced',
        versions: [
          { name: 'v1alpha1', served: true, storage: true },
          { name: 'v1', served: true, storage: false },
        ],
      },
    },
  ],
}

const CRD_SINGLE = { items: [CRDS.items[0]], kind: 'crds', cluster: 'prod' }

const INSTANCES = {
  kind: 'crds',
  cluster: 'prod',
  items: [
    {
      name: 'app-1',
      namespace: 'team-a',
      status: 'True',
      type: 'Ready',
      reason: 'Ok',
      message: 'all good',
      created: '2026-01-02T03:04:05Z',
    },
  ],
}

// ADR-0040: `ui === null` renders the list through ObjectRoute (the real
// click→detail flow); a data view is rendered directly on the CLEAN list
// route with its identity as a prop — never a query param (R1/R8).
const renderAt = (
  ui: ReactElement | null,
  path: string,
  handlers: AnyHandler[],
  initialEntries?: string[],
) => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  server.use(...handlers)
  const element =
    ui === null ? (
      <Routes>
        <Route
          path="/cluster/crd"
          element={
            <ObjectRoute
              kind="crd"
              listRoute="/cluster/crd"
              list={<CrdsView />}
              detail={(p) => <CrdDataView name={p.name} />}
            />
          }
        />
      </Routes>
    ) : (
      ui
    )
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={initialEntries ?? [path]}>{element}</MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  document.cookie = 'kd_session=1; path=/'
})

afterEach(() => {
  localStorage.clear()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('crd-list-renders: 4.1 columns + served versions + kind link', async () => {
  renderAt(
    null,
    '/cluster/crd',
    [http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRDS))],
  )
  await screen.findByRole('table')
  // 5.0 column set (the 4.1 Resource/Group/Version/Scope/Acction, with the
  // single "Version" split into the served-versions column).
  for (const header of ['Kind', 'Group', 'Plural', 'Scope', 'Served', 'Created']) {
    expect(screen.getByText(header)).toBeTruthy()
  }
  // The CRD's identity renders.
  expect(screen.getByText('Application')).toBeTruthy()
  expect(screen.getByText('argoproj.io')).toBeTruthy()
  expect(screen.getByText('applications')).toBeTruthy()
  expect(screen.getByText('Namespaced')).toBeTruthy()
  // Both served versions render; the storage version (v1alpha1) is flagged
  // with the ✦ marker (a separate text node, hence the regex match).
  expect(screen.getByText(/v1alpha1/)).toBeTruthy()
  // The non-storage served version (v1) — a word boundary keeps the match
  // distinct from the v1alpha1 badge above.
  expect(screen.getByText(/^v1$/)).toBeTruthy()
  // ADR-0040: the kind cell is a button (not a Link) — the ref carries the
  // CRD's metadata.name (`<plural>.<group>`), not the bare plural; the URL
  // stays clean (R1).
  expect(screen.getByRole('button', { name: 'Application' })).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('crd-detail-renders: CRD identity + instance rows', async () => {
  // ADR-0040: the identity is a prop from the active ref (rendered on the
  // clean list route). The TWO calls are asserted by request URL: the CRD
  // read and the instance list both carry the ref's name (not the bare
  // plural), and the instance list additionally carries the topbar
  // namespace for a Namespaced CRD.
  let crdReadUrl = ''
  let instancesUrl = ''
  renderAt(
    <CrdDataView name="applications.argoproj.io" />,
    '/cluster/crd/data',
    [
      http.get('*/api/v1/clusters/1/resources/crds', ({ request }) => {
        crdReadUrl = request.url
        return HttpResponse.json(CRD_SINGLE)
      }),
      http.get('*/api/v1/clusters/1/resources/crds/instances', ({ request }) => {
        instancesUrl = request.url
        return HttpResponse.json(INSTANCES)
      }),
    ],
    ['/cluster/crd'],
  )
  // Two queries run sequentially (the instance list is gated on the CRD read
  // resolving) — wait for the instance row, not just the first table.
  expect(await screen.findByText('app-1', {}, { timeout: 4000 })).toBeTruthy()
  // The CRD's own identity, resolved server-side (the 4.1 namespaced→cluster
  // fallback is gone — the CRD spec is the authority). The kind appears in the
  // breadcrumb, the title, and the table — assert presence, not uniqueness.
  expect(screen.getAllByText('argoproj.io').length).toBeGreaterThanOrEqual(1)
  expect(screen.getAllByText('Application').length).toBeGreaterThanOrEqual(1)
  expect(screen.getAllByText('Namespaced').length).toBeGreaterThanOrEqual(1)
  // The served version (the first served in the fixture is v1alpha1).
  expect(screen.getByText('v1alpha1')).toBeTruthy()
  // The remaining instance cells render.
  expect(screen.getByText('team-a')).toBeTruthy()
  expect(screen.getByText('Ready')).toBeTruthy()
  expect(screen.getByText('all good')).toBeTruthy()
  // The breadcrumb links back to the CRD list.
  expect(screen.getByRole('link', { name: 'CRDs' }).getAttribute('href')).toBe('/cluster/crd')
  // R1: the URL is clean — identity is the prop, never the query string.
  expect(window.location.search).toBe('')
  // The two API calls both carry the ref's name (`<plural>.<group>`); the
  // instance list (call 2) adds the topbar namespace (Namespaced CRD).
  const crdRead = new URL(crdReadUrl)
  expect(crdRead.searchParams.get('name')).toBe('applications.argoproj.io')
  expect(crdRead.searchParams.get('namespace')).toBeNull()
  const instances = new URL(instancesUrl)
  expect(instances.searchParams.get('name')).toBe('applications.argoproj.io')
  expect(instances.searchParams.get('namespace')).toBe('team-a')
})

test('crd-detail-empty: no instances → first-class empty state, not an error', async () => {
  renderAt(
    <CrdDataView name="applications.argoproj.io" />,
    '/cluster/crd/data',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRD_SINGLE)),
      http.get('*/api/v1/clusters/1/resources/crds/instances', () =>
        HttpResponse.json({ kind: 'crds', cluster: 'prod', items: [] }),
      ),
    ],
    ['/cluster/crd'],
  )
  await screen.findByText(/No Application instances found/)
  // The empty state names the namespace (the topbar selection is applied).
  expect(screen.getByText(/in namespace 'team-a'/)).toBeTruthy()
})

test('crd-detail-rbac-denied: 403 on the instance list surfaces the error', async () => {
  renderAt(
    <CrdDataView name="applications.argoproj.io" />,
    '/cluster/crd/data',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRD_SINGLE)),
      http.get('*/api/v1/clusters/1/resources/crds/instances', () =>
        HttpResponse.json(
          { error: { code: 'RBAC_DENIED', message: 'list on applications' } },
          { status: 403 },
        ),
      ),
    ],
    ['/cluster/crd'],
  )
  await screen.findByText(/Error loading instances/)
  expect(screen.getByText(/RBAC_DENIED/)).toBeTruthy()
})

test('crd-detail-missing-name: empty name prop → error line', () => {
  // ADR-0040: the identity is the prop (the ref's name); an empty prop is
  // the not-provided state — the URL never carries it (R1/R8).
  renderAt(<CrdDataView name="" />, '/cluster/crd/data', [], ['/cluster/crd'])
  expect(screen.getByText('Error: CRD name not provided')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('crd-list-rbac-denied: 403 on the CRD list surfaces the error', async () => {
  renderAt(
    <CrdsView />,
    '/cluster/crd',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () =>
        HttpResponse.json(
          { error: { code: 'RBAC_DENIED', message: 'list on customresourcedefinitions' } },
          { status: 403 },
        ),
      ),
    ],
  )
  await screen.findByText(/Error loading CRDs/)
  expect(screen.getByText(/RBAC_DENIED/)).toBeTruthy()
})
