import React from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { registerNavigate } from '../../src/components/ObjectRoute'
import { getActiveRef } from '../../src/lib/objectRef'
import NetworkPolicyView from '../../src/views/Security/NetworkPolicy'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as secrets.test.tsx: renders the real row
// mapping (children-as-render-fns included) so cell assertions test the
// view's `toRow` output, not DataTables' DOM. The factory is async: a
// hoisted mock may not touch module-scope consts, so react is imported
// inline (`vi.mock` calls are hoisted above the imports below).
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = (await import('react')) as typeof import('react')
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
          (
            child as React.ReactElement<{
              title: string
              data: string | null
              children?: unknown
            }>
          ).props,
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
                // `data={null}` hands the render fn the whole row (the
                // datatables.net-react contract, see Namespaces.tsx).
                const value = col.data === null ? row : row[col.data]
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

// ADR-0040: mirror App.tsx's NetworkPolicyRoute seam registration so the
// click→openObject flow runs through the same navigate seam the app uses. The
// URL never carries identity — the list route is always clean (R1); the
// click assertions read the active ref back from the registry.
const NetworkPolicyRoute = () => {
  const navigate = useNavigate()
  const seamRef = React.useRef(navigate)
  seamRef.current = navigate
  React.useEffect(() => {
    registerNavigate((path: string) => {
      seamRef.current(path)
    })
  }, [])
  return <NetworkPolicyView />
}

const renderAt = (_ui: ReactElement, path = '/security/network-policy') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/security/network-policy" element={<NetworkPolicyRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const selectTeamA = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case, spec intact.
const denyAll = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'NetworkPolicy',
  metadata: {
    name: 'deny-all',
    namespace: 'team-a',
    creation_timestamp: '2026-10-26T10:00:00Z',
    labels: { app: 'web' },
  },
  spec: {
    pod_selector: { match_labels: { app: 'web' } },
    policy_types: ['Ingress', 'Egress'],
    ingress: [{ from: [] }],
    egress: [],
  },
}

// full CRD to_dict shape: camelCase spec, no policy_types.
const cnp = {
  metadata: {
    name: 'cnp',
    namespace: 'team-a',
    creation_timestamp: '2026-10-26T09:00:00Z',
    labels: null,
  },
  spec: {
    endpointSelector: { matchLabels: { app: 'web' } },
    ingress: [{ from: [] }],
    egress: [{ to: [] }],
  },
}

const ccnp = {
  metadata: {
    name: 'ccnp',
    namespace: null,
    creation_timestamp: '2026-10-26T08:00:00Z',
    labels: null,
  },
  spec: {
    endpointSelector: {},
    egress: [],
  },
}

// Pin the three kind URLs (the view↔API seam): an exact-path capture per
// kind so a kind-string drift (e.g. `network-policy`) fails here, not in a
// browser. The default msw handler answers any other resource URL with
// `{items: []}`, which would hide such drift.
const capturePaths = () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  return seen
}

test('list-renders-namespace-policies', async () => {
  const seen: string[] = []
  let nsParam = ''
  // Record every resource path the view fetches (kind-string seam), then
  // serve items. A specific handler per kind pushes to `seen` too, so the
  // path list is complete even when the generic wildcard is shadowed.
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      nsParam = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'networkpolicies',
        cluster: 'prod',
        items: [denyAll, { metadata: { name: 'no-spec' } }],
      })
    }),
    http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ kind: 'ciliumnetworkpolicies', cluster: 'prod', items: [] })
    }),
    http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ kind: 'ciliumclusterwidenetworkpolicies', cluster: 'prod', items: [] })
    }),
  )
  selectTeamA()
  const { container } = renderAt(<NetworkPolicyView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref and navigates; the URL stays clean.
  const link = await screen.findByRole('button', { name: 'deny-all' })
  // R1: the list route is clean — no identity, no `?selected=` (R9).
  expect(window.location.search).toBe('')
  expect(link.closest('tr')?.textContent).not.toContain('?selected=')
  expect(container.textContent).toBeTruthy()
  // kind strings byte-for-byte: the 4.1 route name is not a kind.
  expect(seen).toContain('/api/v1/clusters/1/resources/networkpolicies')
  expect(seen).toContain('/api/v1/clusters/1/resources/ciliumnetworkpolicies')
  expect(seen).toContain('/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies')
  expect(seen.some((p) => p.includes('network-policy'))).toBe(false)
  expect(seen).toHaveLength(3) // exactly the three kinds, no extras
  // the namespaced kind was asked with the header's namespace.
  expect(nsParam).toBe('team-a')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Both the breadcrumb and the card title render it — at least one must exist.
  expect(screen.getAllByText('Network Policies', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Security → Network Policies.
  expect(screen.getByText('Security')).toBeTruthy()
  // columns: name, policy types, rule counts, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Policy Types',
    'Ingress',
    'Egress',
    'Created',
  ])
  // row: policy types joined, ingress/egress counts.
  expect(screen.getByText('Ingress, Egress')).toBeTruthy()
  const nameCell = link.closest('tr')
  expect(nameCell?.textContent).toContain('1') // ingress: 1 rule
  expect(nameCell?.textContent).toContain('0') // egress: 0 rules
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  expect(nameCell?.textContent).not.toContain('2026-10-26T10:00:00Z')
  expect(nameCell?.textContent).toMatch(/2026/)
  // a row with no spec degrades to —, not a crash.
  const noSpec = screen.getByRole('button', { name: 'no-spec' })
  expect(noSpec.closest('tr')?.textContent).toContain('—')
})

test('list-cilium-section-shown-when-present', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
      HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [denyAll] }),
    ),
    http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', () =>
      HttpResponse.json({ kind: 'ciliumnetworkpolicies', cluster: 'prod', items: [cnp] }),
    ),
    http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', () =>
      HttpResponse.json({
        kind: 'ciliumclusterwidenetworkpolicies',
        cluster: 'prod',
        items: [ccnp],
      }),
    ),
  )
  selectTeamA()
  renderAt(<NetworkPolicyView />)

  await screen.findByRole('button', { name: 'deny-all' })
  const cnpLink = await screen.findByRole('button', { name: 'cnp' })
  const ccnpLink = screen.getByRole('button', { name: 'ccnp' })
  // ADR-0040: the URL is clean for all three kinds (R1) — identity is the ref.
  expect(window.location.search).toBe('')
  // the CRD has no policy_types: the Cilium row shows —.
  expect(cnpLink.closest('tr')?.textContent).toContain('—')
})

test('list-cilium-section-hidden-when-empty', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
      HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [denyAll] }),
    ),
  )
  selectTeamA()
  renderAt(<NetworkPolicyView />)

  await screen.findByRole('button', { name: 'deny-all' })
  expect(screen.queryAllByRole('button', { name: 'cnp' })).toHaveLength(0)
  expect(screen.queryAllByRole('button', { name: 'ccnp' })).toHaveLength(0)
  // the section title is absent, not an empty table.
  const tables = document.querySelectorAll('table')
  expect(tables.length).toBe(1)
})

test('list-no-cluster-state', async () => {
  const seen = capturePaths()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<NetworkPolicyView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

test('list-cilium-error-renders-when-rows-empty', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', () =>
      HttpResponse.json(
        { error: { code: 'CLUSTER_UNREACHABLE', message: 'cilium apiserver unreachable' } },
        { status: 502 },
      ),
    ),
  )
  selectTeamA()
  renderAt(<NetworkPolicyView />)

  // One Cilium query rejects and the sibling returns [] (no rows): the
  // section must still appear with its error line — a failure swallowed
  // because `ciliumRows.length === 0` is a silent outage.
  expect(
    await screen.findByText(
      /Error loading Cilium policies: CLUSTER_UNREACHABLE: cilium apiserver unreachable/,
    ),
  ).toBeTruthy()
  // no rows, no name buttons.
  expect(screen.queryAllByRole('button', { name: 'cnp' })).toHaveLength(0)
  expect(screen.queryAllByRole('button', { name: 'ccnp' })).toHaveLength(0)
})

test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on networkpolicies' } },
        { status: 403 },
      ),
    ),
  )
  selectTeamA()
  renderAt(<NetworkPolicyView />)

  expect(
    await screen.findByText(/Error loading network policies: RBAC_DENIED: list on networkpolicies/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'deny-all' })).toHaveLength(0)
})

// click-name-opens-the-ref-with-clean-url (R1 + registry-kind contract)
test('click-name-opens-the-ref-with-clean-url', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
      HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [denyAll] }),
    ),
    http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', () =>
      HttpResponse.json({ kind: 'ciliumnetworkpolicies', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', () =>
      HttpResponse.json({ kind: 'ciliumclusterwidenetworkpolicies', cluster: 'prod', items: [] }),
    ),
  )
  selectTeamA()
  renderAt(<NetworkPolicyView />)

  // Clicking the name button writes the active ref (kind = the API kind) and
  // navigates to the clean list route — the URL never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'deny-all' })
  await user.click(nameButton)

  expect(window.location.search).toBe('')
  // the view wrote the active ref: kind = the API kind, name, and namespace
  // (the registry-kind contract the dispatcher in App.tsx matches on).
  const ref = getActiveRef()
  expect(ref?.kind).toBe('NetworkPolicy')
  expect(ref?.name).toBe('deny-all')
  expect(ref?.namespace).toBe('team-a')
})
