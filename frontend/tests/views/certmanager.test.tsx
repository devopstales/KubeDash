import { useEffect, useMemo, useReducer, useRef } from 'react'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import type { HttpHandler } from 'msw'
import { server } from '../msw'
import { getActiveRef } from '../../src/lib/objectRef'
import { registerNavigate } from '../../src/components/ObjectRoute'
import CertManagerView from '../../src/views/Network/CertManager'
import CertManagerDataView from '../../src/views/Network/CertManagerData'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as services.test.tsx: renders the real row mapping
// (children-as-render-fns included) so cell assertions test the view's
// `toRow` output, not DataTables' DOM. The factory is async: a hoisted mock
// may not touch module-scope consts, so react is imported inline.
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

// Mirrors App.tsx's CertManagerRoute dispatcher (the test does not import
// the whole app): the clean list route renders the 4-tab list, or the
// ref-matched object detail for the four cert-manager kinds.
const CertManagerTestRoute = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [, bump] = useReducer((c: number) => c + 1, 0)
  const ref = useMemo(() => getActiveRef(), [location, bump])
  const isKind =
    ref !== null &&
    (ref.kind === 'clusterissuer' ||
      ref.kind === 'issuer' ||
      ref.kind === 'certificaterequest' ||
      ref.kind === 'certificate')
  const seamRef = useRef(navigate)
  seamRef.current = navigate
  useEffect(() => {
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])
  if (!isKind) return <CertManagerView />
  return <CertManagerDataView name={ref!.name} kind={ref!.kind} namespace={ref!.namespace ?? ''} />
}

// ADR-0040: render through the dispatcher route so the detail is ref-driven
// (name + kind + namespace from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/network/cert-manager') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/network/cert-manager" element={<CertManagerTestRoute />} />
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

// cert-manager.io/v1 CRD items (full custom-object shape, camelCase).
const clusterIssuer = {
  metadata: { name: 'ca-issuer', creation_timestamp: '2026-01-01T00:00:00Z' },
  spec: {
    acme: {
      email: 'ca@example.com',
      server: 'https://acme-v02.api.letsencrypt.org',
      solvers: [{ http01: { ingress: { class: 'nginx' } } }],
    },
  },
  status: { conditions: [{ type: 'Ready', status: 'True', reason: 'Ready' }] },
}

const issuer = {
  metadata: { name: 'web-issuer', namespace: 'team-a', creation_timestamp: '2026-01-02T00:00:00Z' },
  spec: {
    acme: {
      email: 'it@example.com',
      server: 'https://acme-staging-v02.api.letsencrypt.org',
      solvers: [{ http01: {} }, { dns01: { provider: 'route53' } }],
    },
  },
  status: { conditions: [{ type: 'Ready', status: 'True', reason: 'Ready' }] },
}

const certRequest = {
  metadata: {
    name: 'cr-1',
    namespace: 'team-a',
    creation_timestamp: '2026-01-03T00:00:00Z',
    ownerReferences: [{ kind: 'Certificate', name: 'tls-cert' }],
  },
  spec: { issuerRef: { name: 'web-issuer', kind: 'Issuer' } },
  status: { conditions: [{ type: 'Ready', status: 'False', reason: 'Denied' }] },
}

// The Issuer cell deep target is a ClusterIssuer — the tab-switch goes to
// the Cluster Issuer tab, not the Issuer tab.
const certRequestCluster = {
  metadata: { name: 'cr-2', namespace: 'team-a', creation_timestamp: '2026-01-04T00:00:00Z' },
  spec: { issuerRef: { name: 'ca-issuer', kind: 'ClusterIssuer' } },
}

const certificate = {
  metadata: {
    name: 'tls-cert',
    namespace: 'team-a',
    creation_timestamp: '2026-01-05T00:00:00Z',
    ownerReferences: [{ kind: 'Ingress', name: 'web-ing' }],
  },
  spec: { secretName: 'tls-secret', dnsNames: ['web.example.com'] },
  status: { notAfter: '2027-01-01T00:00:00Z', conditions: [{ type: 'Ready', status: 'True', reason: 'Ready' }] },
}

// One handler per the four registry resources; records every request's
// namespace param so the cluster-scoped / namespaced split is assertable.
const serve = (items: Record<string, unknown[]>) => {
  const requests: { resource: string; name: string | null; namespace: string | null }[] = []
  const handlers: HttpHandler[] = Object.entries(items).map(([resource, list]) =>
    http.get(`*/api/v1/clusters/1/resources/${resource}`, ({ request }) => {
      const u = new URL(request.url)
      requests.push({
        resource,
        name: u.searchParams.get('name'),
        namespace: u.searchParams.get('namespace'),
      })
      return HttpResponse.json({ kind: resource, items: list })
    }),
  )
  return { requests, handlers }
}

const allItems = () => ({
  clusterissuers: [clusterIssuer],
  issuers: [issuer],
  certificaterequests: [certRequest, certRequestCluster],
  certificates: [certificate],
})

// list-renders-4tabs: the card title is EXACTLY "Cert-Manager Objects"; the
// four 4.1 tabs (Cluster Issuer / Issuer / Certificate Request /
// Certificates); ALL four fetch on mount (CTabPanel keeps every panel
// mounted); the cluster-scoped clusterissuers fetch carries NO namespace
// param, the three namespaced kinds carry the selected namespace.
test('list-renders-4tabs', async () => {
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  // The breadcrumb active item AND the card title are both "Cert-Manager
  // Objects" (the e2e-smoke contract) — two occurrences, both exact.
  expect(screen.getAllByText('Cert-Manager Objects').map((el) => el.textContent)).toEqual([
    'Cert-Manager Objects',
    'Cert-Manager Objects',
  ])
  expect(screen.getByText('Network')).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Cluster Issuer' })).toHaveAttribute(
    'aria-selected',
    'true',
  )
  expect(screen.getByRole('tab', { name: 'Issuer' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Certificate Request' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Certificates' })).toBeTruthy()

  await screen.findByRole('button', { name: 'ca-issuer' })
  const byResource = new Map(requests.map((r) => [r.resource, r.namespace]))
  expect(byResource.get('clusterissuers')).toBeNull() // cluster-scoped
  expect(byResource.get('issuers')).toBe('team-a')
  expect(byResource.get('certificaterequests')).toBe('team-a')
  expect(byResource.get('certificates')).toBe('team-a')
})

// list-status-badge: the LAST status.conditions[] entry's `reason` in a
// badge — green when its status === "True", red otherwise (the 4.1 mapping).
test('list-status-badge', async () => {
  const { handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  const okRow = (await screen.findByRole('button', { name: 'ca-issuer' })).closest('tr')!
  expect(within(okRow).getByText('Ready').className).toContain('badge-success')

  const deniedRow = screen.getByRole('button', { name: 'cr-1' }).closest('tr')!
  expect(within(deniedRow).getByText('Denied').className).toContain('badge-danger')
})

// list-name-links: the Name cell is an openObject button (ADR-0040) —
// clicking opens the per-type data detail on the CLEAN route (the 5.0 form
// of 4.1's /data?type=&name=&namespace= link); the detail fetches the
// single object by ?name= + ?namespace= (the namespaced kinds).
test('list-name-links', async () => {
  const user = userEvent.setup()
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  await user.click(await screen.findByRole('button', { name: 'web-issuer' }))

  // The per-type data card title (the 5.0 per-type shape).
  expect(await screen.findByText('Cert-Manager Issuer')).toBeTruthy()
  expect(within(screen.getByText('Name:').closest('tr') as HTMLElement).getByText('web-issuer')).toBeTruthy()
  expect(window.location.search).toBe('')
  // The single-object fetch: ?name= + ?namespace= on the same resource.
  expect(
    requests.some(
      (r) => r.resource === 'issuers' && r.name === 'web-issuer' && r.namespace === 'team-a',
    ),
  ).toBe(true)
})

// list-issuer-tab-switch: the Certificate Request Issuer cell is 4.1's
// goToTab re-implementation — an IN-PAGE tab-switch (to the matching Issuer /
// Cluster Issuer tab) + row-highlight (the target row's bolded name cell);
// NOT a navigation (the URL never changes).
test('list-issuer-tab-switch', async () => {
  const user = userEvent.setup()
  const { handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  await user.click(await screen.findByRole('tab', { name: 'Certificate Request' }))
  // The Issuer cell renders once the certificate-requests query settles.
  await user.click(await screen.findByRole('button', { name: 'Issuer/web-issuer' }))

  // The tab switched to Issuer; the target row's name cell is bolded (the
  // issuers query settles in the same window — poll for the name cell).
  expect(screen.getByRole('tab', { name: 'Issuer' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tab', { name: 'Certificate Request' })).toHaveAttribute(
    'aria-selected',
    'false',
  )
  const highlighted = await screen.findByRole('button', { name: 'web-issuer' })
  expect(highlighted.className).toContain('fw-bold')
  // No navigation: the LIST is still rendered (no detail opened).
  expect(screen.getAllByText('Cert-Manager Objects')).toHaveLength(2)
  expect(screen.queryByText('Cert-Manager Issuer')).toBeNull()
})

// list-certificate-secret-deep-link: the Certificates Secret cell deep-links
// to the LANDED Secret data view (/security/secret/data?name=&namespace=);
// the Owner cell links to the Ingress list ONLY when kind is Ingress (the
// "deep-link to landed kinds" pattern).
test('list-certificate-secret-deep-link', async () => {
  const { handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  const secretLink = await screen.findByRole('link', { name: 'tls-secret' })
  expect(secretLink.getAttribute('href')).toBe(
    '/security/secret/data?name=tls-secret&namespace=team-a',
  )
  const ownerLink = screen.getByRole('link', { name: 'Ingress/web-ing' })
  expect(ownerLink.getAttribute('href')).toBe('/network/ingress')
})

// list-no-cluster-state: no cluster selected — no cert-manager fetch at all.
test('list-no-cluster-state', async () => {
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  renderAt(<CertManagerView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(requests).toHaveLength(0)
})

// list-empty-tabs: every empty tab renders its pinned first-class empty
// state (CRD-absent is the same shape — the seam returns []).
test('list-empty-tabs', async () => {
  const { handlers } = serve({
    clusterissuers: [],
    issuers: [],
    certificaterequests: [],
    certificates: [],
  })
  server.use(...handlers)
  selectTeamA()
  renderAt(<CertManagerView />)

  expect(await screen.findByText('No cluster issuers found')).toBeTruthy()
  expect(screen.getByText('No issuers found')).toBeTruthy()
  expect(screen.getByText('No certificate requests found')).toBeTruthy()
  expect(screen.getByText('No certificates found')).toBeTruthy()
})

// list-error-state: an API error renders the red error line with the pinned
// prefix.
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterissuers', () =>
      HttpResponse.json({ error: { code: 'InternalError', message: 'boom' } }, { status: 500 }),
    ),
    ...serve({
      issuers: [issuer],
      certificaterequests: [certRequest, certRequestCluster],
      certificates: [certificate],
    }).handlers,
  )
  selectTeamA()
  renderAt(<CertManagerView />)

  expect(
    await screen.findByText('Error loading cert-manager objects: InternalError: boom'),
  ).toBeTruthy()
})
