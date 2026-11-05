import { act, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { Suspense } from 'react'
import { server } from './msw'
import { NetworkPolicyRoute } from '../src/App'
import ObjectRoute from '../src/components/ObjectRoute'
import OldDataRedirect from '../src/components/OldDataRedirect'
import SecretView from '../src/views/Security/Secret'
import SecretDataView from '../src/views/Security/SecretData'
import { useClusterStore } from '../src/store/cluster'
import { readRegistry } from '../src/lib/objectRef'

// ADR-0040 TICKET-07 (R7): the route-merge contract, tested end to end
// through the exact route wiring App.tsx uses (ProtectedRoute is skipped —
// its session-hint gate is covered in the routes tests; OldDataRedirect and
// ObjectRoute are the contract under test).
//
// ponytail: jsdom's location/history API is a no-op proxy (jsdom #2941):
// window.location never moves and history.back() does nothing, so these
// tests assert on the RENDERED view + the registry (the contract), not on
// the URL string. Real-browser navigation (replace semantics, back/forward)
// is proven by the e2e smoke (ui-smoke.spec.ts).

// Same KubeDataTable fake as the list tests: renders the real row mapping
// (children-as-render-fns included) so cell assertions test the view's
// `toRow` output, not DataTables' DOM.
vi.mock('../src/components/KubeDataTable', async () => {
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
                return <td key={col.title}>{node}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

// The secret list + the clean ObjectRoute route + the legacy /data redirect
// route — the exact App.tsx wiring for the migrated secret kind.
const renderApp = (initialEntry: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
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
          <Route
            path="/security/secret/data"
            element={<OldDataRedirect kind="secret" listRoute="/security/secret" />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// The detail's card title is <h5>Secret Data</h5>; the list's is
// <h5>Secret List</h5> — scope the query to the title.
const detailTitle = () => screen.queryByText('Secret Data', { selector: 'h5' })

beforeEach(() => {
  document.cookie = 'kd_session=1; path=/'
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
})

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const dbSecret = {
  metadata: {
    name: 'db-creds',
    namespace: 'team-a',
    creation_timestamp: '2026-10-01T10:00:00Z',
    resource_version: '4242',
    labels: { app: 'db' },
  },
  type: 'Opaque',
  data: { password: btoa('s3cr3t'), username: btoa('admin') },
}

const listSecret = {
  metadata: {
    name: 'db-creds',
    namespace: 'team-a',
    creation_timestamp: '2026-10-01T10:00:00Z',
  },
  type: 'Opaque',
  data: {},
}

describe('OldDataRedirect (R7): legacy /data URL → clean route detail', () => {
  test('old URL with ?name=/?namespace= lands on the clean route, ref origin link', async () => {
    server.use(
      http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
        const u = new URL(request.url)
        return HttpResponse.json({
          kind: 'secrets',
          cluster: 'prod',
          items: u.searchParams.get('name') ? [dbSecret] : [],
        })
      }),
    )

    renderApp('/security/secret/data?name=db-creds&namespace=team-a')

    // The redirect hydrated the ref; the detail renders from it — the
    // object's labels and data are on screen (R1: identity rides the ref,
    // never the URL).
    const inTable = async (text: string) =>
      (await screen.findAllByText(text)).some((el) => el.closest('table'))
    expect(await waitFor(() => detailTitle())).toBeTruthy()
    expect(await inTable('app')).toBe(true)
    expect(await inTable('db')).toBe(true)

    // The registry entry the redirect wrote: origin 'link', the identity
    // from the legacy params, and the active pointer on it.
    const reg = readRegistry()
    const active = sessionStorage.getItem('kd_object_active')
    expect(active).not.toBeNull()
    const ref = reg![active!]
    expect(ref.kind).toBe('secret')
    expect(ref.name).toBe('db-creds')
    expect(ref.namespace).toBe('team-a')
    expect(ref.origin).toBe('link')
  })

  test('old URL without ?namespace= falls back to the header namespace (4.1 parity)', async () => {
    server.use(
      http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
        const u = new URL(request.url)
        return HttpResponse.json({
          kind: 'secrets',
          cluster: 'prod',
          items: u.searchParams.get('name') ? [dbSecret] : [],
        })
      }),
    )

    renderApp('/security/secret/data?name=db-creds')

    // The detail renders — the namespace fell back to the header's
    // selectedNamespace, the way 4.1's view did.
    expect(await waitFor(() => detailTitle())).toBeTruthy()

    const reg = readRegistry()
    const ref = reg![sessionStorage.getItem('kd_object_active')!]
    expect(ref.namespace).toBe('team-a') // header's selectedNamespace
    expect(ref.origin).toBe('link')
  })

  test('redirect → detail; "back to list" returns to the list (no infinite loop)', async () => {
    server.use(
      http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
        const u = new URL(request.url)
        return HttpResponse.json({
          kind: 'secrets',
          cluster: 'prod',
          items: u.searchParams.get('name') ? [dbSecret] : [listSecret],
        })
      }),
    )

    renderApp('/security/secret/data?name=db-creds&namespace=team-a')
    // The redirect hydrated the ref; the detail renders from it.
    expect(await waitFor(() => detailTitle())).toBeTruthy()
    // The detail's back breadcrumb: clears the ref + navigates to the
    // clean route (same path), so the R6 dispatch re-renders the LIST —
    // the guard against a re-entry loop (the redirect only fires on the
    // /data path).
    act(() => {
      screen.getByRole('link', { name: 'Secrets' }).click()
    })

    // The active pointer was dropped by the breadcrumb and the route
    // re-rendered the list (the list's title is the positive proof).
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    expect(await waitFor(() => screen.queryByText('Secret List', { selector: 'h5' }))).toBeTruthy()
  })

  test('list → click row → detail → back (the clean contract the redirect must not break)', async () => {
    server.use(
      http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
        const u = new URL(request.url)
        return HttpResponse.json({
          kind: 'secrets',
          cluster: 'prod',
          items: u.searchParams.get('name') ? [dbSecret] : [listSecret],
        })
      }),
    )

    renderApp('/security/secret')
    // No active ref: ObjectRoute renders the LIST, and the row's name cell
    // is the openObject button (the R1/R6 path the redirect must not break).
    const rowButton = await screen.findByRole('button', { name: 'db-creds' })
    expect(detailTitle()).toBeNull()

    // openObject writes the ref with origin 'click' and navigates to the
    // clean route (same path — the seam bump drives the detail re-render).
    act(() => {
      rowButton.click()
    })
    // The detail renders (the seam bump drives the re-render on the same
    // clean route).
    expect(await waitFor(() => detailTitle())).toBeTruthy()
    const reg = readRegistry()
    const ref = reg![sessionStorage.getItem('kd_object_active')!]
    expect(ref.origin).toBe('click')
    expect(ref.name).toBe('db-creds')
    expect(ref.namespace).toBe('team-a')

    // Back (the in-app breadcrumb) drops the active pointer; the
    // same-path navigation re-reads the (now-null) ref and the R6
    // dispatch renders the list.
    act(() => {
      screen.getByRole('link', { name: 'Secrets' }).click()
    })
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    expect(await waitFor(() => screen.queryByText('Secret List', { selector: 'h5' }))).toBeTruthy()
  })
})

// ADR-0040 TICKET-03 dispatcher: one clean path renders list OR detail from
// the active ref. The regression below pins the same-route dispatch:
// openObject navigates to the SAME path, so the only re-render signal is
// the router's location object (a fresh instance per navigation). The
// window.location global has a stable identity — if `location` in the memo
// deps is that global (i.e. useLocation was forgotten), the memo stays
// inert and only a full page reload renders the detail.

const renderDispatcher = (initialEntry: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Suspense fallback={null}>
          <Routes>
            <Route path="/security/network-policy" element={<NetworkPolicyRoute />} />
          </Routes>
        </Suspense>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const demoNetpol = {
  metadata: { name: 'demo-netpol', namespace: 'team-a', creation_timestamp: '2026-10-01T10:00:00Z' },
  spec: {
    policy_types: ['Ingress'],
    ingress: [{ from: [{ pod_selector: {} }] }],
    pod_selector: { match_labels: { app: 'demo-app' } },
  },
}

describe('NetworkPolicyRoute (TICKET-03): list → click row → detail on the same clean route', () => {
  test('clicking the name button renders the detail without a page reload', async () => {
    server.use(
      http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
        HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [demoNetpol] }),
      ),
      http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', () =>
        HttpResponse.json({ kind: 'ciliumnetworkpolicies', cluster: 'prod', items: [] }),
      ),
      http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', () =>
        HttpResponse.json({ kind: 'ciliumclusterwidenetworkpolicies', cluster: 'prod', items: [] }),
      ),
    )

    renderDispatcher('/security/network-policy')

    // No active ref: the dispatcher renders the list; the name cell is the
    // openObject button.
    const rowButton = await screen.findByRole('button', { name: 'demo-netpol' })
    expect(screen.queryByText('Network Policy Data', { selector: 'h5' })).toBeNull()

    // openObject writes the ref (origin 'click') then navigates to the SAME
    // path — the router's location change must re-read the ref.
    act(() => {
      rowButton.click()
    })
    // findBy* (NOT waitFor-with-queryByText, which resolves on the first
    // falsy check): the detail is React.lazy inside App.tsx, so its first
    // import is async and the synchronous first check must retry.
    await screen.findByText('Network Policy Data', { selector: 'h5' }, { timeout: 8000 })

    const reg = readRegistry()
    const ref = reg![sessionStorage.getItem('kd_object_active')!]
    expect(ref.origin).toBe('click')
    expect(ref.kind).toBe('NetworkPolicy')
    expect(ref.name).toBe('demo-netpol')
    expect(ref.namespace).toBe('team-a')

    // The breadcrumb back-link drops the active pointer; the same-path
    // navigation re-reads the (now-null) ref and renders the list again.
    act(() => {
      screen.getByRole('link', { name: 'Network Policies' }).click()
    })
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    await screen.findByText('Network Policies', { selector: 'h5' }, { timeout: 4000 })
  })
})
