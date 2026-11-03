import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import NetworkPolicyDataView from '../../src/views/Security/NetworkPolicyData'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: identity arrives as props (the ref), never from the URL. Render
// the data view directly with its identity props at the clean route — the
// legacy /data route and the ObjectRoute detail both feed it the same props.
const renderAt = (
  name: string,
  kind: string,
  namespace: string,
  path = '/security/network-policy',
) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <NetworkPolicyDataView name={name} kind={kind} namespace={namespace} />
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

// full CRD to_dict shape: camelCase spec, cluster-scoped (namespace null).
const ccnp = {
  apiVersion: 'cilium.io/v2',
  kind: 'CiliumClusterwideNetworkPolicy',
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

test('detail-renders-policy-yaml', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({
        kind: 'networkpolicies',
        cluster: 'prod',
        items: [denyAll],
      })
    }),
  )
  selectTeamA()
  const { container } = renderAt('deny-all', 'NetworkPolicy', 'team-a')

  // R1: the URL never carries identity — it's the clean route.
  expect(window.location.search).toBe('')
  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('policy_types')
  })
  // exactly one resource URL, for kind NetworkPolicy, with name+namespace.
  expect(searchParams.get('name')).toBe('deny-all')
  expect(searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Security → Network Policies → name.
  expect(screen.getByText('Security')).toBeTruthy()
  const nameLink = screen.getByRole('link', { name: 'Network Policies' })
  expect(nameLink.getAttribute('href')).toBe('/security/network-policy')
  // metadata table: the item's metadata is shown. `deny-all` also appears
  // in the breadcrumb, so scope to the table row.
  expect((await screen.findAllByText('deny-all')).some((el) => el.closest('table'))).toBe(true)
  expect(screen.getByText('team-a')).toBeTruthy()
  expect(screen.getByText('NetworkPolicy')).toBeTruthy()
  // the full object is rendered as highlighted YAML containing the policy name.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('deny-all')
  expect(pre!.textContent).toContain('policy_types')
})

test('detail-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
      HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [] }),
    ),
  )
  selectTeamA()
  const { container } = renderAt('ghost', 'NetworkPolicy', 'team-a')

  // R1: the URL stays clean even for a not-found object.
  expect(window.location.search).toBe('')
  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No NetworkPolicy 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

test('detail-bad-kind-client-error', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectTeamA()
  const { container } = renderAt('deny-all', 'Foo', 'team-a')

  // closed enum: caught before any fetch. The error line must name the
  // invalid kind, and no `<pre>` (no YAML block) may render.
  expect(await screen.findByText("Error: unknown policy kind 'Foo'")).toBeTruthy()
  expect(container.querySelector('pre')).toBeNull()
  expect(seen).toHaveLength(0)
})

test('detail-clusterwide-omits-namespace', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({
        kind: 'ciliumclusterwidenetworkpolicies',
        cluster: 'prod',
        items: [ccnp],
      })
    }),
  )
  selectTeamA()
  // The clusterwide kind is cluster-scoped: no namespace (the ref carries
  // undefined, which the route maps to '').
  renderAt('ccnp', 'CiliumClusterwideNetworkPolicy', '')

  await screen.findByText('ccnp')
  // cluster-scoped kind: the fetched URL has no namespace param at all.
  expect(searchParams.get('namespace')).toBeNull()
  expect(searchParams.get('name')).toBe('ccnp')
})

test('detail-empty-kind-client-error', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectTeamA()
  const { container } = renderAt('deny-all', '', 'team-a')

  // valid name + empty kind: the enum check (NOT the name check) must
  // reject it — `detail-bad-kind-client-error` covers a bad kind only with
  // a valid kind string, so without this case the kind validation could be
  // deleted and every test would stay green. The error line names the
  // invalid kind, and no fetch is made.
  expect(await screen.findByText("Error: unknown policy kind ''")).toBeTruthy()
  expect(container.querySelector('pre')).toBeNull()
  expect(seen).toHaveLength(0)
})

test('detail-missing-name-error', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectTeamA()
  renderAt('', 'NetworkPolicy', 'team-a')

  expect(await screen.findByText('Error: policy name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0)
})
