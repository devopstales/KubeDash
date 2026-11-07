import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import CertManagerDataView from '../../src/views/Network/CertManagerData'
import { useClusterStore } from '../../src/store/cluster'

// Render the data view directly (no dispatcher) for view-level state
// assertions; the dispatcher and the legacy /data redirect both feed it the
// same props (kind + name + namespace).
const renderDataAt = (kind: string, name: string, namespace = 'team-a') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/cert-manager/data']}>
        <CertManagerDataView name={name} kind={kind} namespace={namespace} />
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
    selectedNamespace: 'default',
  })

// Row scoping for the metadata CTable: the a11y tree exposes no row name
// from cell contents, so scope through the th label's closest <tr>.
const row = (label: string) => within(screen.getByText(`${label}:`).closest('tr') as HTMLElement)

// cert-manager.io/v1 CRD items (full custom-object shape, camelCase).
const caIssuer = {
  metadata: { name: 'ca-issuer', creation_timestamp: '2026-01-01T00:00:00Z' },
  spec: {
    acme: {
      email: 'ca@example.com',
      server: 'https://acme-v02.api.letsencrypt.org',
      solvers: [{ http01: { ingress: { class: 'nginx' } } }],
    },
  },
  status: {
    conditions: [{ type: 'Ready', status: 'True', reason: 'Ready', message: '"The issuer is online"' }],
  },
}

const webIssuer = {
  metadata: { name: 'web-issuer', namespace: 'team-a', creation_timestamp: '2026-01-02T00:00:00Z' },
  spec: { ca: { secretName: 'ca-secret' } },
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
  status: { conditions: [{ type: 'Ready', status: 'False', reason: 'Denied', message: 'denied by acme' }] },
}

const tlsCert = {
  metadata: {
    name: 'tls-cert',
    namespace: 'team-a',
    creation_timestamp: '2026-01-05T00:00:00Z',
    ownerReferences: [{ kind: 'Ingress', name: 'web-ing' }],
  },
  spec: { secretName: 'tls-secret', dnsNames: ['web.example.com', 'api.example.com'] },
  status: { notAfter: '2027-01-01T00:00:00Z', conditions: [{ type: 'Ready', status: 'True', reason: 'Ready' }] },
}

const serveOne = (resource: string, item: unknown, track?: (u: URL) => void) =>
  http.get(`*/api/v1/clusters/1/resources/${resource}`, ({ request }) => {
    const u = new URL(request.url)
    track?.(u)
    return HttpResponse.json({ kind: resource, items: item ? [item] : [] })
  })

// data-cluster-issuer-rows: the per-type row set (Name / Status / Status
// message / Issuer Type / Issuer Data); the cluster-scoped fetch carries
// NO namespace param; the message's quotes are stripped (the 4.1 helper
// behavior); the full-object JSON block is present.
test('data-cluster-issuer-rows', async () => {
  const seen: URL[] = []
  server.use(serveOne('clusterissuers', caIssuer, (u) => seen.push(u)))
  selectTeamA()
  renderDataAt('clusterissuer', 'ca-issuer')

  expect(await screen.findByText('Cert-Manager Cluster Issuer')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  // Cluster-scoped: the single ?name= request carries NO namespace.
  expect(seen).toHaveLength(1)
  expect(seen[0].searchParams.get('name')).toBe('ca-issuer')
  expect(seen[0].searchParams.get('namespace')).toBeNull()

  expect(row('Name').getByText('ca-issuer')).toBeTruthy()
  expect(row('Status').getByText('Ready').className).toContain(
    'badge-success',
  )
  // The 4.1 GenerateIssuerData quote-strip.
  expect(row('Status message').getByText('The issuer is online')).toBeTruthy()
  // The 4.1 type classification (selfSigned < ca < acme < vault).
  expect(row('Issuer Type').getByText('ACME')).toBeTruthy()
  // The 4.1 issuer_data render (the solver scan: http01 challenge).
  expect(
    row('Issuer Data').getByText(
      'email: ca@example.com, server: https://acme-v02.api.letsencrypt.org, challenges: http01',
    ),
  ).toBeTruthy()
  // The full-object JSON block.
  expect(document.body.textContent).toContain('"acme"')
})

// data-issuer-rows: the Issuer row set has the Issuer Data row but NO Issuer
// Type row (the 4.1 per-object_type shape); the fetch carries ?name= +
// ?namespace=.
test('data-issuer-rows', async () => {
  const seen: URL[] = []
  server.use(serveOne('issuers', webIssuer, (u) => seen.push(u)))
  selectTeamA()
  renderDataAt('issuer', 'web-issuer')

  expect(await screen.findByText('Cert-Manager Issuer')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(seen[0].searchParams.get('name')).toBe('web-issuer')
  expect(seen[0].searchParams.get('namespace')).toBe('team-a')
  expect(row('Name').getByText('web-issuer')).toBeTruthy()
  // The CA issuer_data form.
  expect(row('Issuer Data').getByText('secret: ca-secret')).toBeTruthy()
  // No Issuer Type row for Issuer (only Cluster Issuer has it).
  expect(screen.queryByText('Issuer Type:')).toBeNull()
})

// data-certificate-request-rows: the Issuer row (kind/name of spec.issuerRef)
// + the Owner row (the last ownerReference, kind/name).
test('data-certificate-request-rows', async () => {
  server.use(serveOne('certificaterequests', certRequest))
  selectTeamA()
  renderDataAt('certificaterequest', 'cr-1')

  expect(await screen.findByText('Cert-Manager Certificate Request')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('Issuer').getByText('Issuer/web-issuer')).toBeTruthy()
  expect(row('Owner').getByText('Certificate/tls-cert')).toBeTruthy()
  expect(
    row('Status').getByText('Denied').className,
  ).toContain('badge-danger')
  expect(row('Status message').getByText('denied by acme')).toBeTruthy()
})

// data-certificate-rows: Validity Not After / Certificate (the deep-link to
// the LANDED Secret data view) / Hostnames (one per line, the 4.1 render).
test('data-certificate-rows', async () => {
  server.use(serveOne('certificates', tlsCert))
  selectTeamA()
  renderDataAt('certificate', 'tls-cert')

  expect(await screen.findByText('Cert-Manager Certificate')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(
    row('Validity Not After').getByText(
      '2027-01-01T00:00:00Z',
    ),
  ).toBeTruthy()
  const link = row('Certificate').getByRole('link', { name: 'tls-secret' })
  expect(link.getAttribute('href')).toBe(
    '/security/secret/data?name=tls-secret&namespace=team-a',
  )
  // Both hostnames rendered (one per line).
  expect(row('Hostnames').getByText(/web\.example\.com/)).toBeTruthy()
  expect(row('Hostnames').getByText(/api\.example\.com/)).toBeTruthy()
})

// data-not-found-state: a ?name= miss (items: []) is the pinned muted state
// (never an error style; the CRD-absent state is the same shape).
test('data-not-found-state', async () => {
  server.use(serveOne('clusterissuers', null))
  selectTeamA()
  renderDataAt('clusterissuer', 'ghost')

  const notFound = await screen.findByText("No Cluster Issuer 'ghost' found")
  expect(notFound.className).toContain('text-muted')
  expect(screen.queryByText(/Error/)).toBeNull()
})

// data-missing-name: no name -> the pinned error line (red), no fetch.
test('data-missing-name', async () => {
  let calls = 0
  server.use(
    http.get('*/api/v1/clusters/1/resources/issuers', () => {
      calls += 1
      return HttpResponse.json({ kind: 'issuers', items: [webIssuer] })
    }),
  )
  selectTeamA()
  renderDataAt('issuer', '')

  const el = await screen.findByText('Error: issuer name not provided')
  expect(el.className).toContain('text-danger')
  expect(calls).toBe(0)
})

// data-unknown-kind: a kind outside the closed set renders the error line
// with NO network hit (the query is disabled before the fetch).
test('data-unknown-kind', async () => {
  let calls = 0
  server.use(
    http.get('*/api/v1/clusters/1/resources/*', () => {
      calls += 1
      return HttpResponse.json({ items: [] })
    }),
  )
  selectTeamA()
  renderDataAt('nonsense', 'x')

  const el = await screen.findByText('Error: unknown cert-manager kind: nonsense')
  expect(el.className).toContain('text-danger')
  expect(calls).toBe(0)
})

// data-error-state: an API error renders the red error line (the pinned
// prefix + the API error).
test('data-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterissuers', () =>
      HttpResponse.json(
        { error: { code: 'InternalError', message: 'boom' } },
        { status: 500 },
      ),
    ),
  )
  selectTeamA()
  renderDataAt('clusterissuer', 'ca-issuer')

  const el = await screen.findByText('Error loading cluster issuer: InternalError: boom')
  expect(el.className).toContain('text-danger')
})

// data-no-cluster-state: no cluster selected — the pinned no-cluster line.
test('data-no-cluster-state', async () => {
  server.use(serveOne('clusterissuers', caIssuer))
  renderDataAt('clusterissuer', 'ca-issuer')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
})
