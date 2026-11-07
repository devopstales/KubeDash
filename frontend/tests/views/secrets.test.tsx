import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import SecretView from '../../src/views/Security/Secret'
import SecretDataView, { secretLanguage } from '../../src/views/Security/SecretData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/security/secret') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
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
      [token]: { kind: 'secret', name, namespace, ts: Date.now(), origin: 'click' },
    }),
  )
  sessionStorage.setItem('kd_object_active', token)
}

// Render the data view directly (no ObjectRoute) for view-level state
// assertions; the legacy /data route and the ObjectRoute detail both feed it
// the same props.
const renderDataAt = (name: string, namespace: string, path = '/security/secret/data') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <SecretDataView name={name} namespace={namespace} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const dbSecret = {
  metadata: {
    name: 'db-cred',
    namespace: 'team-a',
    creation_timestamp: '2026-10-01T10:00:00Z',
    resource_version: '4242',
    labels: { app: 'db' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"Secret"}',
      owner: 'platform',
    },
  },
  type: 'Opaque',
  data: { password: btoa('s3cr3t'), username: btoa('admin') },
}

const selectTeamA = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

test('lists-secrets-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'secrets',
        cluster: 'prod',
        items: [
          { metadata: dbSecret.metadata, type: dbSecret.type },
          { metadata: { name: 'untyped', namespace: 'team-a' } },
        ],
      })
    }),
  )
  selectTeamA()
  renderAt(<SecretView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'db-cred' })
  expect(requested).toBe('team-a')
  expect(screen.getByText('Secret List')).toBeTruthy()
  expect(screen.getByText('Security')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Type'])
  // no `?selected=` (R9) and no identity anywhere in the list route.
  expect(window.location.search).toBe('')
  expect(nameButton.closest('tr')?.textContent).not.toContain('?selected=')
  expect(screen.getByText('Opaque')).toBeTruthy()
  expect(screen.getByText('N/A')).toBeTruthy()
  // the decoded value stays out of the list.
  expect(screen.queryByText('s3cr3t')).toBeNull()
})

test('bolds-the-opened-secret-from-the-active-ref', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', () =>
      HttpResponse.json({
        kind: 'secrets',
        cluster: 'prod',
        items: [dbSecret, { metadata: { name: 'other' }, type: 'Opaque' }],
      }),
    ),
  )
  selectTeamA()
  // The active ref (a click on db-cred in team-a) is what bolds the row now —
  // never a `?selected=` param (R9). Render the list view directly (not
  // through ObjectRoute, which would swap in the detail for the seeded ref).
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  seedActiveRef('db-cred', 'team-a')
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/security/secret']}>
        <SecretView />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  const opened = await screen.findByRole('button', { name: 'db-cred' })
  expect(opened.className).toContain('fw-bold')
  expect(opened.getAttribute('aria-current')).toBe('true')
  const other = screen.getByRole('button', { name: 'other' })
  expect(other.className).not.toContain('fw-bold')
  expect(other.getAttribute('aria-current')).toBeNull()
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderAt(<SecretView />)

  expect(await screen.findByText('No secrets found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on secrets' } },
        { status: 403 },
      ),
    ),
  )
  selectTeamA()
  renderAt(<SecretView />)

  expect(
    await screen.findByText(/Error loading secrets: RBAC_DENIED: list on secrets/),
  ).toBeTruthy()
})

test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  let query = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      query = new URL(request.url).search
      return HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [dbSecret] })
    }),
  )
  selectTeamA()
  renderAt(<SecretView />)

  // Clicking the name button opens the detail via openObject; the URL never
  // carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'db-cred' })
  await user.click(nameButton)

  expect(await screen.findByText('Secret Data')).toBeTruthy()
  // R1: the URL stays clean — no `?selected=` (R9) and no identity.
  expect(window.location.search).toBe('')
  // the detail read is for the secret's namespace (the ref carries it).
  expect(query).toBe('?namespace=team-a&name=db-cred')
})

test('shows-secret-data-hidden-until-revealed', async () => {
  let query = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      query = new URL(request.url).search
      return HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [dbSecret] })
    }),
  )
  selectTeamA()
  // ADR-0040: identity arrives as props (the ref), never from the URL.
  renderDataAt('db-cred', 'team-a')

  expect(await screen.findByText('Secret Data')).toBeTruthy()
  expect(await screen.findByText('4242')).toBeTruthy()
  expect(query).toBe('?namespace=team-a&name=db-cred')
  expect(screen.getByRole('link', { name: 'Secrets' }).getAttribute('href')).toBe(
    '/security/secret',
  )
  expect(screen.getByText('Opaque')).toBeTruthy()
  expect(screen.getByText('2026-10-01T10:00:00Z')).toBeTruthy()
  expect(screen.getByText('owner')).toBeTruthy()
  expect(screen.getByText('platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByText('app')).toBeTruthy()

  expect(document.body.textContent).not.toContain('s3cr3t')
  fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
  expect(document.body.textContent).toContain('s3cr3t')
  expect(document.body.textContent).not.toContain('admin')
  fireEvent.click(screen.getByRole('button', { name: 'Hide password' }))
  expect(document.body.textContent).not.toContain('s3cr3t')
})

test('secret-data-reports-a-missing-secret', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', () =>
      HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [] }),
    ),
  )
  selectTeamA()
  renderDataAt('gone', 'team-a')

  expect(
    await screen.findByText(/Error loading secret: Secret 'gone' not found in namespace 'team-a'/),
  ).toBeTruthy()
})

// R8: the detail's namespace comes from the ref (authoritatively), never from
// the header store. Header on `default`, ref for `team-a` → the read is for
// `team-a`.
test('secret-data-reads-the-ref-namespace-not-the-header', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [dbSecret] })
    }),
  )
  // header selectedNamespace = 'default' (NOT team-a)
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'default' })
  // the ref (and the detail's namespace prop) is team-a
  renderDataAt('db-cred', 'team-a')

  expect(await screen.findByText('Secret Data')).toBeTruthy()
  expect(requested).toBe('team-a')
  // the namespace row shows the ref's namespace, not the header's (`default`
  // must not appear as the namespace value).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
})

test('secret-language-matches-4-1', () => {
  expect(secretLanguage('config.json', '{"a":1}')).toBe('json')
  expect(secretLanguage('app.yaml', 'kind: Secret')).toBe('yaml')
  expect(secretLanguage('note', '<note></note>')).toBe('xml')
  expect(secretLanguage('startup.sh', 'const x = 1')).toBe('javascript')
  expect(secretLanguage('ca.crt', '-----BEGIN CERTIFICATE-----\nMII')).toBe('text')
  expect(secretLanguage('password', 's3cr3t')).toBe('text')
})

test('revealed-secret-uses-the-an-old-hope-block', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', () =>
      HttpResponse.json({
        kind: 'secrets',
        cluster: 'prod',
        items: [
          {
            ...dbSecret,
            data: {
              'ca.crt': btoa('-----BEGIN CERTIFICATE-----\nMII'),
              'config.json': btoa('{"user":"admin"}'),
            },
          },
        ],
      }),
    ),
  )
  selectTeamA()
  renderDataAt('db-cred', 'team-a')

  expect(await screen.findByText('Secret Data')).toBeTruthy()
  fireEvent.click(await screen.findByRole('button', { name: 'Show ca.crt' }))
  fireEvent.click(screen.getByRole('button', { name: 'Show config.json' }))
  const code = Array.from(document.querySelectorAll('code')).map((el) => el.textContent ?? '')
  const cert = Array.from(document.querySelectorAll('code')).find((el) =>
    (el.textContent ?? '').includes('BEGIN CERTIFICATE'),
  )
  expect(cert).toBeTruthy()
  const certColors = Array.from(cert!.querySelectorAll('span'))
    .map((el) => el.style.color)
    .filter((color) => color !== '')
  expect(new Set(certColors).size).toBe(0)
  expect(code.some((text) => text.includes('"user"'))).toBe(true)
  const blocks = document.querySelectorAll('pre')
  expect(blocks.length).toBeGreaterThan(0)
  expect(
    Array.from(blocks).some((block) => (block as HTMLElement).style.backgroundColor !== ''),
  ).toBe(true)
})

test('secret-data-requires-a-name', async () => {
  selectTeamA()
  // An empty name (the legacy /data route's missing ?name=) is a client
  // error; no fetch is made.
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderDataAt('', 'team-a')

  expect(await screen.findByText('Error: Secret name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
