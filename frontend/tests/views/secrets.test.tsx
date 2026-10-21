import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import SecretView from '../../src/views/Security/Secret'
import SecretDataView, { secretLanguage } from '../../src/views/Security/SecretData'
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

const renderAt = (ui: ReactElement, path = '/') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
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

  expect(await screen.findByRole('link', { name: 'db-cred' })).toBeTruthy()
  expect(requested).toBe('team-a')
  expect(screen.getByText('Secret List')).toBeTruthy()
  expect(screen.getByText('Security')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Name', 'Type'])
  expect(screen.getByRole('link', { name: 'db-cred' }).getAttribute('href')).toBe(
    '/security/secret/data?name=db-cred&namespace=team-a',
  )
  expect(screen.getByText('Opaque')).toBeTruthy()
  expect(screen.getByText('N/A')).toBeTruthy()
  expect(screen.queryByText('s3cr3t')).toBeNull()
})

test('highlights-the-selected-secret', async () => {
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
  renderAt(<SecretView />, '/security/secret?selected=db-cred')

  const link = await screen.findByRole('link', { name: 'db-cred' })
  expect(link.getAttribute('aria-current')).toBe('true')
  expect(screen.getByRole('link', { name: 'other' }).getAttribute('aria-current')).toBeNull()
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

test('shows-secret-data-hidden-until-revealed', async () => {
  let query = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/secrets', ({ request }) => {
      query = new URL(request.url).search
      return HttpResponse.json({ kind: 'secrets', cluster: 'prod', items: [dbSecret] })
    }),
  )
  selectTeamA()
  renderAt(<SecretDataView />, '/security/secret/data?name=db-cred&namespace=team-a')

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
  renderAt(<SecretDataView />, '/security/secret/data?name=gone&namespace=team-a')

  expect(
    await screen.findByText(/Error loading secret: Secret 'gone' not found in namespace 'team-a'/),
  ).toBeTruthy()
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
  renderAt(<SecretDataView />, '/security/secret/data?name=db-cred&namespace=team-a')

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
  renderAt(<SecretDataView />, '/security/secret/data')

  expect(await screen.findByText('Error: Secret name not provided')).toBeTruthy()
})
