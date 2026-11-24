import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import DeploymentDataView from '../../src/views/Workload/DeploymentData'
import DeploymentsWorkloadView from '../../src/views/Workload/Deployments'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/workload/deployments') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/workload/deployments"
            element={
              <ObjectRoute
                kind="deployment"
                listRoute="/workload/deployments"
                list={<DeploymentsWorkloadView />}
                detail={(p) => (
                  <DeploymentDataView name={p.name} namespace={p.namespace ?? ''} />
                )}
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
      [token]: { kind: 'deployment', name, namespace, ts: Date.now(), origin: 'click' },
    }),
  )
  sessionStorage.setItem('kd_object_active', token)
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case (a generated apps/v1 model),
// spec/status intact. The template spec carries the full Related Resources
// surface (image-pull secrets, service account, env + volume secrets,
// configmap + PVC volumes).
const webDeployment = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { app: 'web' },
    annotations: {},
  },
  spec: {
    replicas: 3,
    selector: { match_labels: { tier: 'frontend' } },
    template: {
      spec: {
        service_account_name: 'web-sa',
        security_context: { run_as_non_root: true },
        containers: [
          {
            name: 'web',
            image: 'nginx:1.25',
            env: [
              { name: 'PORT', value: '8080' },
              { name: 'DB', value_from: { secret_key_ref: { name: 'db-secret' } } },
            ],
          },
        ],
        init_containers: [{ name: 'init', image: 'busybox' }],
        volumes: [
          { config_map: { name: 'web-cm' } },
          { secret: { secret_name: 'tls-secret' } },
          { persistent_volume_claim: { claim_name: 'web-pvc' } },
        ],
        image_pull_secrets: [{ name: 'registry-pull' }],
      },
    },
  },
  status: {
    replicas: 3,
    ready_replicas: 2,
    updated_replicas: 3,
    conditions: [
      {
        type: 'Available',
        reason: 'MinimumReplicasAvailable',
        message: 'Deployment has minimum availability.',
        last_transition_time: '2026-01-02T03:04:06Z',
      },
    ],
  },
}

const serveDeployment = (items: unknown[]) =>
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', () =>
      HttpResponse.json({ kind: 'deployments', cluster: 'prod', items }),
    ),
  )

// deployment-data-renders-detail
test('data-renders-detail', async () => {
  const fetched: string[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/deployments', ({ request }) => {
      fetched.push(new URL(request.url).href)
      return HttpResponse.json({
        kind: 'deployments',
        cluster: 'prod',
        items: [webDeployment],
      })
    }),
  )
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  // Wait for the fetch to land before reading what the view asked for. The
  // highlighter splits tokens across <code class="hljs-*"> spans, so
  // findByText cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('"replicas"')
  })
  // single read: EXACTLY one ?name=&namespace= fetch (no 4.1
  // list-then-filter); the namespace is REQUIRED for the lookup.
  expect(fetched).toHaveLength(1)
  const url = new URL(fetched[0])
  expect(url.searchParams.get('name')).toBe('web')
  expect(url.searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Workloads → Deployments List → name.
  const listLink = screen.getByRole('link', { name: 'Deployments List' })
  expect(listLink.getAttribute('href')).toBe('/workload/deployments')
  // metadata CTable: the item's fields are shown. The same values repeat in
  // the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('3')).toBe(true) // Replicas: spec.replicas, PLAIN TEXT (deviation 9)
  // labels + selectors sub-tables render (distinct keys in the fixture);
  // annotations are empty → the pinned empty state.
  expect(await inTable('app')).toBe(true) // label key
  expect(await inTable('tier')).toBe(true) // selector key
  expect(await inTable('frontend')).toBe(true) // selector value
  expect(screen.getByText('No annotations')).toBeTruthy()
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"replicas": 3')
})

// deployment-data-containers-template-only
test('data-containers-template-only', async () => {
  serveDeployment([webDeployment])
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('nginx:1.25')
  })
  // The Containers tab renders the TEMPLATE's name + image only (no live
  // state — this is the deployment's template, not a running pod).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('nginx:1.25')).toBe(true)
  expect(await inTable('busybox')).toBe(true) // init container image
  expect(await inTable('init')).toBe(true) // init container name
  // ObjectTabs keeps every panel mounted, so scope the header check to the
  // Containers table itself: Name / Image only (NO State / Restarts columns
  // — the live state belongs to a running pod, not the template).
  const containersTable = screen
    .getAllByText('Containers')
    .find((el) => el.closest('table'))!
    .closest('table')!
  const headers = Array.from(containersTable.querySelectorAll('thead th')).map(
    (th) => th.textContent,
  )
  expect(headers).toEqual(['Name', 'Image'])
})

// deployment-data-variables-literal-only
test('data-variables-literal-only', async () => {
  serveDeployment([webDeployment])
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('PORT')
  })
  // 4.1's `environment_variables`: env entries with a literal `value`
  // render here.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('PORT')).toBe(true)
  expect(await inTable('8080')).toBe(true)
  // the secret-ref env (DB) is NOT a variable (its secret contributes to
  // Related Resources, not here) — scope to the Variables table: the
  // JSON block splits the token across highlighter spans, so a DOM text
  // query for 'DB' cannot see it there anyway.
  const variablesTable = (await screen.findAllByText('PORT'))
    .find((el) => el.closest('table'))!
    .closest('table')!
  expect(variablesTable.textContent).not.toContain('DB')
})

// deployment-data-conditions
test('data-conditions', async () => {
  serveDeployment([webDeployment])
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('MinimumReplicasAvailable')
  })
  // one row per status.conditions[] entry (4.1's format).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('Available')).toBe(true)
  expect(await inTable('MinimumReplicasAvailable')).toBe(true)
  expect(await inTable('Deployment has minimum availability.')).toBe(true)
  expect(await inTable('2026-01-02T03:04:06Z')).toBe(true)
  // the 4.1 header set for the conditions table.
  const headers = screen.getAllByRole('columnheader').map((th) => th.textContent)
  expect(headers).toContain('State')
  expect(headers).toContain('Reason')
  expect(headers).toContain('Message')
  expect(headers).toContain('Time')
})

// deployment-data-security-context
test('data-security-context', async () => {
  serveDeployment([webDeployment])
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('run_as_non_root')
  })
  // spec.template.spec.security_context fields as key/value rows
  // (4.1's `.items()` iteration).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('run_as_non_root')).toBe(true)
  expect(await inTable('true')).toBe(true)
})

// deployment-data-related-resources-secret-deep-link
test('data-related-resources-secret-deep-link', async () => {
  serveDeployment([webDeployment])
  selectProd()
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="web" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('web-cm')
  })
  // The Related Resources rows (from spec.template.spec): image-pull
  // secrets, the service account, secrets (env + volumes), configmaps
  // (volumes), PVCs (volumes). Deep-linking (ratified 2026-10-28):
  // Secrets are BUTTONS to the LANDED Secret view; the rest are plain text
  // (their views are not yet landed — the links would 404).
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('registry-pull')).toBe(true) // ImagePullSecret: plain
  expect(await inTable('web-sa')).toBe(true) // ServiceAccount: plain
  expect(await inTable('web-cm')).toBe(true) // Configmap: plain
  expect(await inTable('web-pvc')).toBe(true) // PVC: plain
  expect(await screen.findByRole('button', { name: 'db-secret' })).toBeTruthy() // env secret
  expect(await screen.findByRole('button', { name: 'tls-secret' })).toBeTruthy() // volume secret
  // the configmap cell is NOT a link.
  const cmCell = (await screen.findAllByText('web-cm')).find((el) => el.closest('table'))!
  expect(cmCell.closest('td')!.querySelector('a')).toBeNull()
  expect(cmCell.closest('td')!.querySelector('button')).toBeNull()
})

// deployment-data-not-found-state
test('data-not-found-state', async () => {
  serveDeployment([])
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<DeploymentDataView name="ghost" namespace="team-a" />)

  // empty items upstream is a state, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No deployment 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// deployment-data-missing-name
test('data-missing-name', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DeploymentDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: deployment name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
