import { expect, test } from '@playwright/test'

import {
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  KIND_KUBECONFIG,
  SMOKE_CLUSTER,
  authHeaders,
  errorCode,
  loginToken,
} from './helpers'

/**
 * E2E API smoke — every IMPLEMENTED /api/v1 endpoint exercised through the
 * real HTTP boundary (Flask :8080 + Postgres/Redis via `task dev-up`, local
 * bootstrap admin; no kind, no mock OIDC).
 *
 * Why API-level and not only UI-level: the UI only touches a subset of the
 * surface, and stable error-code contracts (409/422/401/501) are backend
 * invariants the UI rarely renders. Each test asserts the documented
 * contract, not implementation details.
 *
 * Run:
 *   task dev-up
 *   # (one-time schema — see auth-smoke.spec.ts header)
 *   corepack pnpm exec playwright test e2e/api-smoke.spec.ts
 */

test.describe('KubeDash API smoke', () => {
  test.describe.configure({ timeout: 30_000 })

  test.beforeAll(async ({ request }) => {
    const resp = await request.get('/healthz')
    expect(resp.status(), 'dev stack (Flask :8080) must be up — run `task dev-up`').toBe(200)
  })

  test('open surface: /healthz 200 + /api/v1/auth/settings 200 flags', async ({ request }) => {
    const settings = await request.get('/api/v1/auth/settings')
    expect(settings.status()).toBe(200)
    const body = await settings.json()
    // The dev stack boots with the bootstrap admin → local auth is enabled;
    // no OIDC issuer is configured → SSO is off.
    expect(body.local_enabled).toBe(true)
    expect(body.sso_enabled).toBe(false)
  })

  test('auth: local login 302 parks the token pair; bad password 401s without enumeration', async ({
    request,
  }) => {
    const ok = await request.post('/api/v1/auth/local', {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
      maxRedirects: 0,
    })
    expect(ok.status()).toBe(302)
    const location = ok.headers()['location'] ?? ''
    expect(location).toContain('token=')
    expect(location).toContain('refresh=')

    // Unknown email and wrong password share the same 401 code (no
    // enumeration, I-NEW-2).
    for (const [email, password] of [
      [ADMIN_EMAIL, 'wrong-password'],
      ['nobody@nowhere.invalid', 'whatever1!'],
    ]) {
      const bad = await request.post('/api/v1/auth/local', {
        data: { email, password },
        maxRedirects: 0,
      })
      expect(bad.status()).toBe(401)
      const body = await bad.json()
      expect(errorCode(body)).toBe('INVALID_CREDENTIALS')
    }
  })

  test('auth: /auth/me 401 pre-JWT, 200 + identity post-JWT', async ({ request }) => {
    const anon = await request.get('/api/v1/auth/me')
    expect(anon.status()).toBe(401)

    const token = await loginToken(request)
    const me = await request.get('/api/v1/auth/me', { headers: authHeaders(token) })
    expect(me.status()).toBe(200)
    const body = await me.json()
    expect(body.email).toBe(ADMIN_EMAIL)
    expect(body.role).toBe('admin')
    expect(body.auth_source).toBe('local')
  })

  test('auth: /auth/refresh rotates the pair (old refresh token is one-shot)', async ({
    request,
  }) => {
    const resp = await request.post('/api/v1/auth/local', {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
      maxRedirects: 0,
    })
    const url = new URL(resp.headers()['location'] ?? '', 'http://localhost')
    const refresh = url.searchParams.get('refresh') ?? ''
    expect(refresh).toBeTruthy()

    const rotated = await request.post('/api/v1/auth/refresh', { data: { refresh_token: refresh } })
    expect(rotated.status()).toBe(200)
    const body = await rotated.json()
    expect(body.access).toBeTruthy()
    expect(body.refresh).toBeTruthy()
    expect(body.refresh).not.toBe(refresh) // rotation: the old value is gone
  })

  test('auth: /auth/logout revokes refresh tokens (401 after)', async ({ request }) => {
    const resp = await request.post('/api/v1/auth/local', {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
      maxRedirects: 0,
    })
    const url = new URL(resp.headers()['location'] ?? '', 'http://localhost')
    const access = url.searchParams.get('token') ?? ''
    const refresh = url.searchParams.get('refresh') ?? ''

    const out = await request.post('/api/v1/auth/logout', { headers: authHeaders(access) })
    expect(out.status()).toBe(200)

    // The revoked refresh token must no longer rotate.
    const reused = await request.post('/api/v1/auth/refresh', { data: { refresh_token: refresh } })
    expect(reused.status()).toBe(401)
  })

  test('clusters: register 201 → list contains the row → get + health', async ({ request }) => {
    const token = await loginToken(request)
    const headers = authHeaders(token)

    // Fresh name per run: the registry is a shared dev-stack state and the
    // duplicate gate (409) has its own dedicated test below.
    const name = `e2e-smoke-${Date.now()}`
    const reg = await request.post('/api/v1/clusters', {
      headers,
      data: {
        name,
        api_server: 'https://127.0.0.1:6443',
        kubeconfig: KIND_KUBECONFIG,
        context: 'kind',
      },
    })
    expect(reg.status()).toBe(201)
    expect((await reg.json()).name).toBe(name)

    const list = await request.get('/api/v1/clusters', { headers })
    expect(list.status()).toBe(200)
    const rows = await list.json()
    const row = rows.find((c: { name: string }) => c.name === name)
    expect(row, 'registered cluster must appear in the bound list').toBeTruthy()
    expect(row.source).toBe('registry')
    // The admin also sees the synthetic local cluster (ADR-0021, id 0).
    expect(rows.some((c: { id: number }) => c.id === 0)).toBe(true)

    const get = await request.get(`/api/v1/clusters/${row.id}`, { headers })
    expect(get.status()).toBe(200)
    expect((await get.json()).name).toBe(name)

    // Health: the smoke kubeconfig points at an unreachable API server →
    // 502 CLUSTER_UNREACHABLE is the documented contract, not a failure.
    const health = await request.get(`/api/v1/clusters/${row.id}/health`, { headers })
    expect(health.status()).toBe(502)
    expect(errorCode(await health.json())).toBe('CLUSTER_UNREACHABLE')
  })

  test('clusters: register edge cases — bad YAML 422, duplicate 409', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))

    const badYaml = await request.post('/api/v1/clusters', {
      headers,
      data: {
        name: `e2e-badyaml-${Date.now()}`,
        api_server: 'https://127.0.0.1:6443',
        kubeconfig: 'not: [valid yaml',
        context: 'kind',
      },
    })
    expect(badYaml.status()).toBe(422)
    expect(errorCode(await badYaml.json())).toBe('INVALID_KUBECONFIG')

    const dup = await request.post('/api/v1/clusters', {
      headers,
      data: {
        name: SMOKE_CLUSTER,
        api_server: 'https://127.0.0.1:6443',
        kubeconfig: KIND_KUBECONFIG,
        context: 'kind',
      },
    })
    expect(dup.status()).toBe(409)
    expect(errorCode(await dup.json())).toBe('CLUSTER_ALREADY_EXISTS')
  })

  test('clusters: unauthenticated → 401 (the auth hook scopes /api/v1/*)', async ({ request }) => {
    for (const [method, path] of [
      ['GET', '/api/v1/clusters'],
      ['GET', '/api/v1/clusters/0'],
      ['GET', '/api/v1/kubeconfig'],
      ['GET', '/api/v1/permissions/my-access'],
    ] as const) {
      const resp = method === 'GET' ? await request.get(path) : await request.post(path)
      expect(resp.status(), `${method} ${path} must be 401 pre-JWT`).toBe(401)
    }
  })

  test('resources: list namespaces/pods on the local cluster; unsupported kind 404', async ({
    request,
  }) => {
    const headers = authHeaders(await loginToken(request))

    // Cluster 0 = synthetic local cluster (ADR-0021); the admin client lists
    // the namespaces/pods KubeDash runs in.
    for (const kind of ['namespaces', 'pods']) {
      const resp = await request.get(`/api/v1/clusters/0/resources/${kind}`, { headers })
      expect(resp.status(), `GET /resources/${kind}`).toBe(200)
      const body = await resp.json()
      expect(body.kind).toBe(kind)
      expect(body.cluster).toBe('local')
      expect(Array.isArray(body.items)).toBe(true)
      if (kind === 'namespaces') {
        const names = body.items.map((n: { metadata: { name: string } }) => n.metadata.name)
        expect(names).toContain('default')
        expect(names).toContain('kube-system')
      }
    }

    const unsupported = await request.get('/api/v1/clusters/0/resources/widgets', { headers })
    expect(unsupported.status()).toBe(404)
    expect(errorCode(await unsupported.json())).toBe('RESOURCE_KIND_NOT_SUPPORTED')

    // Unknown registry cluster id → CLUSTER_NOT_FOUND (the binding gate).
    const missing = await request.get('/api/v1/clusters/99999/resources/namespaces', { headers })
    expect(missing.status()).toBe(404)
  })

  test('metrics: /clusters/0/metrics/summary 200 with the summary contract', async ({
    request,
  }) => {
    const headers = authHeaders(await loginToken(request))
    const resp = await request.get('/api/v1/clusters/0/metrics/summary', { headers })
    expect(resp.status(), 'GET /metrics/summary').toBe(200)
    const body = await resp.json()
    // metrics_available is a boolean — the bare dev cluster likely has no
    // metrics-server, so `false` is the EXPECTED state, not a failure
    // (certainty rule: never 500, never 0). The declared-state objects are
    // always present (they come from pods/nodes, not the Metrics API).
    expect(typeof body.metrics_available).toBe('boolean')
    for (const key of ['cpu', 'memory', 'pods']) {
      expect(body[key], `summary.${key} object present`).toBeTruthy()
    }
  })

  test('events: /clusters/0/events 200 bare list (newest-first)', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))
    const resp = await request.get('/api/v1/clusters/0/events', { headers })
    expect(resp.status(), 'GET /events').toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body)).toBe(true)
  })

  test('admin/users: list, create → PATCH role → DELETE; bootstrap admin immutable', async ({
    request,
  }) => {
    const headers = authHeaders(await loginToken(request))
    const email = `e2e-user-${Date.now()}@local`
    const password = 'Sm0ke!Pass1'

    const created = await request.post('/api/v1/admin/users', {
      headers,
      data: { username: 'e2e-smoke-user', email, password, type: 'Local', role: 'user' },
    })
    expect(created.status()).toBe(201)
    const user = await created.json()
    expect(user.email).toBe(email)
    expect(user.role).toBe('user')

    // Create edge: weak password → 422.
    const weak = await request.post('/api/v1/admin/users', {
      headers,
      data: {
        username: 'weak',
        email: `weak-${Date.now()}@local`,
        password: 'short',
        type: 'Local',
      },
    })
    expect(weak.status()).toBe(422)

    // PATCH: promote to admin.
    const patched = await request.patch(`/api/v1/admin/users/${user.id}`, {
      headers,
      data: { role: 'admin' },
    })
    expect(patched.status()).toBe(200)
    expect((await patched.json()).role).toBe('admin')

    // DELETE: the created user goes; self-delete is refused with 409.
    const del = await request.delete(`/api/v1/admin/users/${user.id}`, { headers })
    expect(del.status()).toBe(200)
    expect((await del.json()).deleted).toBe(user.sub)

    const list = await request.get('/api/v1/admin/users', { headers })
    expect(list.status()).toBe(200)
    const admin = (await list.json()).find((u: { email: string }) => u.email === ADMIN_EMAIL)
    expect(admin).toBeTruthy()
    const selfDel = await request.delete(`/api/v1/admin/users/${admin.id}`, { headers })
    expect(selfDel.status()).toBe(409)
    expect(errorCode(await selfDel.json())).toBe('CLUSTER_ALREADY_EXISTS')
  })

  test('permissions: my-access 200 list + templates CRUD', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))

    const access = await request.get('/api/v1/permissions/my-access', { headers })
    expect(access.status()).toBe(200)
    expect(Array.isArray(await access.json())).toBe(true)

    const templateName = `e2e-tpl-${Date.now()}`
    const templateBody = {
      name: templateName,
      description: 'e2e smoke template',
      scope: 'namespace',
      // Shape: non-empty verbs/resources (the handler's 422 check).
      rules: [{ api_groups: [''], resources: ['pods'], verbs: ['get', 'list'] }],
    }
    const created = await request.post('/api/v1/admin/permissions/templates', {
      headers,
      data: templateBody,
    })
    expect(created.status()).toBe(201)

    const list = await request.get('/api/v1/admin/permissions/templates', { headers })
    expect(list.status()).toBe(200)
    expect((await list.json()).some((t: { name: string }) => t.name === templateName)).toBe(true)

    const get = await request.get(`/api/v1/admin/permissions/templates/${templateName}`, {
      headers,
    })
    expect(get.status()).toBe(200)

    const put = await request.put(`/api/v1/admin/permissions/templates/${templateName}`, {
      headers,
      data: { ...templateBody, description: 'e2e smoke template (updated)' },
    })
    expect(put.status()).toBe(200)

    const del = await request.delete(`/api/v1/admin/permissions/templates/${templateName}`, {
      headers,
    })
    expect(del.status()).toBe(200)

    const gone = await request.get(`/api/v1/admin/permissions/templates/${templateName}`, {
      headers,
    })
    expect(gone.status()).toBe(404)
  })

  test('kubeconfig: download — 200 YAML or 500 with a stable code', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))
    const resp = await request.get('/api/v1/kubeconfig', { headers })
    // A bare dev backend has no KUBEDASH_PLUGIN_SERVER (ADR-0011 registry
    // kubeconfig source) → the documented 500 INTERNAL_ERROR. A fully
    // configured backend returns the YAML attachment; both are valid
    // contracts, the error must never be a raw 500 without a stable code.
    if (resp.status() === 500) {
      expect(errorCode(await resp.json())).toBe('INTERNAL_ERROR')
      return
    }
    expect(resp.status()).toBe(200)
    expect(resp.headers()['content-type']).toContain('application/yaml')
    expect(resp.headers()['content-disposition']).toContain('kubedash-kubeconfig.yaml')
    const text = await resp.text()
    expect(text).toContain('apiVersion: v1')
    expect(text).toContain('users:')
  })

  test('groups: admin group create → list → detail (local: prefix is server-side)', async ({
    request,
  }) => {
    const headers = authHeaders(await loginToken(request))
    const display = `e2e-group-${Date.now()}`
    const stored = `local:${display}`

    const created = await request.post('/api/v1/admin/groups', {
      headers,
      data: { name: display },
    })
    expect(created.status()).toBe(201)

    const list = await request.get('/api/v1/admin/groups', { headers })
    expect(list.status()).toBe(200)
    expect((await list.json()).some((g: { name: string }) => g.name === stored)).toBe(true)

    const get = await request.get(`/api/v1/admin/groups/${encodeURIComponent(stored)}`, {
      headers,
    })
    expect(get.status()).toBe(200)
  })

  // /audit + /audit/export are base-structure stubs: audit ROWS are written
  // (user_create/role_change/…), but the read route 501s until the audit
  // query lands — the stub must stay a stable NOT_IMPLEMENTED, not a 500.
  test('audit: read routes are 501 NOT_IMPLEMENTED stubs', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))
    for (const path of ['/api/v1/audit', '/api/v1/audit/export']) {
      const resp = await request.get(path, { headers })
      expect(resp.status(), `GET ${path}`).toBe(501)
      expect(errorCode(await resp.json())).toBe('NOT_IMPLEMENTED')
    }
  })

  test('501 stubs: metrics/logs/traces report NOT_IMPLEMENTED, not 500', async ({ request }) => {
    const headers = authHeaders(await loginToken(request))
    for (const path of [
      '/api/v1/metrics/query',
      '/api/v1/metrics/query_range',
      '/api/v1/logs/query',
      '/api/v1/traces',
    ]) {
      const resp = await request.get(path, { headers })
      expect(resp.status(), `GET ${path}`).toBe(501)
      expect(errorCode(await resp.json())).toBe('NOT_IMPLEMENTED')
    }
  })
})
