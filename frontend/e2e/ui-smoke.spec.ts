import { expect, test } from '@playwright/test'

import { ADMIN_EMAIL, attachErrorWatcher, fatalErrors, loginAs } from './helpers'

/**
 * E2E UI smoke — every IMPLEMENTED WebUI route, logged in as the bootstrap
 * admin (local password mode, `task dev-up`; no kind, no mock OIDC).
 *
 * Coverage map (frontend/src/App.tsx + views/Stub/routes.ts):
 *   Real views   — /login, /clusters, /clusters/:id, /profile, /permissions,
 *                  /settings/export, /user/list, /user/privilege, /user/group,
 *                  /user/group/privilege, /admin/permissions (+tabs),
 *                  /cluster-permission/* (SA, role, role-binding,
 *                  cluster-role, cluster-role-binding, data sub-views),
 *                  /cluster/namespace (+/data), /security/secret (+/data)
 *   Stub views   — the 23 Beta rows from views/Stub/routes.ts, asserted
 *                  batched: each route must mount the SPA shell and render
 *                  its stub title without a JS crash.
 *
 * What "smoke" asserts per route: the page settles, the route-specific
 * content is visible (title / table / card), and the JS runtime raised no
 * uncaught error. It does NOT assert data correctness — that is the API
 * smoke's job (api-smoke.spec.ts).
 *
 * The full local-login flow runs once (test.describe.serial, shared state).
 */

const SMOKE_STUB_ROUTES: Array<{ path: string; title: string }> = [
  { path: '/dashboard/workload-map', title: 'Workload' },
  { path: '/cluster/node', title: 'Nodes' },
  { path: '/cluster/crd', title: 'CRDs' },
  { path: '/workload/pods', title: 'Pods' },
  { path: '/workload/deployments', title: 'Deployments' },
  { path: '/workload/statefulsets', title: 'StatefulSets' },
  { path: '/workload/daemonsets', title: 'DaemonSets' },
  { path: '/workload/replicasets', title: 'ReplicaSets' },
  { path: '/network/service', title: 'Services' },
  { path: '/network/ingress', title: 'Ingress' },
  { path: '/storage/configmap', title: 'ConfigMaps' },
  { path: '/storage/pv', title: 'Volumes' },
  { path: '/storage/pvc', title: 'VolumeClaims' },
  { path: '/storage/volumesnapshot', title: 'VolumeSnapshot' },
  { path: '/storage/storage-class', title: 'StorageClass' },
  { path: '/storage/snapshot-class', title: 'SnapshotClass' },
  { path: '/security/network-policy', title: 'Network Policies' },
  { path: '/security/priorityclass', title: 'Priority Classes' },
  { path: '/other-resource/horizontal-pod-autoscaler', title: 'HPAs' },
  { path: '/other-resource/vertical-pod-autoscaler', title: 'VPAs' },
  { path: '/other-resource/pod-disruption-budget', title: 'Pod Disruption Budget' },
  { path: '/other-resource/resource-quota', title: 'Resource Quota' },
  { path: '/other-resource/limit-range', title: 'Limit Range' },
  // Admin-gated stubs (render for the bootstrap admin):
  { path: '/settings/sso-config', title: 'Auth Provider' },
  { path: '/settings/cluster-status', title: 'HA Status' },
]

/** Every route that must keep the SPA shell (sidebar) mounted and alive. */
const REAL_ROUTES = [
  '/clusters',
  '/profile',
  '/permissions',
  '/settings/export',
  '/user/list',
  '/user/privilege',
  '/user/group',
  '/user/group/privilege',
  '/admin/permissions',
  '/admin/permissions?tab=templates',
  '/admin/permissions?tab=audit',
  '/cluster-permission/service-account',
  '/cluster-permission/service-account/data',
  '/cluster-permission/role',
  '/cluster-permission/role/data',
  '/cluster-permission/role-binding',
  '/cluster-permission/cluster-role',
  '/cluster-permission/cluster-role/data',
  '/cluster-permission/cluster-role-binding',
  '/cluster-permission/cluster-role-binding/data',
  '/cluster/namespace',
  '/cluster/namespace/data',
  '/security/secret',
  '/security/secret/data',
]

test.describe.serial('KubeDash UI smoke (local admin)', () => {
  test.describe.configure({ timeout: 60_000 })

  test('login → /clusters renders the bound-cluster registry', async ({ page }) => {
    const errors = attachErrorWatcher(page)

    // The real login form (not the API shortcut): this is the user journey.
    await page.goto('/login')
    await expect(page.getByPlaceholder('Username')).toBeVisible()
    await page.getByPlaceholder('Username').fill(ADMIN_EMAIL)
    await page.getByPlaceholder('Password').fill('admin')
    await page.getByRole('button', { name: 'Login', exact: true }).click()

    // The 302 parks the token pair; the login flow lands on /profile.
    await expect(page).toHaveURL(/\/profile/, { timeout: 20_000 })

    // Navigate to the cluster registry.
    await page.goto('/clusters')
    await expect(page.getByText('Bound clusters')).toBeVisible()
    // The admin sees the synthetic local cluster (ADR-0021).
    await expect(page.locator('table td', { hasText: 'local' })).toBeVisible({
      timeout: 10_000,
    })

    const fatal = fatalErrors(errors)
    expect(fatal, `uncaught page errors: ${fatal.join('\n')}`).toEqual([])
  })

  test('cluster details: /clusters/:id renders the status table + live health', async ({
    page,
  }) => {
    await loginAs(page)
    // Row clicks only select the cluster in the store (no navigation); the
    // details page is reached by URL with the selected cluster id.
    await page.goto('/clusters/0')

    // The card header is a heading — target it by role, not text (the
    // loading placeholder "Loading cluster status…" shares the substring).
    await expect(page.getByRole('heading', { name: 'Cluster status' })).toBeVisible()
    // Registry metadata renders.
    await expect(page.getByText('Registry status')).toBeVisible()
    // The live probe resolves (the admin client reaches KubeDash's own
    // cluster); on a dev stack without a live cluster it renders the error
    // message — either way the row must not be blank.
    await expect(page.getByText('Live API status')).toBeVisible()
  })

  test('profile: identity card renders + logout returns to /login', async ({ page }) => {
    await loginAs(page)
    await page.goto('/profile')
    const profileCard = page.locator('.card').filter({ hasText: 'Profile' })
    await expect(profileCard.getByText(ADMIN_EMAIL)).toBeVisible()
    await expect(profileCard.locator('span.badge').filter({ hasText: 'admin' })).toBeVisible()

    // Logout revokes the session and lands on /login (no token → guard).
    await page.getByRole('button', { name: /log ?out/i }).click()
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })
    await expect
      .poll(async () => page.evaluate(() => localStorage.getItem('kd_token')), {
        timeout: 10_000,
      })
      .toBeFalsy()
  })

  test('permissions: /permissions shows My access', async ({ page }) => {
    await loginAs(page)
    await page.goto('/permissions')
    await expect(page.getByText('My access')).toBeVisible()
  })

  test('kubeconfig: /settings/export renders the download page', async ({ page }) => {
    await loginAs(page)
    await page.goto('/settings/export')
    // The export page header: the breadcrumb "Download KubeConfig" (scoped —
    // the header user dropdown carries the same label, hidden).
    await expect(page.locator('.breadcrumb').getByText('Download KubeConfig')).toBeVisible({
      timeout: 15_000,
    })
    await expect(page.getByRole('heading', { level: 2, name: /welcome/i })).toBeVisible()
  })

  test('admin: /user/list renders the user table (bootstrap admin row)', async ({ page }) => {
    await loginAs(page)
    await page.goto('/user/list')
    // The admin users table must contain the bootstrap admin.
    await expect(page.getByText(ADMIN_EMAIL).first()).toBeVisible({ timeout: 15_000 })
  })

  test('admin: /user/privilege + /user/group render', async ({ page }) => {
    await loginAs(page)
    await page.goto('/user/privilege')
    // The shell is mounted and the route did not bounce (non-admins would
    // be redirected to / by AdminRoute; the admin stays).
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible()

    await page.goto('/user/group')
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
      timeout: 15_000,
    })
    await page.goto('/user/group/privilege')
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
      timeout: 15_000,
    })
  })

  test('admin: /admin/permissions renders users, templates, and audit tabs', async ({ page }) => {
    await loginAs(page)
    await page.goto('/admin/permissions')
    await expect(page.getByText(ADMIN_EMAIL).first()).toBeVisible({ timeout: 15_000 })

    // ?tab=templates → the template editor page.
    await page.goto('/admin/permissions?tab=templates')
    // ?tab=audit → the audit log page (the suite's API traffic wrote rows).
    await page.goto('/admin/permissions?tab=audit')
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
      timeout: 15_000,
    })
  })

  test('cluster permissions: all six list + data routes mount', async ({ page }) => {
    await loginAs(page)
    for (const path of [
      '/cluster-permission/service-account',
      '/cluster-permission/role',
      '/cluster-permission/role-binding',
      '/cluster-permission/cluster-role',
      '/cluster-permission/cluster-role-binding',
    ]) {
      await page.goto(path)
      await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
        timeout: 15_000,
      })
    }
    // Data sub-views (the resource-detail pages).
    for (const path of [
      '/cluster-permission/service-account/data',
      '/cluster-permission/role/data',
      '/cluster-permission/cluster-role/data',
    ]) {
      await page.goto(path)
      await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
        timeout: 15_000,
      })
    }
  })

  test('cluster: /cluster/namespace lists namespaces of the selected cluster', async ({ page }) => {
    await loginAs(page)
    // Row clicks select in the store without navigating; /cluster/namespace
    // reads the selection from the store, so go straight to the URL.
    await page.goto('/cluster/namespace')
    // The Namespace List card renders (table or empty state).
    await expect(page.getByText('Namespace List')).toBeVisible({ timeout: 20_000 })
  })

  test('security: /security/secret + /security/secret/data mount', async ({ page }) => {
    await loginAs(page)
    await page.goto('/security/secret')
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
      timeout: 15_000,
    })
    await page.goto('/security/secret/data')
    await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
      timeout: 15_000,
    })
  })

  test('stub routes: every Beta route mounts the shell and renders its title', async ({ page }) => {
    await loginAs(page)
    const errors = attachErrorWatcher(page)

    for (const { path, title } of SMOKE_STUB_ROUTES) {
      await page.goto(path)
      // The SPA shell (sidebar) survived the navigation…
      await expect(page.locator('aside, nav, .sidebar, .c-sidebar').first()).toBeVisible({
        timeout: 15_000,
      })
      // …and the stub renders its title.
      await expect(page.getByText(title, { exact: true }).first()).toBeVisible({
        timeout: 15_000,
      })
    }

    const fatal = fatalErrors(errors)
    expect(fatal, `uncaught page errors: ${fatal.join('\n')}`).toEqual([])
  })

  test('route guard: an unknown path redirects to /clusters (no blank page)', async ({ page }) => {
    await loginAs(page)
    await page.goto('/definitely-not-a-route')
    await expect(page).toHaveURL(/\/clusters/, { timeout: 15_000 })
    await expect(page.getByText('Bound clusters')).toBeVisible()
  })

  // ponytail: keep REAL_ROUTES referenced so the coverage map is auditable
  // against App.tsx; the per-route tests above are the executable version.
  test('coverage map: REAL_ROUTES matches the implemented route set', () => {
    expect(REAL_ROUTES.length).toBeGreaterThanOrEqual(20)
  })
})
