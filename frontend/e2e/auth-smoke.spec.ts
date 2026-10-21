import { expect, test, type Page } from '@playwright/test'

/**
 * E2E auth smoke — catches the three regression classes that unit tests miss:
 *
 * 1. **App root render** — the full <App /> tree mounts without an infinite
 *    re-render loop (useColorModes / React 19). If the shell loops, the page
 *    never settles and the first assertion times out.
 * 2. **SPA serving** — GET / returns the React HTML (not a 404). Catches
 *    KUBEDASH_STATIC_DIR not being wired from env to create_app().
 * 3. **Local login → profile** — the full auth journey: settings → local
 *    form → 302 token park → /profile renders identity + synthetic cluster.
 *
 * Runs against the real dev stack (Flask :8080 + Postgres/Redis via
 * `task dev-up`). No kind cluster, no mock OIDC — local password auth only.
 *
 *   task dev-up
 *   # create schema (one-time):
 *   cd backend && .venv/bin/python -c "
 *     from app import create_app; from app.extensions import db
 *     a = create_app({'DATABASE_URL': 'postgresql+psycopg://kubedash:kubedash@localhost:5432/kubedash'})
 *     with a.app_context(): db.create_all()"
 *   # start backend:
 *   KUBEDASH_BOOTSTRAP_ADMIN_EMAIL=admin@local \
 *   KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD=correct-horse \
 *   KUBEDASH_STATIC_DIR=$PWD/backend/static \
 *   KUBEDASH_ROLE=leader KUBEDASH_REPLICA_ID=local \
 *     backend/.venv/bin/python backend/wsgi.py
 *
 *   corepack pnpm exec playwright test e2e/auth-smoke.spec.ts
 */

const ADMIN_EMAIL = 'admin@local'
const ADMIN_PASSWORD = 'admin'

/** Collect pageerror events so we can assert the JS runtime didn't crash. */
function attachErrorWatcher(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (err) => errors.push(err.message))
  return errors
}

test.describe('KubeDash auth smoke (local password)', () => {
  test.describe.configure({ timeout: 30_000 })

  test('SPA shell renders at / without JS crash', async ({ page }) => {
    const errors = attachErrorWatcher(page)

    // BUG #2: GET / must return the SPA HTML (200), not a 404.
    const resp = await page.goto('/')
    expect(resp?.status()).toBe(200)
    expect(resp?.headers()['content-type']).toContain('text/html')

    // BUG #1: the full <App /> tree mounts. ProtectedRoute bounces / →
    // /login (no kd_token in a fresh context). If useColorModes or any
    // shell hook loops, this navigation never settles.
    await expect(page).toHaveURL(/\/login/, { timeout: 10_000 })

    // The Login form is visible (settings route resolved, view rendered).
    // The form uses placeholder-driven inputs (no <label>), so select by
    // placeholder.
    await expect(page.getByPlaceholder('Username')).toBeVisible()

    // No uncaught JS errors (infinite loop, null element, bad import).
    // Filter the benign favicon 404 (a resource error, not a pageerror).
    const fatal = errors.filter((e) => !e.includes('favicon') && !e.includes('Manifest'))
    expect(fatal, `uncaught page errors: ${fatal.join('\n')}`).toEqual([])
  })

  test('local login → profile shows identity + synthetic cluster', async ({ page }) => {
    const errors = attachErrorWatcher(page)

    // --- 1. Land on /login ---
    await page.goto('/login')
    await expect(page.getByPlaceholder('Username')).toBeVisible()

    // --- 2. Fill the local form and submit ---
    await page.getByPlaceholder('Username').fill(ADMIN_EMAIL)
    await page.getByPlaceholder('Password').fill(ADMIN_PASSWORD)
    await page.getByRole('button', { name: 'Login', exact: true }).click()

    // --- 3. The 302 parks the token pair and navigates to /profile ---
    await expect(page).toHaveURL(/\/profile/, { timeout: 15_000 })
    await expect
      .poll(async () => page.evaluate(() => localStorage.getItem('kd_token')), {
        timeout: 10_000,
      })
      .toBeTruthy()

    // --- 4. Profile renders the identity card ---
    // Scope to the profile card: the email also appears in the header user
    // dropdown, so a bare getByText would match two elements (strict-mode fail).
    const profileCard = page.locator('.card').filter({ hasText: 'Profile' })
    await expect(profileCard.getByText(ADMIN_EMAIL)).toBeVisible()
    // Role badge (the <span class="badge"> inside the card).
    await expect(profileCard.locator('span.badge').filter({ hasText: 'admin' })).toBeVisible()

    // --- 5. The admin sees the synthetic local cluster ---
    // Navigate to /clusters; the registry table includes the id:0 "local"
    // row for admins (the synthetic admin cluster, ADR-0021).
    await page.goto('/clusters')
    // The table cell renders c.name = "local". Scope to the table to avoid
    // matching the "Admin kubeconfig source" label on other pages.
    await expect(page.locator('table td', { hasText: 'local' })).toBeVisible({ timeout: 10_000 })

    const fatal = errors.filter((e) => !e.includes('favicon') && !e.includes('Manifest'))
    expect(fatal, `uncaught page errors: ${fatal.join('\n')}`).toEqual([])
  })

  test('wrong password shows inline error, stays on /login', async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill(ADMIN_EMAIL)
    await page.getByPlaceholder('Password').fill('wrong-password')
    await page.getByRole('button', { name: 'Login', exact: true }).click()

    // 401 → the view surfaces the envelope message, stays on /login.
    await expect(page.getByText('invalid email or password')).toBeVisible({ timeout: 10_000 })
    await expect(page).toHaveURL(/\/login/)
    // No token was parked.
    await expect.poll(async () => page.evaluate(() => localStorage.getItem('kd_token'))).toBeNull()
  })
})
