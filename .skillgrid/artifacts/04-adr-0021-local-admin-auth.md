# Local Admin Auth (bootstrap password mode)

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

ADR-0020 (Air-Gap Deployment) assumes an IdP on the internal network and
explicitly defers "pure no-IdP mode — local username/password auth when
there is no IdP at all" to ARCHITECTURE.md § 11. Two real situations
break under that deferral:

1. **Bootstrap moment.** A fresh KubeDash install must be reachable
   before (or without) SSO being wired: someone needs to get in to
   register the first cluster, point the deployment at its IdP, or
   verify the install. With OIDC-only login and no IdP configured, the
   login page 302s to a nonexistent `/authorize` and the install is a
   black box.
2. **No-IdP sites.** Some air-gapped sites genuinely have no IdP (small
   OT/IT-converged environments). They need a local sign-in path that
   reuses the existing local-JWT + refresh-token machinery (ADR-0001)
   rather than introducing a second auth mechanism.

The user has ruled (2026-10-17): local password mode enters NOW, scoped
as the **bootstrap-admin + local-user** path, with SSO remaining the
primary sign-in path for IdP-configured deployments. Non-admin local
users' *cluster access* (CA-based kubeconfig, bindings, role templates)
is explicitly out of scope and belongs to the permission-management
change (ADR-0013).

The question this ADR decides: how local auth is introduced without
doubling the auth surface, and where its boundary sits against
ADR-0020.

#### Decision Drivers

- **Reuse the existing token machinery** — local login must issue the
  same HS256 JWT + rotating refresh pair as OIDC (ADR-0001, base-
  structure R2/OD-1); the SPA's `apiFetch`, refresh-on-401, and
  revocation set all keep working unchanged.
- **SSO stays primary** — for IdP-configured deployments the SSO button
  is the first-class path; local mode must not displace it, and SSO
  identities keep `auth_source='oidc'` (SCIM/JIT/role-mapping changes
  key off that).
- **Idempotent, env-driven bootstrap** — the first admin is declared in
  the environment (`KUBEDASH_BOOTSTRAP_ADMIN_EMAIL` /
  `KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD`), created/refreshed at boot, no
  separate `kubectl`-based seed job, no out-of-band SQL.
- **Air-gap integrity (ADR-0020)** — no new runtime egress; the only new
  runtime surface is a local POST to the app itself. Password storage
  must be stdlib-only (no new hashing dependency in the air-gap
  bundle).
- **Admins act on their own kubeconfig** — the admin's cluster identity
  is the in-cluster service account or a mounted/local kubeconfig file
  (`KUBEDASH_ADMIN_KUBECONFIG`), NOT a registry row: the registry
  (ADR-0002, one-way-door) stays the user-registered, encrypted,
  binding-gated store.
- **Honest schema** — the profile page and admin gate must be able to
  tell a local identity from an SSO identity; `users` needs
  `auth_source`, not just a nullable password.

#### Considered Options

- Bootstrap-admin local password login, sibling route of OIDC in
  `AuthApi`, same token pair; env-driven idempotent upsert at boot;
  admin cluster access via a second pool input (in-cluster or file).
- Full local user store with self-registration + approval workflow.
- Defer entirely: keep OIDC-only and seed the first admin by direct
  SQL/psql against Postgres.
- A separate `auth-local` API module with its own token issuing.

#### Decision Outcome

Chosen option: "bootstrap-admin local password login as a sibling route
of OIDC, env-driven idempotent upsert at boot, admin cluster access via
a second pool input", because it adds exactly one route, two nullable-
ish columns, and one config pair while reusing 100% of the existing
token, refresh, revocation, and SPA-side machinery — the smallest
surface that makes a no-IdP install reachable and keeps SSO primary.

Concretely, with the bootstrap env set:

1. **Schema:** `users` gains `password_hash VARCHAR(255) NULL`
   (`pbkdf2:sha256:600000$<b64salt>$<b64hash>`, stdlib
   `hashlib.pbkdf2_hmac`, 600k iterations, 16-byte salt) and
   `auth_source VARCHAR(16) NOT NULL DEFAULT 'oidc'`. Existing SSO rows
   are explicitly `'oidc'`; only the bootstrap row (and, later,
   permission-management-created local users) are `'local'`.
2. **Boot:** `create_app()` runs an idempotent upsert on
   `users.email` when both bootstrap env vars are set (role `admin`,
   `auth_source='local'`, hash refreshed on env change). Either unset →
   no-op, and `POST /api/v1/auth/local` answers 403
   `LOCAL_AUTH_DISABLED`. Two-replica concurrent boot is safe: the
   upsert targets the `email` unique key.
3. **Login:** `POST /api/v1/auth/local` `{ email, password }` →
   constant-time compare → same `issue_token_pair` + 302
   `/?token=…&refresh=…` delivery contract as the OIDC callback.
   Wrong password OR unknown email → 401 `INVALID_CREDENTIALS` (one
   code; no user enumeration).
4. **Identity:** `GET /api/v1/auth/me` returns `auth_source` for all
   users; admins additionally get `kubeconfig_source`
   (`"in-cluster" | "kubeconfig-file" | null`). The login page shows
   the SSO button only when `GET /api/v1/auth/settings` reports
   `sso_enabled: true` (i.e. `oidc_issuer` non-empty) and the local form
   only when `local_enabled: true`.
5. **Admin cluster access:** `K8sClientPool` resolves the admin source
   once from config — `KUBEDASH_ADMIN_KUBECONFIG` empty → in-cluster
   service account; set → `load_kube_config` from that path (file
   missing/unreadable → `/readyz` 503 naming `admin-kubeconfig`).
   Admin callers see one synthetic cluster entry
   `{ id: 0, name: "local", source: "admin" }` in
   `GET /api/v1/clusters`; `id: 0` routes to the admin source in the
   pool and goes through the same SAR path (ADR-0004) as registry
   clusters. Non-admin callers never see `id: 0` (registry rows start
   at id 1, so no collision by construction).
6. **Boundary with ADR-0020:** local mode is the *bootstrap + no-IdP*
   path. For IdP-configured deployments SSO remains the primary sign-in
   (login page leads with SSO; local is secondary). ADR-0020's § 11
   deferral is thereby **superseded-in-part**: the "pure no-IdP mode"
   that remains deferred is multi-user local management (provisioning,
   roles, CA-based kubeconfig distribution), which belongs to
   ADR-0013 (permission management).

##### Consequences

- Good, because a no-IdP install is reachable with two env vars and zero
  out-of-band steps; the bootstrap admin is also the escape hatch for
  a broken IdP config on SSO sites.
- Good, because the token surface is unchanged — `apiFetch`, 401
  refresh, jti revocation, and the CLI plugin all work for local users
  without a single SPA change beyond the login form.
- Good, because the registry stays pure (ADR-0002 one-way-door intact):
  the admin source is a pool input, not a registry row, and
  `cluster_bindings` is untouched.
- Bad, because an SSO user whose IdP `email` collides with the
  bootstrap email is upserted to `auth_source='oidc'` at next SSO
  login — the password then stops working for that identity (documented;
  operators must not reuse the bootstrap email in their IdP).
- Bad, because the bootstrap password lives in the environment/secret —
  rotation means editing the secret and restarting (the boot upsert
  refreshes the hash). There is no in-UI password change in this scope.
- Bad, because non-admin local users can sign in (once created by the
  later permission-management change) but have no cluster access until
  that change ships CA-based kubeconfig + bindings — a visible
  intermediate state, deliberately parked in ADR-0013.

##### Confirmation

- With bootstrap env set, `task backend-run` boot creates exactly one
  `users` row (role `admin`, `auth_source='local'`); a second boot
  creates none; changing the password env updates the hash.
- `POST /api/v1/auth/local` with the right credentials 302s to
  `/?token=…&refresh=…` exactly like the OIDC callback; the SPA parks
  the tokens and lands on `/profile`; wrong password → 401
  `INVALID_CREDENTIALS`; env unset → 403 `LOCAL_AUTH_DISABLED`.
- Admin `GET /api/v1/clusters` includes exactly one `id: 0` `source:
  admin` entry; non-admin list is byte-identical to pre-change behavior;
  `GET /api/v1/clusters/0/resources/pods` works for the admin (kind,
  CI) and 403s for a non-admin.
- `/readyz` fails naming `admin-kubeconfig` when
  `KUBEDASH_ADMIN_KUBECONFIG` points at a missing file.
- ADR-0020's air-gap confirmation steps still pass: local login makes
  zero outbound calls (stdlib pbkdf2, local DB); the no-CDN `task
  fe-check` assertion holds for the new Login/Profile views.

#### Pros and Cons of the Options

##### Bootstrap-admin local password, sibling route (chosen)

One route, two columns, one config pair, 100% token-machinery reuse.

- Good, because a no-IdP install is reachable with two env vars; SSO
  sites get an escape hatch; zero new runtime egress (ADR-0020 intact).
- Good, because idempotent env-driven upsert needs no seed job, no
  migration data, and survives reboots/restarts (HA-safe).
- Bad, because the bootstrap password is env/secret-bound (rotation =
  secret edit + restart).
- Bad, because an IdP email collision flips the identity to SSO (the
  local password stops working for that email).

##### Full local user store (self-registration + approval)

A user management surface: register, approve, roles, password reset.

- Good, because no-IdP sites could onboard many users without the
  permission-management change.
- Bad, because it is ADR-0013's scope — role templates, bindings, and
  CA-based kubeconfig — pulled forward a whole vertical early.
- Bad, because it grows the trust surface (registration endpoint,
  approval state machine) exactly where ADR-0020 wants the smallest
  surface.

##### Defer: seed the first admin by direct SQL

Keep OIDC-only; `psql UPDATE users SET role='admin'` against Postgres.

- Good, because zero code change now.
- Bad, because there is no password column to verify against — a SQL
  seed only works if local login exists, so this option actually
  requires the auth code minus the route; it defers the hard part.
- Bad, because out-of-band SQL in a Helm-deployed, air-gapped install
  is exactly the operational friction the env-driven bootstrap removes.

##### Separate `auth-local` API module

Its own Smorest `Api`, its own token issuing.

- Good, because the OIDC module stays untouched.
- Bad, because `users` upsert, token issuing, and the `/auth/*`
  auth-hook opt-out get duplicated; two modules answer "who am I" with
  diverging `me` shapes.
- Bad, because the two paths share ~80% of their body — the split is
  a seam with one caller each, i.e. a hypothetical boundary.

#### More Information

- Related: ADR-0001 (local JWTs + refresh rotation — reused verbatim),
  ADR-0002 (registry stays the user-registered store; the admin source
  is a second pool input), ADR-0004 (SAR on the synthetic `local`
  cluster), ADR-0006 (static SPA serving unchanged), ADR-0013
  (permission management owns multi-user local access), ADR-0020
  (air-gap boundary; § 11 deferral narrowed in part by this ADR).
- Spec: `.skillgrid/specs/2026-10-17-authentication-vertical/`
  (briefing + blueprint).
- ARCHITECTURE.md § 7.7 (air-gap) and § 11 (deferred no-IdP mode) carry
  the boundary notes.
