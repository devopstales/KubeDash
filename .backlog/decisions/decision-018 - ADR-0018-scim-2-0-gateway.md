---
id: decision-018
title: "ADR-0018 SCIM 2.0 Gateway"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0018-scim-2-0-gateway.md`

# SCIM 2.0 Gateway

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash discovers users and groups **only at SSO login**: a `users` row is
created on first login and groups come from that login's `groups` claim. Two
gaps follow. (1) **De-provisioning is invisible** — when an employee leaves
and the IdP disables their account, KubeDash keeps the user row and their
bindings until someone notices. (2) **Group membership is not authoritative**
— the IdP is the source of truth for groups, but KubeDash infers it from a
single login rather than receiving it. OpenUnison's SCIM 2.0 Gateway closes
both by letting the IdP (or an identity hub) **push** user/group lifecycle.

The constraint: the SCIM channel is **machine-to-machine** (IdP → KubeDash),
so it must not reuse user SSO. And SCIM must manage *identity* (who the user
is, their groups, active state) without entangling the *access* model
(bindings), which stays an explicit admin/NaaS/PAM action.

#### Decision Drivers

- **De-provisioning must be visible**: IdP disables → KubeDash rejects login,
  without a human noticing.
- **Group membership must be authoritative** (pushed from the IdP, not
  inferred from one login).
- The channel must be **machine-to-machine** (not user SSO) with its own
  scoped credential.
- **Identity and access must stay decoupled**: a SCIM update never silently
  changes a user's cluster bindings.
- It must be the **standard protocol** the source systems (Okta/EntraID/
  Keycloak) already speak.

#### Considered Options

- Keep login-driven discovery only.
- A SCIM 2.0 server (RFC 7644) that the IdP/HR source pushes to, with a
  dedicated machine-to-machine credential.
- Poll the IdP's user API on a schedule.

#### Decision Outcome

Chosen option: "a SCIM 2.0 server the IdP/HR source pushes to", because it is
the standard protocol the source systems already speak and it makes the IdP
the push authority for identity.

KubeDash exposes `/scim/v2/Users` and `/scim/v2/Groups` (list/get/create/
put/patch/delete) authenticated by a **dedicated SCIM Bearer token** (scoped to
SCIM resources only, not user SSO). SCIM `active: false` maps to
`users.status = disabled` (login rejected, bindings retained); `active: true`
re-enables. SCIM's opaque `id` maps to the KubeDash `users.id`/`sso_groups.id`
via `scim_mappings`; upserts are keyed on `externalId` so they are idempotent
and out-of-order safe. A SCIM create/update does **not** auto-create bindings
— identity and access stay decoupled. A deactivate retains bindings by
default (`scim.deleteBindingsOnDeactivate: false`). The filter subset covers
the Okta/EntraID/Keycloak provisioning cases; the full RFC 7644 filter
grammar is deferred.

##### Consequences

- Good, because de-provisioning is now visible (IdP disables → login
  rejected) and group membership is authoritative (pushed, not inferred).
- Good, because identity (SCIM) and access (bindings) are decoupled, so a
  SCIM update can never silently change a user's cluster access.
- Bad, because it adds a second auth surface (the SCIM token) and a SCIM
  resource model to maintain.
- Bad, because the filter grammar is a subset — an IdP that sends an
  unsupported filter gets a 400 until the full grammar lands (deferred).

##### Confirmation

- A SCIM `active: false` PATCH → `users.status = disabled`; the next login is
  rejected; bindings are retained.
- A SCIM user upsert keyed on `externalId` is idempotent (re-POST is a no-op)
  and out-of-order safe.
- A SCIM create/update does **not** create bindings (verified: binding count
  unchanged).
- An unsupported SCIM filter returns `400` (not a SQL error).

#### Pros and Cons of the Options

##### Login-driven discovery only (status quo)

Users/groups discovered only at SSO login.

- Good, because simplest; no new surface.
- Neutral, because it reuses the existing login path.
- Bad, because de-provisioning is invisible and group membership is
  best-effort (from one login's claim).

##### SCIM 2.0 server (chosen)

The IdP/HR source pushes user/group lifecycle via RFC 7644.

- Good, because de-provisioning is visible, group membership is authoritative,
  identity/access are decoupled, and it is the standard protocol.
- Bad, because it adds a second auth surface (SCIM token) + a SCIM resource
  model.
- Bad, because the filter grammar is a subset (unsupported filter → 400).

##### Poll the IdP's user API

KubeDash periodically pulls users/groups from the IdP.

- Good, because no change to the IdP side (no push config).
- Neutral, because it can reuse the OIDC connection.
- Bad, because it is not push (lagging de-provisioning), not standard, and
  needs per-IdP adapters.

#### More Information

- OpenUnison's SCIM 2.0 Gateway is the reference pattern.
- Related: ADR-0015/0016 (bindings — the access model SCIM stays decoupled
  from), ADR-0014 (a disabled user's existing credentials are still
  revocable).
