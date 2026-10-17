# SCIM 2.0 Gateway

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

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

## Considered Options

- Keep login-driven discovery only. Simplest, but de-provisioning is invisible
  and group membership is best-effort.
- A SCIM 2.0 server (RFC 7644) that the IdP/HR source pushes to, with a
  dedicated machine-to-machine credential. Closes both gaps and is the
  standard protocol Okta/EntraID/Keycloak already speak.
- Poll the IdP's user API on a schedule. Works, but is not push, is not
  standard, and needs per-IdP adapters.

## Decision Outcome

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

### Consequences

- Good, because de-provisioning is now visible (IdP disables → login
  rejected) and group membership is authoritative (pushed, not inferred).
- Good, because identity (SCIM) and access (bindings) are decoupled, so a
  SCIM update can never silently change a user's cluster access.
- Bad, because it adds a second auth surface (the SCIM token) and a SCIM
  resource model to maintain.
- Bad, because the filter grammar is a subset — an IdP that sends an
  unsupported filter gets a 400 until the full grammar lands (deferred).
