# Navigation Seam — Multi-Kind Routes + Kind-Keyed Navigate Registry (Change C) — Briefing

> Companion to `blueprint.md`. The *why*: `ObjectRoute`'s fixed single-`kind`
> prop forces three hand-rolled dispatchers in `App.tsx`
> (`NetworkPolicyRoute`, `IngressRoute`, `IngressClassRoute`), each ~45 lines
> duplicating ObjectRoute's internals (ref read, seam bump, seam
> registration). The navigate seam itself is a **single-slot module global**
> with three writers (last-mount-wins across kinds — a latent bug the
> dispatchers work around by being the last to register on their routes).
> The relay TTLs (frontend `RELAY_TTL_MS`, backend `STASH_TTL_SECONDS`) are
> held equal by comment alone. Decisions: ADR-0041 + interview `q8`/`q9`
> (mnemonic `interview/kind-arch-20261107`). Lands after B (the registry and
> generated routes exist by then).

## What

- `ObjectRoute` takes `kinds: string[]` (breaking prop) and its `detail`
  renderer receives the matched ref's `kind` — the three dispatchers collapse
  into single `ObjectRoute` elements with multi-kind arrays + a kind-switching
  `detail` prop.
- The navigate seam becomes a **kind-keyed registry** in `lib/objectRef.ts`
  (`registerNavigate(kinds, fn)` / `getNavigateFor(kind)`) — a route registers
  for its own kinds; `OldDataRedirect` looks up by the ref's kind.
  Last-write-wins becomes per-kind (safe: the registry's routes are unique
  per kind — asserted by a kind-disjointness test), cross-kind stomping is
  impossible. The two out-of-scope dispatchers (`CertManagerRoute`,
  `ExternalLoadBalancerRoute` — the B decision keeps their routes hand-written)
  migrate their seam registrations too (the breaking API leaves no stragglers)
  but keep their hand-rolled components. One documented additive delta:
  deep links to the three converted routes now consume the relay on mount
  (parity with single-kind routes; none of the dispatchers did before).
- The relay TTL pair is pinned by tests on **both** sides (frontend
  `RELAY_TTL_MS === 60_000`, backend `STASH_TTL_SECONDS === 60`) with each
  test naming the other side — the cross-boundary invariant stops being a
  comment.

## Requirements

- **R1.** `ObjectRoute`: `kinds: string[]`; `detail: (params: { name: string; namespace?: string; kind: string }) => ReactNode`. All call sites migrated in the same change (breaking prop, no compat alias).
- **R2.** Kind-keyed navigate registry in `lib/objectRef.ts`; the single-slot `registeredNavigate` global in `ObjectRoute.tsx` is deleted; `OldDataRedirect` needs no seam (it `<Navigate>`s directly — verified 2026-11-07: it does not read the navigate registry; `getNavigateFor` exists for the future redirect-path seam + test observability).
- **R3.** The three dispatcher components are deleted; their routes render
  one `ObjectRoute` with the kind array + kind-switching `detail`.
- **R4.** Pinned TTL tests both sides, each naming the counterpart constant.
- **R5.** Behaviour unchanged except one documented additive delta: deep links to the three **converted** multi-kind routes now consume the relay on mount (parity with single-kind routes; none of the dispatchers did before). Ref-driven detail, relay consumption elsewhere, legacy redirects: identical (ADR-0040); e2e green.

## Success

- A tabbed multi-kind route is one registry row + one `ObjectRoute` element.
- The seam has no cross-kind writer ambiguity (provable: the registry is
  keyed; the old global is gone).
- The TTL invariant is test-enforced on both sides of the boundary.

## Out of scope

- Backend (A), the registry/route generation (B), dead-code chore (D).
- URL changes. New navigation features. Relay protocol changes.
