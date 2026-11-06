---
type: BusinessWorkflow
title: "Frontend build → sync → serve (with the air-gap gate)"
description: "The SPA lifecycle: vite build (tsc + eslint first) → frontend/dist → sha256-stamped copy into backend/static (task fe-sync) → served by the same Gunicorn that serves the API (SPA fallback); task fe-check gates the bundle on the air-gap rule; the image copies dist → /app/static at build time."
tags: [frontend, build, static-serving, air-gap, workflow]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: Taskfile.yaml
      all_of: ['fe-build', 'fe-sync', 'fe-check']
    - path: backend/Dockerfile
      all_of: ['COPY --from=frontend /build/dist ./static', 'wsgi:wsgi']
    - path: tests/fe-airgap-check.mjs
      all_of: ['const RE_HTTP']
---

# Frontend build → sync → serve

One bundle, two consumers: the dev loop (Flask serves
`backend/static/`) and the image (Gunicorn serves `/app/static`).

## The flow

1. **Dev server** — `task fe-dev` (vite dev; the API is proxied to
   :8080). Never bare `pnpm dev` — without `VITE_API_BASE` the dev loop
   CORS-fails against :8080.
2. **Build** — `task fe-build`: `tsc --noEmit` → `eslint src` →
   `vite build` → `frontend/dist/` (content-cached; `FORCE=yes`
   bypasses).
3. **Air-gap gate** — `task fe-check` runs
   `tests/fe-airgap-check.mjs` over `frontend/dist`: any `https?://` or
   `//cdn.` reference (minus the documentation allow-list) fails the
   build (ADR-0020). CI runs the same script.
4. **Sync** — `task fe-sync`: sha256-stamped copy of `frontend/dist` →
   `backend/static/` (a no-op when the bundle is unchanged) — the
   served bundle is what Flask/Gunicorn ships in dev.
5. **Serve** — the same Gunicorn that serves `/api/v1/*` serves the
   bundle: hashed assets `Cache-Control: immutable`, `index.html`
   `no-cache`, non-API/non-asset paths fall through to the SPA fallback
   (which also carries the ADR-0040 POST handoff —
   `workflows/object-deep-link.md`). `/api/*` responses are `no-store`.
6. **Image** — the Dockerfile's `frontend` stage builds
   `dist/`; the runtime stage `COPY --from=frontend /build/dist
   ./static` (i.e. `/app/static`, derived from `KUBEDASH_HOME=/app`),
   non-root, `gunicorn … wsgi:wsgi`.

## Failure behavior

- `fe-build` fails on a `tsc` or `eslint` error — the old
  `backend/static` bundle keeps serving (sync is a separate step).
- `fe-check` failure lists every offender (`file:line: url`) — fix the
  source reference or (only for genuine doc links) extend the
  allow-list.
- Stale sync: `fe-sync`'s sha256 stamp makes an unchanged bundle a
  no-op, so a "sync ran" message doesn't mean bytes moved.

## Verification (2026-11-06)

Anchors confirmed. The air-gap gate is pinned by
`backend/tests/test_fe_airgap_check.py`; the Dockerfile shape by
`backend/tests/test_dockerfile.py`; static serving by
`backend/tests/test_static.py`.

**Related.** ADR-0020 (air-gap), ADR-0006 (single container),
ADR-0040 (the fallback's second job),
`invariants/air-gap-bundle.md`, `invariants/security-header-layer.md`.
