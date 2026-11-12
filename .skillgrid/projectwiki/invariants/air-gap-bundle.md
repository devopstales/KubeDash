---
type: InvariantContract
title: "The built SPA bundle and the API docs contain no external references (air-gap)"
description: "task fe-check fails the build on any https?:// or //cdn. reference in frontend/dist (allow-listed doc links excepted); Swagger UI assets are served from the vendored package, never a CDN. (ADR-0020.)"
tags: [air-gap, bundle, swagger, adr-0020]
status: stable
generated: { by: skillgrid/knowledge-init, at: 2026-11-06T00:00:00Z }
verification:
  engine: ripgrep
  anchors:
    - path: tests/fe-airgap-check.mjs
      all_of: ["const RE_HTTP = /https?:\\/\\/[^\\s\"'<>()\\\\]+/g;", "const RE_CDN = /\\/\\/cdn\\.[^\\s\"'<>()\\\\]+/g;"]
    - path: backend/tests/test_fe_airgap_check.py
      all_of: ['test_clean_dist_passes', 'test_cdn_ref_fails_with_offender']
    - path: backend/tests/api/test_apidocs.py
      all_of: ['test_docs_page_uses_local_asset_routes', 'test_served_bundle_is_byte_identical_to_package']
claims:
  - subject: external-URL pattern the gate greps
    literal: "const RE_HTTP = /https?:\\/\\/[^\\s\"'<>()\\\\]+/g;"
  - subject: protocol-relative CDN pattern
    literal: "const RE_CDN = /\\/\\/cdn\\.[^\\s\"'<>()\\\\]+/g;"
---

# No external references in the built bundle

At runtime KubeDash makes zero outbound calls (ADR-0020): the deployed
SPA must not reference any CDN, font host, or third-party origin, and
the API docs page must not load Swagger UI from the internet.

**The contract.**

- `task fe-check` runs `tests/fe-airgap-check.mjs` over
  `frontend/dist`: it fails (exit 1, one `file:line: url` per offender)
  on any `https?://` reference or protocol-relative `//cdn.` reference,
  minus a substring allow-list of **documentation** links (w3.org,
  react.dev, datatables.net, highlightjs, coreui, …). The allow-list
  extends, never replaces, the scan; binaries are skipped except `.svg`.
- Swagger UI is served locally: `/api/docs` loads `swagger-ui.css` /
  `swagger-ui-standalone-preset.js` / `swagger-ui-bundle.js` from the
  vendored `swagger-ui-bundle` PyPI package via `importlib.resources`
  on `/api/docs/*` routes. `OPENAPI_SWAGGER_UI_URL` is a local
  placeholder kept only because smorest registers the page when that key
  is set.
- The CoreUI template is vendored in-repo (no npm-CDN runtime fetches);
  the kubectl plugin binary is distributed as a file in air-gap mode.

**Why.** Air-gapped deployments (defense, financial, OT) have no
outbound internet; a stray CDN reference is a blank pane or a hung load
that only shows up in the customer's cluster.

**Pinned by.** `backend/tests/test_fe_airgap_check.py` (clean dist
passes; CDN refs and protocol-relative refs fail with the offender),
`backend/tests/api/test_apidocs.py` (9 tests: local asset routes,
served bundle byte-identical to the package).

**Related.** ADR-0020 (decision), ADR-0006 (single container — the
bundle is what the one image ships), `workflows/frontend-build-serve.md`.
