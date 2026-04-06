## 1. Pagination: helpers and list logic

- [x] 1.1 Extend `build_project_list` in helpers to accept optional `continue_token` and `remaining` (or equivalent); set `metadata.continue` when remaining > 0 and token is present
- [x] 1.2 In projects.py `list_projects`, apply stable sort (e.g. by metadata.name) to allowed projects after permission and label filtering; accept `limit` and `continue`; slice one page and compute next continue token (e.g. encode offset or last name); call `build_project_list` with continue and remaining count
- [x] 1.3 In extension_api blueprint list handler, pass `limit` and `continue` from query params to `list_projects`; ensure response includes `metadata.continue` from the returned ProjectList

## 2. Continue token encoding

- [x] 2.1 Implement opaque continue token: generate token (e.g. base64-encoded offset or last-seen name + limit) when returning a page with more results; parse token in next request to resume from correct position; invalid token: return 400 or treat as first page (document choice)

## 3. Field selector

- [x] 3.1 Add field selector parsing in projects.py (or helpers): parse `fieldSelector` string into supported equalities (e.g. metadata.name=value, spec.protected=true, status.phase=Active); support comma-separated AND; reject or ignore unsupported fields per design
- [x] 3.2 In `list_projects`, after label filtering and before sort/pagination, filter projects by parsed field selector; apply to Project-shaped items (metadata, spec, status)
- [x] 3.3 In extension_api blueprint list handler, pass `fieldSelector` from query params to `list_projects`

## 4. Tests and docs

- [x] 4.1 Add or extend unit tests for list_projects with limit/continue (first page, next page, last page) and for fieldSelector (name, protected, phase)
- [x] 4.2 Update OpenAPI/spec or docs to describe `continue` and `fieldSelector` for list projects and document supported field selector fields
