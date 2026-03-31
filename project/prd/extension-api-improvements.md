### PRD: Extension API Improvements

**OpenSpec change**: `openspec/changes/extension-api-improvements/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

KubeDash exposes a Kubernetes‑style **Extension API** (e.g. `Projects`), but:

- List operations can become heavy as the number of Projects grows.
- Clients lack familiar Kubernetes capabilities like pagination (`limit`/`continue`) and field selectors.

We want the Extension API to feel **first‑class and Kubernetes‑native** for CLI and automation users.

#### Goals

- Add **Kubernetes‑style pagination** and filtering to Extension API list endpoints.
- Preserve backwards compatibility for existing clients.

#### Functional Requirements

- For `Projects` and similar Extension API resources:
  - Support `limit` and `continue` query parameters consistent with Kubernetes list semantics.
  - Support field selectors for common fields (e.g. `metadata.name`, labels) where feasible.
- Responses must:
  - Include `metadata.continue` when more results are available.
  - Preserve existing fields and error formats.

#### Non‑Functional Requirements

- **Performance**
  - Pagination must be implemented efficiently at the storage layer, avoiding full scans where possible.
- **Compatibility**
  - Existing clients that do not use `limit`/`continue` must continue to receive full lists (within existing limits).

---

### Implementation Tasks (from OpenSpec)

#### 1. Pagination: Helpers and List Logic

- [x] 1.1 Extend `build_project_list` in helpers to accept optional `continue_token` and `remaining` (or equivalent); set `metadata.continue` when `remaining > 0` and token is present.
- [x] 1.2 In `projects.py` `list_projects`, apply stable sort (e.g. by `metadata.name`) to allowed projects after permission and label filtering; accept `limit` and `continue`; slice one page and compute next continue token (e.g. encode offset or last name); call `build_project_list` with `continue` and remaining count.
- [x] 1.3 In extension_api blueprint list handler, pass `limit` and `continue` from query params to `list_projects`; ensure response includes `metadata.continue` from the returned `ProjectList`.

#### 2. Continue Token Encoding

- [x] 2.1 Implement opaque continue token: generate token (e.g. base64‑encoded offset or last‑seen name + limit) when returning a page with more results; parse token in next request to resume from correct position; invalid token: return 400 or treat as first page (document choice).

#### 3. Field Selector

- [x] 3.1 Add field selector parsing in `projects.py` (or helpers): parse `fieldSelector` string into supported equalities (e.g. `metadata.name=value`, `spec.protected=true`, `status.phase=Active`); support comma‑separated AND; reject or ignore unsupported fields per design.
- [x] 3.2 In `list_projects`, after label filtering and before sort/pagination, filter projects by parsed field selector; apply to Project‑shaped items (`metadata`, `spec`, `status`).
- [x] 3.3 In extension_api blueprint list handler, pass `fieldSelector` from query params to `list_projects`.

#### 4. Tests and Docs

- [x] 4.1 Add or extend unit tests for `list_projects` with `limit`/`continue` (first page, next page, last page) and for `fieldSelector` (name, protected, phase).
- [x] 4.2 Update OpenAPI/spec or docs to describe `continue` and `fieldSelector` for list projects and document supported field selector fields.

