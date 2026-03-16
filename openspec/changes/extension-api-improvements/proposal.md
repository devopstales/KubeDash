## Why

The Extension API list-projects endpoint accepts query parameters `limit` and `continue` and `fieldSelector` per Kubernetes list conventions, but only `limit` and `labelSelector` are implemented. There is no continuation token for pagination and no field-based filtering. This limits clients (e.g. kubectl, automation) that rely on standard list semantics and makes large project lists harder to consume. Implementing these closes the gap between advertised API and behavior.

## What Changes

- **Pagination:** Implement `continue` token for list projects. Return `metadata.continue` in ProjectList when more results exist; accept `continue` on the next request to return the next page. Respect `limit` per page; continuation is opaque to the client.
- **Field selector:** Implement `fieldSelector` for list projects so clients can filter by field (e.g. `metadata.name=default`, `spec.protected=true`, `status.phase=Active`). Support common K8s field-selector semantics (equality, possibly one or two well-used operators) applied after permission filtering.
- No change to auth, authz, or other endpoints. Watch remains out of scope for this change.

## Capabilities

### New Capabilities

- **projects-list-pagination:** List projects supports continuation: response may include `metadata.continue`; request may include `continue` to fetch the next page; `limit` controls page size. Behavior remains consistent with permission filtering and labelSelector.
- **projects-field-selector:** List projects (and optionally get when returning list-like responses) supports `fieldSelector` query parameter to filter results by resource fields (e.g. metadata.name, spec.protected, status.phase) using supported operators.

### Modified Capabilities

- None.

## Impact

- **Code:** `src/kubedash/blueprint/extension_api/extension_api.py` (list handler: pass continue/limit, return list with metadata.continue when applicable). `src/kubedash/lib/extension_api/projects.py` (list_projects: accept continue + limit, apply fieldSelector filter, return next continue token when more items exist). `src/kubedash/lib/extension_api/helpers.py` (build_project_list: support optional continue and remaining-count so caller can set metadata.continue).
- **APIs:** Query params `continue` and `fieldSelector` become effective on `GET /apis/kubedash.devopstales.github.io/v1/projects`. Response shape ProjectList gains optional `metadata.continue`; no breaking change to existing fields.
- **Dependencies:** None. Pagination is in-memory/cursor-style (e.g. offset or stable sort + key); no new storage.
