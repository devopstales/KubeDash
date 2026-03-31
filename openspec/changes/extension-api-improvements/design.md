## Context

- **Current state:** Extension API list projects (`GET /apis/.../v1/projects`) accepts query params `limit`, `continue`, `labelSelector`, `fieldSelector`. Only `limit` and `labelSelector` are implemented. `build_project_list()` returns a fixed structure with no `metadata.continue`. Projects are namespaces filtered by RBAC; list is built in memory after permission filtering.
- **Constraints:** Keep Kubernetes list semantics (opaque continue token, limit per page). No new external storage; pagination state must be derivable or stateless (e.g. offset in token). Field selector must run after permission and label filtering so we never expose existence of namespaces the user cannot see.

## Goals / Non-Goals

**Goals:**

- Support continuation-based pagination: client sends `continue` and `limit`; server returns a page and, when more results exist, `metadata.continue` for the next request.
- Support `fieldSelector` on list projects: filter by fields such as `metadata.name`, `spec.protected`, `status.phase` using equality (and optionally one or two operators if we align with K8s).

**Non-Goals:**

- Watch endpoint; resourceVersion semantics; server-side persistence of continue state across restarts.
- Changing auth/authz or other resources. OpenAPI/root sync and list-performance (SAR caching) are out of scope.

## Decisions

1. **Continue token format and semantics**
   - **Decision:** Use an opaque token that encodes enough to resume (e.g. offset or last-seen name + limit). Token is short-lived and not required to survive server restart. Generate and parse in the extension API layer (e.g. base64-encoded JSON or a signed/short string). Do not expose internal ordering (e.g. namespace names) in the token.
   - **Rationale:** Matches K8s “opaque to client” expectation. Avoids clients depending on internal structure. Short-lived keeps implementation simple (no distributed state).
   - **Alternative:** Offset-only token. Simpler but ordering must be stable (e.g. sort by name) so that permission/label/field filters applied in the same order produce consistent pages.

2. **Ordering and stability**
   - **Decision:** Apply a stable sort to allowed projects (e.g. by `metadata.name`) before applying limit/continue. Pagination then slices this ordered list; continue token encodes “after this name” or “offset N” so the next request reproduces the same ordering and skips already-returned items.
   - **Rationale:** Required for deterministic pages and for continue to work without re-querying from scratch. Name is unique and available on every Project.

3. **Where to apply fieldSelector**
   - **Decision:** Apply fieldSelector in the projects layer after building the list of allowed projects (and after labelSelector), and before pagination (limit/continue). So: list namespaces → permission filter → label filter → field filter → sort → paginate → build_project_list with continue.
   - **Rationale:** Field selector only filters visible items; no info leak. Single place (projects.py) keeps list logic consistent.

4. **Field selector support**
   - **Decision:** Support a small set of field equalities aligned with Kubernetes field selector syntax: e.g. `metadata.name=value`, `spec.protected=true`, `status.phase=Active`. Parse a single equality or comma-separated list; reject unsupported fields with 400 or ignore (document behavior). No “in” or complex operators in v1 unless trivial to add.
   - **Rationale:** Covers common use cases (filter by name, protected, phase). Full K8s field-selector parity is larger scope; we can extend later.

5. **build_project_list and continue**
   - **Decision:** Extend `build_project_list(projects, ..., continue_token=None, remaining=0)` so the blueprint can pass the next continue token and whether there are more items; helper sets `metadata.continue` when remaining > 0 and token is not None. Caller (list_projects) computes remaining and token after slicing the ordered list.
   - **Rationale:** Helpers stay responsible for response shape; business logic in projects.py decides pagination and token.

## Risks / Trade-offs

- **[Token validity]** Continue token may become invalid after restart or if list order changes (e.g. new namespaces). **Mitigation:** Document that continue is best-effort and clients should retry without continue on 400/404 if needed; keep token short-lived.
- **[Performance]** Building full allowed list then filtering/sorting/paginating still does O(n) SAR for non-admins. **Mitigation:** Unchanged from current behavior; list-performance is out of scope for this change.
- **[Field selector scope]** Supporting only a few fields may not match all client expectations. **Mitigation:** Document supported fields; return 400 or ignore unsupported selectors by policy.

## Migration Plan

- No data migration. Deploy code; list endpoint accepts continue and fieldSelector. Existing clients that do not send continue or fieldSelector see unchanged behavior (first page, no field filter). Rollback: revert code; continue and fieldSelector again have no effect.

## Open Questions

- None. Optional: whether to return 400 for invalid continue token vs. treat as “no continue” and return first page (K8s often returns 410 Gone for expired continue).
