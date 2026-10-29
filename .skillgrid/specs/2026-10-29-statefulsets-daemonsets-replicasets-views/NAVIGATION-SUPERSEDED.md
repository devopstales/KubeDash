# Navigation Contract — Superseded (2026-10-29)

**Status:** SUPERSEDED — recorded 2026-10-29 by
`2026-10-29-session-object-navigation`.

The `?name=` / `?namespace=` query-param navigation ratified in this spec
(`adr.md` Deviations; `briefing.md` Navigation line; `blueprint.md` data-page
route shape; `acceptance.feature` link/URL scenarios) is replaced by the
session-based object navigation contract:

- Object selection (kind, name, namespace) lives in tab-private
  `sessionStorage` (`kd_object_refs` registry + `kd_object_active` pointer);
  **no object identity rides in the URL**.
- List rows open the detail via `setObjectRef(...)` (in-tab) or a same-origin
  form **POST** (cross-tab deep link); the data page route carries no query
  string.
- The `/.../data` route suffix is merged into the list route (one route per
  kind; detail renders when the active ref matches the kind).
- Old URLs (`/x/y/data?name=...&namespace=...`) are redirected one-shot to
  the clean list route with the ref hydrated.

Where this spec's artifacts still name the query-param shape (link targets,
`/data` URLs, `?namespace=` reads), treat them as describing the SUPERSEDED
contract: the migrated views follow `2026-10-29-session-object-navigation`.
The backend `?name=`/`?namespace=` REST query params on
`/api/v1/clusters/:id/resources/<kind>` are unchanged (GET filtering, not
navigation).

**Execution note (2026-10-29):** this change is still in flight (not yet
landed). Execute its views to the NEW contract directly (session object ref +
form-POST deep link, no `/data` suffix) instead of building the query-param
shape and migrating it.
