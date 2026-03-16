## ADDED Requirements

### Requirement: List projects supports pagination with continue token

The system SHALL support Kubernetes-style list pagination for projects. A request MAY include query parameters `limit` (positive integer, page size) and `continue` (opaque token from a previous list response). The response SHALL include up to `limit` items. When more items exist, the response SHALL include `metadata.continue` set to an opaque token that the client MAY use in a subsequent request as the `continue` parameter to retrieve the next page. When no more items exist, `metadata.continue` SHALL be omitted or empty.

#### Scenario: First page with limit

- **WHEN** client sends GET list projects with `limit=10` and no `continue`
- **THEN** the server returns a ProjectList with at most 10 items and, if more projects exist, a non-empty `metadata.continue` token

#### Scenario: Next page with continue

- **WHEN** client sends GET list projects with `limit=10` and `continue=<token>` where the token was returned in a previous list response
- **THEN** the server returns the next page of at most 10 items and, if more exist, a new `metadata.continue` token; items SHALL NOT duplicate items from the previous page

#### Scenario: Last page

- **WHEN** client sends GET list projects with `continue=<token>` and the token corresponds to the last page
- **THEN** the server returns a ProjectList with no `metadata.continue` (or empty) and the remaining items

#### Scenario: Pagination respects permission and label selector

- **WHEN** client uses limit and continue to page through list projects
- **THEN** only projects the user is allowed to see (and that match labelSelector if present) are included in the paginated result set; ordering SHALL be stable so pages are consistent
