## ADDED Requirements

### Requirement: User can view available clusters
The system SHALL display a list of clusters accessible to the current user based on their permissions.

#### Scenario: Admin views all clusters
- **WHEN** admin user accesses cluster switcher
- **THEN** system displays all active clusters with health status indicators

#### Scenario: User views permitted clusters only
- **WHEN** non-admin user accesses cluster switcher
- **THEN** system displays only clusters where user has explicit role assignment

#### Scenario: Cluster list shows health status
- **WHEN** cluster switcher displays clusters
- **THEN** each cluster shows health indicator (green=healthy, red=unhealthy, gray=unknown)

#### Scenario: Current cluster highlighted
- **WHEN** cluster switcher displays
- **THEN** currently selected cluster is visually highlighted with checkmark or different background

### Requirement: User can switch cluster context
The system SHALL allow users to change their current cluster context with immediate effect.

#### Scenario: Successful cluster switch
- **WHEN** user selects different cluster from switcher
- **THEN** system updates session cluster context and reloads current page with new cluster data

#### Scenario: Cluster switch persists across navigation
- **WHEN** user switches to cluster A and navigates to different pages
- **THEN** system maintains cluster A context until user explicitly switches

#### Scenario: Cluster switch to unhealthy cluster warning
- **WHEN** user switches to cluster with unhealthy status
- **THEN** system shows warning toast "Cluster '{name}' may be unreachable" but allows switch

#### Scenario: Default cluster on login
- **WHEN** user logs in
- **THEN** system selects default cluster (marked `is_default=true`) as initial context

#### Scenario: No default cluster fallback
- **WHEN** user logs in and no cluster is marked as default
- **THEN** system selects first healthy cluster as default context

### Requirement: System maintains cluster context per session
The system SHALL maintain cluster context in user session storage.

#### Scenario: Session stores cluster name
- **WHEN** user switches to cluster A
- **THEN** system stores `session['current_cluster'] = 'cluster-a'`

#### Scenario: Session expiration clears context
- **WHEN** user session expires
- **THEN** system clears cluster context and requires re-selection on next login

#### Scenario: Multi-tab session synchronization
- **WHEN** user switches cluster in one browser tab
- **THEN** other tabs maintain old context until navigation (session is user-level, not tab-level)

### Requirement: System resolves cluster for each request
The system SHALL resolve cluster context for each incoming request using defined precedence.

#### Scenario: API query parameter takes precedence
- **WHEN** request includes `?cluster=cluster-name` query parameter
- **THEN** system uses specified cluster regardless of session context

#### Scenario: Session context used for UI requests
- **WHEN** request has no cluster parameter and session has `current_cluster`
- **THEN** system uses session cluster context

#### Scenario: Default cluster fallback
- **WHEN** request has no cluster parameter and session has no context
- **THEN** system uses default cluster (`is_default=true`)

#### Scenario: No cluster available error
- **WHEN** request has no cluster parameter, session has no context, and no default cluster exists
- **THEN** system returns 400 error "No cluster context available"

### Requirement: System indicates cluster context in UI
The system SHALL clearly display current cluster context throughout the UI.

#### Scenario: Global cluster switcher visible
- **WHEN** user views any authenticated page
- **THEN** cluster switcher dropdown is visible in global navigation header

#### Scenario: Current cluster name displayed
- **WHEN** cluster switcher is viewed
- **THEN** current cluster name is prominently displayed in dropdown button

#### Scenario: Cluster health badge
- **WHEN** cluster switcher is viewed
- **THEN** health status badge (colored dot) appears next to cluster name

#### Scenario: Cluster metadata on hover
- **WHEN** user hovers over cluster in switcher
- **THEN** tooltip shows cluster API URL, Kubernetes version, and node count

### Requirement: System handles cluster unavailability gracefully
The system SHALL provide clear feedback when selected cluster becomes unavailable.

#### Scenario: Cluster becomes unreachable during session
- **WHEN** user's selected cluster becomes unreachable (network issue, cluster down)
- **THEN** system shows error "Cluster '{name}' is unreachable" with option to switch clusters

#### Scenario: Auto-switch on cluster deletion
- **WHEN** user's selected cluster is deleted by admin
- **THEN** system automatically switches user to default cluster on next request with notification

#### Scenario: Resource not found due to cluster switch
- **WHEN** user navigates to bookmarked URL for resource in cluster that no longer exists
- **THEN** system shows 404 with message "Resource not found in cluster '{name}'" and cluster switcher
