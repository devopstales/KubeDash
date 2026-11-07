Feature: Frontend kind registry (generated routes + shared list/data views)

  # One typed registry (src/lib/kinds.ts) owns every standard kind's
  # route / plural / title / redirect / custom flag; App.tsx renders its
  # resource routes from the registry (one generated route pair per
  # standard row) instead of 39 hand-unrolled blocks (21 ObjectRoute +
  # 18 OldDataRedirect). The 13 fully-standard view pairs + the
  # role/clusterrole list-find pairs become thin config wrappers over
  # two shared components; the 8 divergent sides keep hand-rolled views;
  # the 3 custom dispatcher routes stay explicit. No behaviour change:
  # titles byte-identical (unit pins + e2e strings frozen), one lazy
  # chunk per view, legacy /data redirects intact where they shipped.

  # R1 - registry invariants
  Scenario: the registry rows are keyed by kind with unique routes
    Given the registry loads with its rows transcribed from the current App.tsx route blocks
    When the registry invariants test runs over all 24 rows
    Then every row is keyed by a unique kind
    And every row's route is unique across the registry
    And the 21 standard rows plus the 3 custom rows account for every row

  Scenario: the registry standard-kind set matches the app route table
    Given the expected-kinds fixture lists the 21 standard kinds
    When the registry invariants test compares the standard rows
    Then the standard-kind set equals the fixture exactly
    And no standard kind is missing and none is extra

  Scenario: the registry rows carry verbatim titles and non-empty plurals
    Given every registry row carries its title and plural
    When the registry invariants test inspects each row
    Then every title equals its view's CCardTitle string verbatim
    And every plural is non-empty and matches its view's fetch URL
    And legacy-data defaults to true unless a row says false

  Scenario: the registry marks legacy-data false only for the six storage kinds
    Given the six storage rows storageclass configmap snapshotclass volumesnapshot pvc persistentvolume
    When the registry invariants test checks the legacy-data flags
    Then those six rows carry legacyData false
    And every other standard row carries legacyData true

  Scenario: a registry side is shared-rendered exactly when its factory is absent
    Given each registry row may carry a list factory and a data factory
    When the registry invariants test classifies each standard row's sides
    Then a side is shared-rendered if and only if its factory is absent
    And each custom row carries no factories and a non-empty kinds array

  # R2 - generated routes
  Scenario: standard kind routes are generated from the registry
    Given App.tsx renders its resource routes from the registry
    When the generated route table is evaluated over the 21 standard rows
    Then each standard row yields an ObjectRoute at its registry route
    And each row whose legacy-data is true yields a legacy /data OldDataRedirect route
    And both route elements wrap their content in ProtectedRoute
    And the non-resource routes for login clusters dashboard profile permissions kubeconfig admin and stubs are untouched

  Scenario: the six storage kinds emit no legacy data redirect route
    Given the six storage rows carry legacyData false
    When the generated route table is evaluated over the standard rows
    Then no legacy /data redirect route exists for any of the six storage routes
    And their list routes are still served by generated ObjectRoutes

  Scenario: adding a standard kind requires no App.tsx edit
    Given a new standard registry row for kind "webhook" with route "/other-resource/webhook"
    When the route generator runs over the registry
    Then the generator emits the ObjectRoute and legacy /data pair for the new row
    And App.tsx contains no kind-specific route literal for "webhook"

  # R3 - shared components
  Scenario: the shared list view opens the data view via openObject on the same route
    Given ResourceListView renders with a stub spec for kind "limitrange"
    And the MSW handler serves two rows for the registry plural
    When the list renders its KubeDataTable rows
    Then the card title equals spec.title exactly
    And clicking a row's name cell calls openObject with spec.kind the row name the namespace and spec.route
    And no object identity appears in the URL

  Scenario: the shared data view renders detail with a muted not-found state
    Given ResourceDataView renders with spec name and namespace for kind "limitrange"
    And the fetch returns the object
    When the data view renders
    Then the metadata table and the detail table render
    And a JSON highlight block is present
    And clicking the breadcrumb list item clears the active ref

  Scenario: the shared data view shows a muted not-found state on a miss
    Given ResourceDataView renders with spec name and namespace
    And the fetch returns no object
    When the data view renders
    Then it shows the muted NOT_FOUND state

  Scenario: the list-find data variant fetches the full list and finds client-side
    Given ResourceDataView renders with dataVariant "list-find" for kind "role"
    And the fetch serves the full role list containing "rbac-admin"
    When the data view renders for name "rbac-admin"
    Then it fetches the full list and finds the object client-side
    And it renders the transcribed data title with no metadata table and no JSON block
    And a miss renders the muted NOT_FOUND state

  # Door check - the two tracers
  Scenario: the tracer kinds render end-to-end through the generated registry
    Given limitrange and role are registry rows and their view pairs are thin wrappers
    When the routes for "/other-resource/limitrange" and "/cluster-permission/role" resolve
    Then the generated ObjectRoutes render the shared list views
    And legacy /data URLs for both kinds redirect to the clean routes
    And the hand-unrolled limitrange and role blocks are gone from App.tsx

  Scenario: the converted tracer views keep one chunk each
    Given a vite build over the converted tracers
    When the dist/assets chunk list is compared against the pre-change build
    Then separate LimitRange and Role chunks still exist
    And no two converted view files share a chunk

  Scenario: the door-check unit title pins stay green unedited
    Given the unit title pins in the limit_ranges limit_range_data and roles tests
    When the full unit suite runs after the tracer cutover
    Then the pinned title assertions pass with zero edits
    And any per-kind branch required inside a shared component is reported as a door-check failure

  # Migrate batches
  Scenario: batch A kinds render through the generated registry
    Given serviceaccount clusterrole namespace node and crd are registry rows
    When the routes for their kinds resolve
    Then clusterrole renders the shared list with the list-find data variant
    And serviceaccount and crd render shared lists with their hand-rolled data views
    And namespace and node render their hand-rolled views through the registry lazy factories
    And their remaining hand-unrolled blocks are gone from App.tsx
    And legacy /data redirects for their routes behave as today

  Scenario: batch B kinds render through the generated registry
    Given secret priorityclass runtimeclass resourcequota poddisruptionbudget verticalpodautoscaler horizontalpodautoscaler and service are registry rows
    When the routes for their kinds resolve
    Then secret renders the shared list with its hand-rolled data view
    And the seven fully-standard kinds render the shared list and data views
    And their hand-unrolled blocks are gone from App.tsx
    And legacy /data redirects for their routes behave as today

  Scenario: batch C storage kinds render without legacy data redirects
    Given storageclass configmap snapshotclass volumesnapshot pvc and persistentvolume are registry rows with legacyData false
    When the routes for their kinds resolve
    Then the five fully-standard kinds render the shared list and data views
    And persistentvolume renders its hand-rolled list and the shared data view
    And their hand-unrolled blocks are gone from App.tsx
    And no legacy /data redirect route exists for any of the six

  Scenario: custom-rendered sides keep their hand-rolled behaviour
    Given the eight custom-rendered sides across the three batches
    When their views render after conversion
    Then the serviceaccount crd and secret data views keep their reveal clipboard and instance-specific behaviour
    And the namespace and node views keep their admin buttons delete columns rollup tiles and metrics queries
    And persistentvolume keeps its claim filter metrics join and usage cells
    And no title assertion in their view tests is edited

  # Contract close
  Scenario: the custom dispatcher routes read their paths from the registry
    Given the three custom rows for the ingress ingress-class and network-policy dispatchers carry kinds arrays
    When the three custom route blocks in App.tsx render
    Then their path strings come from their registry rows
    And no path literal remains in the custom blocks
    And the tabbed ingress and ingress-class lists and the network-policy dispatcher behave as today

  Scenario: the per-view clone family is gone among shared-rendered kinds
    Given a jscpd run over frontend/src/views
    When the clone report is compared against the pre-change baseline
    Then the per-view clone family among shared-rendered kinds is gone
    And the eight custom-rendered sides remain hand-rolled by design

  Scenario: the hand-unrolled standard route blocks are gone from App.tsx
    Given all four conversion tickets are complete
    When App.tsx is inspected
    Then no ObjectRoute or OldDataRedirect block remains for a standard kind
    And only the three custom dispatcher blocks and the named out-of-scope blocks remain
    And App.tsx is under roughly 700 lines

  Scenario: the e2e view title strings stay green unedited
    Given the e2e sweep asserts the five view-derived strings
    When the full e2e run executes after the change
    Then the strings "Ingress List" "IngressClass List" "Persistent Volume List" "CRD Data — ConfigMap" and "Namespace List" all pass
    And no e2e or unit title assertion was edited
