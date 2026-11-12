Feature: Navigation seam (kind-keyed navigate registry + multi-kind ObjectRoute)

  Background:
    Given I am logged in as a local admin
    And a bound cluster "local" is selected in the header
    And the header namespace selector shows "team-a"

  # R2 — kind-keyed registry (registerNavigate / unregisterNavigate / getNavigateFor)
  Scenario: registering for one kind leaves other kinds intact
    Given the navigate registry has fn f1 registered for kind "a"
    When fn f2 is registered for kind "b"
    Then getNavigateFor("a") returns f1
    And getNavigateFor("b") returns f2

  Scenario: re-registering a kind replaces only that kind's fn
    Given the navigate registry has fn f1 registered for kind "a"
    And fn f0 is registered for kind "b"
    When fn f2 is registered for kind "a"
    Then getNavigateFor("a") returns f2
    And getNavigateFor("b") returns f0

  Scenario: unmounting removes only the fn the route registered
    Given a route is mounted and registered for kind "a" with fn f1
    And fn f2 is registered for kind "a"
    When the first route unmounts
    Then getNavigateFor("a") returns f2

  Scenario: after the last route for a kind unmounts the lookup is empty
    Given a route is mounted and registered for kind "a"
    When the route unmounts
    Then getNavigateFor("a") returns nothing

  Scenario: the route table's kind sets are disjoint
    Given the kind arrays of every route in App.tsx (the 5 multi-kind routes + every single-kind route)
    When the kinds are compared across routes
    Then no kind appears in more than one route's array

  # R1 — ObjectRoute kinds: string[] (breaking prop, no compat alias)
  Scenario: a matching ref renders the detail on a multi-kind route
    Given ObjectRoute is rendered with kinds ["ingress", "gateway", "httproute", "referencegrant"]
    And the active object ref is { kind: "gateway", name: "gw-1", namespace: "team-a" }
    When the route renders
    Then the detail is rendered
    And the list is not rendered

  Scenario: a foreign-kind ref renders the list
    Given ObjectRoute is rendered with kinds ["ingress", "gateway"]
    And the active object ref is { kind: "service", name: "web", namespace: "team-a" }
    When the route renders
    Then the list is rendered
    And the detail is not rendered

  Scenario: detail receives the matched kind as a param
    Given ObjectRoute is rendered with kinds ["ingress", "gateway"]
    And the active object ref is { kind: "gateway", name: "gw-1", namespace: "team-a" }
    When the route renders
    Then the detail received params { name: "gw-1", namespace: "team-a", kind: "gateway" }

  Scenario: a single-kind route passes its own kind to detail
    Given ObjectRoute is rendered with kinds ["secret"]
    And the active object ref is { kind: "secret", name: "db-creds", namespace: "team-a" }
    When the route renders
    Then the detail received params kind "secret"

  # R3 — dispatcher inventory (5 dispatchers: 3 converted, 2 kept hand-rolled)
  Scenario: the three in-scope dispatchers collapse into single ObjectRoute elements
    Given the routes /security/network-policy, /network/ingress and /network/ingress-class
    When App.tsx is inspected
    Then each route renders exactly one ObjectRoute element with its kind array
    And the components NetworkPolicyRoute, IngressRoute and IngressClassRoute no longer exist

  Scenario: a ref of each converted kind renders the right detail
    Given the /network/ingress route is mounted
    When the active object ref is { kind: "ingress", name: "ing-1", namespace: "team-a" } and the route renders
    Then the Ingress data view for "ing-1" in "team-a" is rendered
    When the active object ref is { kind: "gateway", name: "gw-1", namespace: "team-a" } and the route renders
    Then the GatewayApi data view for "gw-1" of kind "gateway" in "team-a" is rendered

  Scenario: cert-manager and external-LB dispatchers stay hand-rolled after the conversion
    Given the routes /network/cert-manager and /network/external-loadbalancer
    When App.tsx is inspected after the conversion
    Then the components CertManagerRoute and ExternalLoadBalancerRoute still exist
    And each still renders its hand-rolled list and detail

  Scenario: the out-of-scope dispatchers register through the kind-keyed API
    Given the 5 multi-kind dispatchers in App.tsx
    When the seam registrations are inspected
    Then every registration calls registerNavigate with a kind array and an unmount cleanup
    And no single-argument registerNavigate call remains

  # R5 — behaviour unchanged except the one documented relay delta (ADR-0040)
  Scenario: the kindFromParam legacy redirect is unchanged
    Given the /security/network-policy/data redirect route is mounted with kindFromParam
    When I open the legacy URL "/security/network-policy/data?kind=CiliumNetworkPolicy&name=cp-1&namespace=team-a"
    Then the detail for "cp-1" of kind "CiliumNetworkPolicy" in "team-a" is rendered
    And the final URL is exactly "/security/network-policy" with no query string

  Scenario: a foreign kind param on the legacy redirect renders the list
    Given the /security/network-policy/data redirect route is mounted with kindFromParam
    When I open the legacy URL "/security/network-policy/data?kind=pod&name=p-1&namespace=team-a"
    Then the NetworkPolicy list for "team-a" is rendered

  Scenario: a deep link to a converted multi-kind route consumes the relay on mount
    Given a one-shot relay is seeded for the ref { kind: "gateway", name: "gw-1", namespace: "team-a" }
    When I open /network/ingress by plain GET
    Then the GatewayApi data view for "gw-1" of kind "gateway" in "team-a" is rendered
    And the relay key self-deletes from localStorage

  Scenario: relay consumption on single-kind routes is unchanged
    Given a one-shot relay is seeded for the ref { kind: "secret", name: "db-creds", namespace: "team-a" }
    When I open /security/secret by plain GET
    Then the Secret data page for "db-creds" in "team-a" is rendered
    And the relay key self-deletes from localStorage

  # R4 — relay TTL pinned on both sides of the boundary
  Scenario: the relay TTL pair is pinned on both sides of the boundary
    Given the frontend constant RELAY_TTL_MS in src/lib/objectRef.ts
    And the backend constant STASH_TTL_SECONDS in app/core/object_handoff.py
    When both pin tests run
    Then RELAY_TTL_MS is 60_000 and its test names STASH_TTL_SECONDS
    And STASH_TTL_SECONDS is 60 and its test names RELAY_TTL_MS

  # Seam contract + verification floor
  Scenario: the single-slot navigate global is gone
    Given the frontend/src tree after the change
    When I grep for "registeredNavigate" and "getRegisteredNavigate"
    Then there are zero hits

  Scenario: object-navigation e2e is green
    Given the built app under kind + Helm
    When the e2e suite runs (task e2e)
    Then every object-navigation scenario passes
