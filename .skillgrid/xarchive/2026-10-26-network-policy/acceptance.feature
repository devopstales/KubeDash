Feature: KubeDash network policies — 4.1 parity list + detail
  # briefing.md R1-R5. ADR-0004 (SAR is the only gate; the cache key
  # carries every SAR attribute), ADR-0010 (reads through the pool seam;
  # the informer cache interposes later), ADR-0020 (air gap), ADR-0022
  # (retires one stub parity row). The certainty rule (AGENTS.md):
  # Cilium absence is the EXPECTED state and degrades to empty, never an
  # error; a read KubeDash cannot make is an error, never a silent empty.
  # Scenario names are the SATISFIES oracle for the blueprint tasks and
  # the test titles. Each scenario's class (happy path / edge / failure)
  # is the comment on its first line.

  Background:
    Given the KubeDash single-page app with the API mocked
    And a registered cluster named "prod" is selected
    And the header namespace selector is on "team-a"

  # -------------------------------------------------- R1: vanilla kind

  Scenario: networkpolicies-list-namespaced
    # happy path - R1
    Given the cluster has a NetworkPolicy named "deny-all" in namespace "team-a"
    When the API is asked for cluster "prod" resources "networkpolicies" with namespace "team-a"
    Then the API responds 200 with kind "networkpolicies" and one item
    And the item is the kubernetes to_dict form with spec policy_types, ingress and egress intact

  Scenario: networkpolicies-list-all-namespaces
    # edge - R1 (no namespace query)
    Given the cluster has NetworkPolicies in two namespaces
    When the API is asked for cluster "prod" resources "networkpolicies" without a namespace
    Then the API responds 200 with the items from all namespaces

  Scenario: networkpolicies-get-by-name
    # happy path - R1 (?name= contract, mirrors get_secret)
    Given the cluster has a NetworkPolicy named "deny-all" in namespace "team-a"
    When the API is asked for cluster "prod" resources "networkpolicies" with name "deny-all" and namespace "team-a"
    Then the API responds 200 with exactly one item named "deny-all"
    When the API is asked for cluster "prod" resources "networkpolicies" with name "ghost" and namespace "team-a"
    Then the API responds 200 with zero items

  Scenario: networkpolicies-sar-denied
    # failure - R1 (ADR-0004: the SAR is asked BEFORE the read)
    Given a user who cannot list networkpolicies in group "networking.k8s.io"
    When the API is asked for cluster "prod" resources "networkpolicies" with namespace "team-a"
    Then the API responds 403 RBAC_DENIED naming "networkpolicies"
    And no cluster read is attempted

  Scenario: networkpolicies-binding-404
    # failure - R1 (binding gate before the SAR)
    Given a user with no binding to cluster "prod"
    When the API is asked for cluster "prod" resources "networkpolicies"
    Then the API responds 404 CLUSTER_NOT_FOUND

  Scenario: networkpolicies-kind-singular-rejected
    # edge - R1 (the 4.1 route name is not a kind)
    When the API is asked for cluster "prod" resources "network-policy"
    Then the API responds 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------------- R2: Cilium

  Scenario: cilium-list-uses-served-version
    # happy path - R2 (version autodetection; no hardcoded cilium.io/v2)
    Given the cluster runs Cilium with a CRD served on version "v2alpha1"
    And the CRD has one CiliumNetworkPolicy named "cnp" in namespace "team-a"
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with namespace "team-a"
    Then the API responds 200 with one item
    And the item has spec endpointSelector, ingress and egress intact

  Scenario: cilium-crds-absent-empty
    # edge - R2 (Cilium not installed = expected state, not an error)
    Given the cluster has no cilium.io CRDs
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with namespace "team-a"
    Then the API responds 200 with zero items
    And the API is asked for cluster "prod" resources "ciliumclusterwidenetworkpolicies"
    And the API responds 200 with zero items

  Scenario: cilium-crds-error-502
    # failure - R2 (a read KubeDash cannot make is an error)
    Given the cluster's cilium.io API returns an internal error
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with namespace "team-a"
    Then the API responds 502 CLUSTER_UNREACHABLE

  Scenario: cilium-clusterwide-ignores-namespace
    # edge - R2 (cluster-scoped kind)
    Given the cluster has one CiliumClusterwideNetworkPolicy named "ccnp"
    When the API is asked for cluster "prod" resources "ciliumclusterwidenetworkpolicies" with namespace "team-a"
    Then the API responds 200 with the "ccnp" item
    When the API is asked for cluster "prod" resources "ciliumclusterwidenetworkpolicies" with name "ccnp"
    Then the API responds 404 RESOURCE_KIND_NOT_SUPPORTED

  Scenario: cilium-get-by-name
    # happy path - R2 (namespaced kind only)
    Given the CRD has one CiliumNetworkPolicy named "cnp" in namespace "team-a"
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with name "cnp" and namespace "team-a"
    Then the API responds 200 with exactly one item named "cnp"
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with name "ghost" and namespace "team-a"
    Then the API responds 200 with zero items
    Given the cluster has no cilium.io CRDs
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with name "cnp" and namespace "team-a"
    Then the API responds 200 with zero items

  Scenario: cilium-sar-gated
    # failure - R2 (the SAR carries the cilium.io group)
    Given a user who cannot list ciliumnetworkpolicies in group "cilium.io"
    When the API is asked for cluster "prod" resources "ciliumnetworkpolicies" with namespace "team-a"
    Then the API responds 403 RBAC_DENIED naming "ciliumnetworkpolicies"
    And the SAR was asked with group "cilium.io" and namespace "team-a"
    And no cluster read is attempted

  # ------------------------------------------------- R3: list view

  Scenario: list-renders-namespace-policies
    # happy path - R3
    Given the mocked API returns one NetworkPolicy for namespace "team-a"
    When the user opens "/security/network-policy"
    Then the table shows the policy name, policy types, ingress rule count, egress rule count and the created timestamp in local time
    And the name links to "/security/network-policy/data" with kind "NetworkPolicy"

  Scenario: list-cilium-section-shown-when-present
    # happy path - R3 (4.1 appends clusterwide to every namespace view)
    Given the mocked API returns one CiliumNetworkPolicy and one CiliumClusterwideNetworkPolicy
    When the user opens "/security/network-policy"
    Then a separate Cilium section is rendered with both rows
    And the rows link with kind "CiliumNetworkPolicy" and "CiliumClusterwideNetworkPolicy"

  Scenario: list-cilium-section-hidden-when-empty
    # edge - R3 (Cilium absent, or no policies: equivalent for the user)
    Given the mocked API returns empty lists for both Cilium kinds
    When the user opens "/security/network-policy"
    Then no Cilium section is rendered

  Scenario: list-no-cluster-state
    # edge - R3
    Given no cluster is selected
    When the user opens "/security/network-policy"
    Then the page shows "No cluster selected." and no resource fetch is made

  Scenario: list-error-state
    # failure - R3
    Given the networkpolicies fetch rejects with RBAC_DENIED
    When the user opens "/security/network-policy"
    Then the page shows an error line with the message and no blank table

  # ------------------------------------------------ R4: detail view

  Scenario: detail-renders-policy-yaml
    # happy path - R4 (single read, not 4.1's list-then-filter)
    Given the mocked API returns one item for the ?name= lookup
    When the user opens "/security/network-policy/data?name=deny-all&kind=NetworkPolicy&namespace=team-a"
    Then the page fetches exactly one resource URL for kind "NetworkPolicy"
    And the policy metadata is shown
    And the full object is rendered as highlighted YAML containing the policy name

  Scenario: detail-not-found-state
    # edge - R4 (empty items upstream is a state, not an error)
    Given the mocked API returns an empty items list for the ?name= lookup
    When the user opens "/security/network-policy/data?name=ghost&kind=NetworkPolicy&namespace=team-a"
    Then the page shows a "not found" state naming "ghost"

  Scenario: detail-bad-kind-client-error
    # edge - R4 (closed enum, caught before any fetch)
    When the user opens "/security/network-policy/data?name=deny-all&kind=Foo&namespace=team-a"
    Then no resource fetch is made
    And the page shows an error line naming the invalid kind

  Scenario: detail-clusterwide-omits-namespace
    # edge - R4 (cluster-scoped kind sends no namespace param)
    Given the mocked API returns one item for the clusterwide ?name= lookup
    When the user opens "/security/network-policy/data?name=ccnp&kind=CiliumClusterwideNetworkPolicy"
    Then the fetched URL contains no namespace parameter

  # --------------------------------------------------- R5: stub removal

  Scenario: stub-route-retired
    # happy path - R5
    When the router is rendered with the real views
    Then "/security/network-policy" resolves to the NetworkPolicy view, not the stub
    And the e2e smoke path for "/security/network-policy" still passes

  # ------------------------------------------- integration (kind-gated)

  Scenario: networkpolicies-list-on-kind
    # integration backstop - R1 (held-out test, Task 5)
    Given a kind cluster with a deny-all NetworkPolicy applied in namespace "default"
    When the API is asked for the kind cluster resources "networkpolicies" with namespace "default"
    Then the API responds 200 with the applied policy and spec policy_types ["Ingress", "Egress"]

  Scenario: cilium-absent-on-live-cluster-empty
    # integration backstop - R2 (held-out test, Task 5: the REAL apiserver's
    # "group unregistered" shape is what the unit fakes cannot pin)
    Given a bare kind cluster with no cilium.io CRDs
    When the API is asked for the kind cluster resources "ciliumnetworkpolicies" with namespace "default"
    Then the API responds 200 with zero items, not a 502
    When the API is asked for the kind cluster resources "ciliumclusterwidenetworkpolicies"
    Then the API responds 200 with zero items, not a 502
