Feature: Cert-Manager + External Load Balancer views (moved from /plugins/ to /network/)
  As an operator inspecting cert-manager TLS objects and the external
  LoadBalancer provider (MetalLB / Cilium),
  I want the 4.1 plugin views at /network/cert-manager and
  /network/external-loadbalancer (4-tab list + per-type data,
  provider-detected),
  so the plugin views resolve to first-class Network-group views at their
  /network/ paths (the /plugins/ → /network/ move, ratified 2026-10-29 —
  folded into Network, NOT a Plugins group revived; ADR-0022's "minus
  Plugins" stays intact).

  # Backend — the 4 cert-manager.io CRD kinds (the get_crd_served seam).

  Scenario: clusterissuers list (cluster-scoped) — 200, full custom objects
    When the cert-manager clusterissuers CRD is served
    And the user is bound to a cluster
    And the user may "list" clusterissuers on cert-manager.io
    When they GET /api/clusters/c1/resources/clusterissuers
    Then the response is 200
    And the body kind is "clusterissuers"
    And each item is a FULL custom object (camelCase, spec/status intact)
    # certmanager-clusterissuers-list-200

  Scenario: issuers list (namespaced) — 200, full custom objects
    When the cert-manager issuers CRD is served
    And the user may "list" issuers in ns-a
    When they GET /api/clusters/c1/resources/issuers?namespace=ns-a
    Then the response is 200
    And the body kind is "issuers"
    # certmanager-issuers-list-200

  Scenario: certificaterequests list (namespaced) — 200
    When the user may "list" certificaterequests in ns-a
    When they GET /api/clusters/c1/resources/certificaterequests?namespace=ns-a
    Then the response is 200
    And the body kind is "certificaterequests"
    # certmanager-certificaterequests-list-200

  Scenario: certificates list (namespaced) — 200
    When the user may "list" certificates in ns-a
    When they GET /api/clusters/c1/resources/certificates?namespace=ns-a
    Then the response is 200
    And the body kind is "certificates"
    # certmanager-certificates-list-200

  Scenario: cert-manager CRD absent — 200, empty list (first-class, NOT 502)
    When the cert-manager CRDs are NOT installed (get_crd_served -> None)
    When they GET /api/clusters/c1/resources/clusterissuers
    Then the response is 200
    And the body items is an empty list
    And no ClusterUnreachableError (502) is raised
    # certmanager-crd-absent-empty

  Scenario: get-by-name returns a 0/1-item list
    When they GET /api/clusters/c1/resources/certificates?namespace=ns-a&name=c1
    Then the response is 200
    And the body items has at most one item (the full custom object)
    When they GET /api/clusters/c1/resources/certificates?namespace=ns-a&name=missing
    Then the body items is an empty list
    # certmanager-get-by-name

  Scenario: cert-manager SAR deny — 403 RBAC_DENIED
    When the user may NOT "list" clusterissuers on cert-manager.io
    When they GET /api/clusters/c1/resources/clusterissuers
    Then the response is 403
    And the body error is "RBAC_DENIED"
    And the SAR (list clusterissuers) was made before the k8s call
    # certmanager-sar-denied

  Scenario: the singular cert-manager kinds are rejected
    When they GET /api/clusters/c1/resources/clusterissuer
    Then the response is 404
    And the body error is "RESOURCE_KIND_NOT_SUPPORTED"
    # certmanager-kind-singular-rejected

  Scenario: cert-manager binding 404
    When the user is NOT bound to the cluster
    When they GET /api/clusters/c1/resources/issuers?namespace=ns-a
    Then the response is 404
    # certmanager-binding-404

  # Backend — the 4 external-LB CRD kinds (provider-detection).

  Scenario: ipaddresspools list — MetalLB present -> the MetalLB read, provider tag
    When the MetalLB ipaddresspools CRD is served
    And the user may "list" ipaddresspools in ns-a
    When they GET /api/clusters/c1/resources/ipaddresspools?namespace=ns-a
    Then the response is 200
    And each item has a provider field "metallb"
    # exlb-ipaddresspools-list-200-provider-detect

  Scenario: ipaddresspools provider fallback — MetalLB absent, Cilium present
    When the MetalLB ipaddresspools CRD is NOT served
    And the Cilium ciliumloadbalancerippools CRD is served
    When they GET /api/clusters/c1/resources/ipaddresspools?namespace=ns-a
    Then the response is 200
    And each item has a provider field "cilium"
    And the read was the CLUSTER-scoped Cilium call
    # exlb-provider-fallback-cilium

  Scenario: ipaddresspools both providers absent — empty
    When neither the MetalLB nor the Cilium ipaddresspools CRD is served
    When they GET /api/clusters/c1/resources/ipaddresspools?namespace=ns-a
    Then the response is 200
    And the body items is an empty list
    # exlb-provider-absent-empty

  Scenario: bgpadvertisements is MetalLB-only (no Cilium fallback)
    When the MetalLB bgpadvertisements CRD is NOT served
    When they GET /api/clusters/c1/resources/bgpadvertisements?namespace=ns-a
    Then the response is 200
    And the body items is an empty list
    # exlb-bgpadvertisements-metallb-only

  Scenario: external-LB get-by-name returns a 0/1-item list
    When they GET /api/clusters/c1/resources/l2advertisements?namespace=ns-a&name=l2-a
    Then the body items has at most one item
    When they GET /api/clusters/c1/resources/l2advertisements?namespace=ns-a&name=missing
    Then the body items is an empty list
    # exlb-get-by-name

  Scenario: the singular external-LB kinds are rejected
    When they GET /api/clusters/c1/resources/ipaddresspool
    Then the response is 404
    And the body error is "RESOURCE_KIND_NOT_SUPPORTED"
    # exlb-kind-singular-rejected

  Scenario: external-LB SAR deny — 403 RBAC_DENIED
    When the user may NOT "list" bgppeers on metallb.io
    When they GET /api/clusters/c1/resources/bgppeers?namespace=ns-a
    Then the response is 403
    And the body error is "RBAC_DENIED"
    # exlb-sar-denied

  # Frontend — the Cert-Manager list page.

  Scenario: the Cert-Manager list page renders the 4-tab shape
    Given a bound cluster
    And the user selects ns-a
    When they open /network/cert-manager
    Then the card title is "Cert-Manager Objects"
    And four tabs render: "Cluster Issuer", "Issuer", "Certificate Request", "Certificates"
    And each tab renders a table of its kind's items
    # certmanager-list-renders-4tabs

  Scenario: the Cert-Manager Status cell is the last condition reason (badge)
    When the Cluster Issuer tab shows a cert-manager object
    Then its Status cell is the last status.conditions[] reason
    And the badge is green when the condition status is "True", red otherwise
    # certmanager-list-status-badge

  Scenario: the Cert-Manager Name cell links to the data page
    When the Certificates tab shows a certificate
    Then its Name cell links to /network/cert-manager/data?type=certificate&name=<n>&namespace=ns-a
    # certmanager-list-name-links

  Scenario: the Certificates Secret cell deep-links to the landed Secret view
    When the Certificates tab shows a certificate
    Then its Secret cell links to /security/secret/data?name=<secret>&namespace=ns-a
    # certmanager-list-certificate-secret-deep-link

  Scenario: the Cert-Manager list page states
    Given a bound cluster
    When they open /network/cert-manager with no namespace selected
    Then the namespaced tabs show the namespace-selector state
    And the Cluster Issuer tab (cluster-scoped) lists without a namespace
    When the cluster's cert-manager CRDs are absent
    Then every tab shows its per-tab empty state (NOT an error)
    # certmanager-list-states

  # Frontend — the Cert-Manager data page.

  Scenario: the Cert-Manager data page renders the per-type table + JSON
    Given a bound cluster
    And the user selects ns-a
    When they open /network/cert-manager/data?type=certificate&name=c1&namespace=ns-a
    Then the card title is "Cert-Manager Certificate"
    And the per-type metadata CTable renders (Name / Status / Status message / Validity Not After / Certificate / Hostnames)
    And a JSON block renders JSON.stringify(item, null, 2)
    # certmanager-data-renders-per-type

  Scenario: the Cert-Manager data page not-found state
    Given a bound cluster
    And the user selects ns-a
    When they open /network/cert-manager/data?type=certificate&name=missing&namespace=ns-a
    And the backend returns items: []
    Then the page shows "No certificate 'missing' found" (a state, not an error)
    # certmanager-data-not-found-state

  Scenario: the Cert-Manager data page missing-name error
    When they open /network/cert-manager/data?type=certificate&namespace=ns-a
    Then the page shows "Error: certificate name not provided"
    # certmanager-data-missing-name

  # Frontend — the External Load Balancer list page.

  Scenario: the External LB list page renders the 4-tab shape
    Given a bound cluster
    And the user selects ns-a
    When they open /network/external-loadbalancer
    Then the card title is "LoadBalancer Objects"
    And four tabs render: "IP Address Pools", "L2 Advertisements", "BGP Peers", "BGP Advertisements"
    And each tab renders a table with a Type column (the provider) and a Name column
    # exlb-list-renders-4tabs

  Scenario: the External LB Type column shows the detected provider
    When the IP Address Pools tab shows a MetalLB pool
    Then its Type cell is "metallb"
    When the IP Address Pools tab shows a Cilium pool (MetalLB absent)
    Then its Type cell is "cilium"
    # exlb-list-type-column

  Scenario: the External LB Name cell links to the data page
    When the BGP Peers tab shows a bgp peer
    Then its Name cell links to /network/external-loadbalancer/data?type=bgppeers&name=<n>&namespace=ns-a
    # exlb-list-name-links

  Scenario: the External LB list page states
    Given a bound cluster
    When they open /network/external-loadbalancer with no namespace selected
    Then the namespaced tabs show the namespace-selector state
    When neither the MetalLB nor the Cilium CRDs are installed
    Then every tab shows its per-tab empty state (NOT an error)
    # exlb-list-states

  # Frontend — the External Load Balancer data page.

  Scenario: the External LB data page renders the per-type + provider table + JSON
    Given a bound cluster
    And the user selects ns-a
    When they open /network/external-loadbalancer/data?type=ipaddresspool&name=pool-a&namespace=ns-a
    And the object is a MetalLB pool
    Then the card title is "ipaddresspool Objects"
    And the per-type + provider-specific metadata CTable renders (Addresses / Auto assign / Avoid buggy IPs / the Allocation + Service Selector rows)
    And a JSON block renders JSON.stringify(item, null, 2)
    # exlb-data-renders-per-type

  Scenario: the External LB data page not-found state
    Given a bound cluster
    And the user selects ns-a
    When they open /network/external-loadbalancer/data?type=ipaddresspool&name=missing&namespace=ns-a
    And the backend returns items: []
    Then the page shows "No ipaddresspool 'missing' found" (a state, not an error)
    # exlb-data-not-found-state

  # Routing + nav (the /plugins/ -> /network/ move).

  Scenario: the two nav leaves are added to the Network group
    When the user opens the sidebar
    Then the Network group contains "Cert-Manager" -> /network/cert-manager (Beta badge)
    And the Network group contains "External Load Balancer" -> /network/external-loadbalancer (Beta badge)
    And no new "Plugins" nav group exists
    # nav-leaves-added-to-network, no-plugins-group

  Scenario: both view pairs are routed
    When they open /network/cert-manager
    Then the Cert-Manager list view renders (not a 404)
    When they open /network/external-loadbalancer
    Then the External LB list view renders (not a 404)
    # both-view-pairs-routed
