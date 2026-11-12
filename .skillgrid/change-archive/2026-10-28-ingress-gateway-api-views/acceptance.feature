Feature: Ingress + Gateway API views (and the converter)
  # briefing.md R1-R9. Three load-bearing themes: (1) the 4.1 Ingress pages
  # (list: name/ingress-class/hostname; data: metadata + rules table) are
  # ported to 5.0 as a real, SAR-gated, read-only list + data pair under
  # Network (ADR-0022); (2) /network/gateway-api is a NEW four-tab CRD page
  # (GatewayClass/Gateway/HTTPRoute/ReferenceGrant via the VPA CRD seam —
  # CRD-absent is a first-class empty state); (3) the Ingress->Gateway API
  # converter (a pure-Python port of ing-switch's mapping) + a generic
  # SAR-gated apply endpoint (the one-way door) + the converter UI
  # (convert -> preview -> apply -> re-fetch).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # =========================================== INGRESS (the 4.1 port)

  # --------------------------------------------------- API: ingress list (R1)

  Scenario: ingresses-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/ingresses?namespace=team-a
    Then the response is 200
    And the body kind is ingresses
    And every item is in to_dict snake_case form
    And the first item's spec and status fields are present (NOT stripped)

  Scenario: ingresses-list-all-namespaces
    # edge — R1 (no ?namespace= -> the all-namespaces branch)
    When a bound user requests GET /api/v1/clusters/1/resources/ingresses
    Then the response is 200
    And the K8s client used the all-namespaces list call

  Scenario: ingresses-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on ingresses (networking.k8s.io, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/ingresses?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the ingresses resource
    And the K8s client list call was never made

  Scenario: ingresses-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/ingresses?namespace=team-a
    Then the response is 404

  Scenario: ingress-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/ingress
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ----------------------------------------------- API: ingress lookup (R2)

  Scenario: ingresses-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/ingresses?name=web-ing&namespace=team-a
    Then the response is 200 with a one-item list containing the named ingress
    And the item's spec and status fields are present
    When a bound user requests GET /api/v1/clusters/1/resources/ingresses?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # -------------------------------------------------- frontend: ingress (R3,R4)

  Scenario: ingress-list-renders-rows
    # happy path — R3
    Given the cluster is selected
    And the selected namespace is team-a
    When the user opens /network/ingress
    Then the card title is EXACTLY "Ingress List"
    And the fetch URL has namespace=team-a
    And every ingress name links to /network/ingress/data?name=<name>&namespace=team-a
    And the columns are Name, IngressClass, Hostname
    And the Hostname cell is the spec.rules hosts joined by comma

  Scenario: ingress-data-renders
    # happy path — R4 (metadata + rules table + JSON block + convert button)
    Given the cluster is selected
    When the user opens /network/ingress/data?name=web-ing&namespace=team-a
    Then exactly one fetch is made with name=web-ing and namespace=team-a
    And the table shows the name, ingress class, created, labels, and annotations rows
    And the rules table shows one row per spec.rules path (host, path, path type, service, port, tls)
    And the full object is rendered as a JSON-highlighted block
    And a "Convert to Gateway API" button is present

  Scenario: ingress-data-not-found-state
    # edge — R4 (a miss is a state, not an error)
    Given the named ingress does not exist in the namespace
    When the user opens /network/ingress/data?name=ghost&namespace=team-a
    Then the page shows "No Ingress 'ghost' found"
    And the page does not show an error style for the miss

  Scenario: ingress-data-missing-name
    # edge — R4
    When the user opens /network/ingress/data?namespace=team-a
    Then the page shows "Error: ingress name not provided"

  # =========================================== GATEWAY API (NEW, four tabs)

  # ------------------------------------------- API: gateway api kinds (R5)

  Scenario: gateway-api-kinds-list
    # happy path — R5 (each kind via the VPA CRD seam, full custom object)
    When a bound user requests GET /api/v1/clusters/1/resources/gatewayclasses
    Then the response is 200
    And every item is a full custom object (camelCase, spec intact)
    When a bound user requests GET /api/v1/clusters/1/resources/gateways?namespace=team-a
    Then the response is 200
    When a bound user requests GET /api/v1/clusters/1/resources/httproutes?namespace=team-a
    Then the response is 200
    When a bound user requests GET /api/v1/clusters/1/resources/referencegrants
    Then the response is 200

  Scenario: gateway-api-crd-absent-empty
    # edge — R5 (the Gateway API CRDs are optional; absent -> first-class empty state)
    Given the Gateway API CRDs are not installed on the cluster
    When a bound user requests GET /api/v1/clusters/1/resources/httproutes?namespace=team-a
    Then the response is 200
    And the body items is empty (NOT an error)

  Scenario: gateway-api-sar-denied
    # failure — R5 (ADR-0004: SAR on the CRD's group)
    Given the SAR check for list on httproutes (gateway.networking.k8s.io) denies
    When a bound user requests GET /api/v1/clusters/1/resources/httproutes?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the httproutes resource

  # ------------------------------------------------ frontend: gateway api (R5,R6)

  Scenario: gateway-api-tabbed-page
    # happy path — R5 (four CTabs, each a KubeDataTable in the VPA-seam shape)
    Given the cluster is selected
    When the user opens /network/gateway-api
    Then the card title is EXACTLY "Gateway API"
    And the page renders four tabs: GatewayClasses, Gateways, HTTPRoutes, ReferenceGrants
    And each tab's name links to /network/gateway-api/data?name=<name>&kind=<kind>

  Scenario: gateway-api-data-renders
    # happy path — R6 (the kind's fields + JSON block; bad kind -> error line)
    Given the cluster is selected
    When the user opens /network/gateway-api/data?name=my-gw&namespace=team-a&kind=gateways
    Then the page renders the gateway's fields + labels/annotations + the JSON block
    When the user opens /network/gateway-api/data?name=x&namespace=team-a&kind=bogus
    Then the page shows an error line (the kind is not in the closed set) and no fetch is made

  # =========================================== CONVERTER (ing-switch port)

  # ------------------------------------------------------- converter (R7)

  Scenario: convert-emits-gatewayclass-gateway-httproute
    # happy path — R7 (the ported ing-switch mapping)
    Given an ingress with one host, one path, and one backend service
    When a bound user requests POST /api/v1/clusters/1/gateway-api/convert with that ingress
    Then the response is 200
    And the resources contain a GatewayClass, a Gateway, and one HTTPRoute
    And the Gateway's gatewayClassName is the provider's class
    And the HTTPRoute's parentRefs reference the generated Gateway
    And the HTTPRoute's backendRefs reference the ingress's service

  Scenario: convert-annotation-mapping-parity
    # happy path — R7 (the NGINX-annotation -> Gateway API mapping, 1:1 with ing-switch)
    Given an ingress with rewrite-target, canary+canary-weight, enable-cors, force-ssl-redirect+tls, proxy-read-timeout, and a regex path
    When a bound user requests the convert endpoint
    Then the HTTPRoute has a URLRewrite filter (ReplaceFullPath) for rewrite-target
    And the HTTPRoute's backendRef has the canary weight
    And the HTTPRoute has a CORS filter (allowOrigins/allowMethods/allowHeaders/allowCredentials/maxAge)
    And two HTTPRoutes are emitted (a -redirect route with RequestRedirect on sectionName http + a backend route on sectionName https-N)
    And the HTTPRoute has timeouts.backendRequest from proxy-read-timeout
    And the regex path is a RegularExpression path match

  Scenario: convert-warnings-for-unsupported-annotations
    # edge — R7 (provider-specific annotations are dropped, not converted)
    Given an ingress with an unsupported nginx annotation (e.g. limit-rps)
    When a bound user requests the convert endpoint
    Then the response warnings list names the dropped annotation
    And no provider-specific policy resource is emitted for it

  Scenario: convert-missing-ingress-404
    # edge — R7 (the get_ingress 0/1-item contract -> 404 on a miss)
    Given the named ingress does not exist
    When a bound user requests the convert endpoint
    Then the response is 404

  # ------------------------------------------------------- apply (R8)

  Scenario: apply-creates-objects
    # happy path — R8 (the generic mutation endpoint)
    Given the converter's output resources
    When a bound user requests POST /api/v1/clusters/1/resources/apply with those objects
    Then the response is 200
    And the applied array has one entry per object with status created

  Scenario: apply-idempotent
    # happy path — R8 (re-apply is a no-op — get-or-create)
    Given the objects were already applied
    When a bound user requests the apply endpoint again with the same objects
    Then the response is 200
    And the applied entries have status unchanged

  Scenario: apply-sar-denied-atomic
    # failure — R8 (ADR-0004 EXTENDED: create SAR, atomic before the apply)
    Given the SAR check for create on one of the objects denies
    When a bound user requests the apply endpoint
    Then the response is 403 RBAC_DENIED naming the denied resource
    And no object was applied (the SAR phase is before the apply phase)

  Scenario: apply-partial-failure
    # edge — R8 (a partial failure is 200 with the errors array, not a 500)
    Given one of the objects fails to apply (e.g. a validation error)
    When a bound user requests the apply endpoint
    Then the response is 200
    And the errors array names the failed object
    And the applied array has the successful objects

  # =========================================== CONVERTER UI + ROUTING

  Scenario: converter-ui-convert-apply
    # happy path — R4 (button) + R7 + R8 (the UI flow)
    Given the user is on the ingress data page for a valid ingress
    When the user clicks "Convert to Gateway API"
    Then the converter shows the generated resources as per-resource YAML tabs
    When the user clicks Apply
    Then the per-object result is shown (applied/unchanged)
    And the Gateway API tabs are re-fetched (the new resources appear)

  Scenario: ingress-stub-removed-and-routes-wired
    # happy path — R9
    Given the ingress and gateway api views are built
    Then /network/ingress is not in the stub route list
    And /network/ingress/data, /network/gateway-api, and /network/gateway-api/data are not nav entries
    And the /network/ingress nav leaf is byte-identical to before the change

  Scenario: gateway-api-leaf-added
    # happy path — R9 (the NEW nav leaf)
    Given the gateway api views are built
    Then the /network/gateway-api leaf is in the Network group of the nav
    And the leaf label is "Gateway API"
