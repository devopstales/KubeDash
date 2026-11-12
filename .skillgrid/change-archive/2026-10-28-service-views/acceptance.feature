Feature: Service views (list + three-tab data, namespaced)
  # briefing.md R1-R6. The load-bearing theme: the 4.1 Service pages
  # (list: name/type/cluster-ip/external-ip; data: a three-tab page —
  # Service / Ports / Pods) are ported to 5.0 as a real, SAR-gated, read-only
  # list + three-tab data pair under Network (ADR-0022) — a namespaced core
  # kind (core v1), with the ratified 5.0 deltas (?name=&namespace= params,
  # the JSON block, the CoreUI CTabs, the External IP 500 fix, and the Pods
  # tab's pods read via a new ?labelSelector= param on the existing pods
  # route).

  Background:
    Given the KubeDash Flask app under test
    And a cluster bound to the acting user

  # --------------------------------------------------------- API: list (R1)

  Scenario: services-list-200
    # happy path — R1
    When a bound user requests GET /api/v1/clusters/1/resources/services?namespace=team-a
    Then the response is 200
    And the body kind is services
    And the body cluster is the bound cluster name
    And every item is in to_dict snake_case form
    And the first item's spec and status fields are present (NOT stripped)

  Scenario: services-list-all-namespaces
    # edge — R1 (no ?namespace= -> the all-namespaces branch, the list_secrets pattern)
    When a bound user requests GET /api/v1/clusters/1/resources/services
    Then the response is 200
    And the K8s client used the all-namespaces list call

  Scenario: services-sar-denied
    # failure — R1 (ADR-0004: SAR before the client call)
    Given the SAR check for list on services (core, namespace team-a) denies
    When a bound user requests GET /api/v1/clusters/1/resources/services?namespace=team-a
    Then the response is 403 RBAC_DENIED naming the services resource
    And the K8s client list call was never made

  Scenario: services-binding-404
    # edge — R1 (binding gate)
    Given the acting user is not bound to the cluster
    When the user requests GET /api/v1/clusters/999/resources/services?namespace=team-a
    Then the response is 404

  Scenario: service-kind-singular-rejected
    # edge — R1 (the 4.1 route name was singular; the API kind is plural)
    When a bound user requests GET /api/v1/clusters/1/resources/service
    Then the response is 404 RESOURCE_KIND_NOT_SUPPORTED

  # ------------------------------------------------- API: name lookup (R2)

  Scenario: services-get-by-name
    # happy path — R2
    When a bound user requests GET /api/v1/clusters/1/resources/services?name=web-svc&namespace=team-a
    Then the response is 200 with a one-item list containing the named service
    And the item's spec and status fields are present
    When a bound user requests GET /api/v1/clusters/1/resources/services?name=ghost&namespace=team-a
    Then the response is 200 with an empty items list

  # ------------------------------------------- API: pods labelSelector (R3)

  Scenario: pods-labelselector-filters
    # happy path — R3 (the new ?labelSelector= param, server-side filter)
    Given the namespace has pods matching the selector app=web
    When a bound user requests GET /api/v1/clusters/1/resources/pods?namespace=team-a&labelSelector=app=web
    Then the response is 200
    And the K8s client list call used label_selector=app=web
    And only the matching pods are returned

  Scenario: pods-labelselector-absent-unchanged
    # edge — R3 (no ?labelSelector= -> the existing unfiltered list)
    When a bound user requests GET /api/v1/clusters/1/resources/pods?namespace=team-a
    Then the response is 200
    And the K8s client list call used label_selector=None
    And all pods in the namespace are returned

  # ---------------------------------------------------- frontend: list (R4)

  Scenario: service-list-renders-rows-with-data-links
    # happy path — R4
    Given the cluster is selected
    And the selected namespace is team-a
    When the user opens /network/service
    Then the card title is EXACTLY "Service List"
    And the fetch URL has namespace=team-a
    And every service name links to /network/service/data?name=<name>&namespace=team-a
    And the columns are Name, Type, Cluster IP, External IP

  Scenario: service-list-external-ip-cell
    # happy path — R4 (LoadBalancer-only, the 4.1 deep-index 500 fix)
    Given a LoadBalancer service with an ingress ip, a ClusterIP service, and a LoadBalancer service with no ingress
    When the user opens /network/service
    Then the LoadBalancer-with-ingress row External IP is the ingress ip
    And the ClusterIP row External IP is "—"
    And the LoadBalancer-without-ingress row External IP is "—"

  Scenario: service-list-empty-state
    # edge — R4
    Given the service list is empty
    When the user opens /network/service
    Then the table shows "No services found"

  Scenario: service-list-no-cluster
    # edge — R4
    Given no cluster is selected
    When the user opens /network/service
    Then the table shows "No cluster selected."
    And no fetch is made

  # ---------------------------------------------------- frontend: data (R5)

  Scenario: service-data-renders-three-tabs
    # happy path — R5
    Given the cluster is selected
    When the user opens /network/service/data?name=web-svc&namespace=team-a
    Then exactly one service fetch is made with name=web-svc and namespace=team-a
    And the page renders three tabs: Service (active by default), Ports, Pods

  Scenario: service-data-service-tab
    # happy path — R5 (the metadata table + the JSON block)
    Given the named service is a ClusterIP with labels, annotations, and a data payload
    When the user opens /network/service/data?name=web-svc&namespace=team-a
    Then the Service tab shows the name, type, created, cluster ip, and external ip rows
    And the labels and annotations sub-tables render
    And the annotations sub-table includes last-applied-configuration (verbatim, NOT trimmed)
    And the full object is rendered as a JSON-highlighted block

  Scenario: service-data-ports-tab
    # happy path — R5 (one row per spec.ports entry)
    Given the named service has a single port (http/80/TCP/8080)
    When the user opens /network/service/data?name=web-svc&namespace=team-a
    And the user clicks the Ports tab
    Then the Ports tab shows one row with Name http, Port 80, Protocol TCP, Target 8080, Node Port "—"

  Scenario: service-data-no-ports
    # edge — R5 (no spec.ports -> "No ports")
    Given the named service has no spec.ports
    When the user opens /network/service/data?name=headless-svc&namespace=team-a
    And the user clicks the Ports tab
    Then the Ports tab shows "No ports"

  Scenario: service-data-pods-tab
    # happy path — R5 (the second fetch with ?labelSelector=)
    Given the named service has a non-empty spec.selector (app=web)
    And the namespace has two pods matching that selector
    When the user opens /network/service/data?name=web-svc&namespace=team-a
    And the user clicks the Pods tab
    Then a second fetch is made on the pods route with labelSelector=app=web
    And the Pods tab shows two rows with Status badge, Name, IP, Node, and Owner
    And the owner is rendered as kind.name with a slash (the 4.1 stray-s typo fixed)

  Scenario: service-data-pods-tab-empty-selector
    # edge — R5 (no spec.selector -> no fetch, the empty state)
    Given the named service has an empty spec.selector
    When the user opens /network/service/data?name=headless-svc&namespace=team-a
    And the user clicks the Pods tab
    Then no pods fetch is made
    And the Pods tab shows "No pods match this service's selector"

  Scenario: service-data-pods-tab-no-match
    # edge — R5 (a non-empty selector but zero matching pods -> the empty state, not an error)
    Given the named service has a non-empty spec.selector
    And the namespace has no pods matching that selector
    When the user opens /network/service/data?name=web-svc&namespace=team-a
    And the user clicks the Pods tab
    Then the Pods tab shows "No pods match this service's selector"
    And the page does not show an error style for the miss

  Scenario: service-data-pod-owner-format
    # edge — R5 (the 4.1 "%ss/%s" typo is fixed)
    Given a pod with an owner reference of kind ReplicaSet name web-abc123
    When the user opens the service data page and clicks the Pods tab
    Then the pod's Owner cell is "replicaset/web-abc123"
    And the Owner cell is NOT "replicasets/web-abc123"

  Scenario: service-data-not-found-state
    # edge — R5 (a miss is a state, not an error)
    Given the named service does not exist in the namespace
    When the user opens /network/service/data?name=ghost&namespace=team-a
    Then the page shows "No Service 'ghost' found"
    And the page does not show an error style for the miss

  Scenario: service-data-missing-name
    # edge — R5
    When the user opens /network/service/data?namespace=team-a
    Then the page shows "Error: service name not provided"

  # ------------------------------------------------- routing (R6)

  Scenario: service-stub-removed-and-routes-wired
    # happy path — R6
    Given the service views are built
    Then /network/service is not in the stub route list
    And /network/service/data is not a nav entry
    And the _nav.tsx leaf is byte-identical to before the change
