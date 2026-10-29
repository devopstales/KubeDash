@views @ingressclass-gatewayclass
Feature: IngressClass + GatewayClass Views (List + Data)

  As a user of the KubeDash dashboard
  I want IngressClass and GatewayClass list + data views
  So that I can see the controllers that name IngressClass and GatewayClass resources (cluster-scoped)

  Background:
    Given the "prod" cluster is selected
    And the user is bound to the "prod" cluster
    And the user has RBAC permission for the resource

  # ── IngressClass list ────────────────────────────────────────────────────

  @ingressclasses
  Scenario: The IngressClass list resolves at /network/ingress-class
    When I open /network/ingress-class
    Then the page shows a table titled "IngressClass List"
    And the columns are "Name", "Controller" and "Created"
    And the Controller cell shows the spec.controller value or "—"
    And the Created cell shows the creation timestamp

  @ingressclasses
  Scenario: The IngressClass list name links carry no namespace
    When the IngressClass list shows an item named "nginx"
    Then the "nginx" Name cell links to /network/ingress-class/data?name=nginx
    And the link URL does not contain a namespace parameter

  @ingressclasses
  Scenario: The IngressClass list empty state
    When the cluster has no IngressClasses
    And I open /network/ingress-class
    Then the page shows "No ingress classes found"

  @ingressclasses
  Scenario: The IngressClass list no-cluster state
    Given no cluster is selected
    When I open /network/ingress-class
    Then the page shows "No cluster selected."

  # ── IngressClass data ────────────────────────────────────────────────────

  @ingressclass-data
  Scenario: The IngressClass data page shows the metadata + Parameters + JSON
    When I open /network/ingress-class/data?name=nginx
    Then the page shows a detail table with "Name", "Created", "Controller", "Labels" and "Annotations"
    And the Controller row shows the spec.controller value or "—"
    And the page shows a full-object JSON block

  @ingressclass-data
  Scenario: The IngressClass data page shows the Parameters table when present
    Given an IngressClass "nginx" whose spec.parameters is { kind: "IngressClassParameters", name: "nginx-params" }
    When I open /network/ingress-class/data?name=nginx
    Then the Parameters table shows a "Kind" row "IngressClassParameters"
    And the Parameters table shows a "Name" row "nginx-params"

  @ingressclass-data
  Scenario: The IngressClass data page shows no Parameters when absent
    Given an IngressClass "nginx" with no spec.parameters
    When I open /network/ingress-class/data?name=nginx
    Then the Parameters table shows "No parameters"

  @ingressclass-data
  Scenario: The IngressClass data page not-found state
    When I open /network/ingress-class/data?name=missing
    Then the page shows "No IngressClass 'missing' found"
    And the message is not styled as an error

  @ingressclass-data
  Scenario: The IngressClass data page missing name
    When I open /network/ingress-class/data
    Then the page shows "Error: ingress class name not provided"

  # ── IngressClass API (SAR) ───────────────────────────────────────────────

  @ingressclasses-api
  Scenario: The IngressClass list is SAR-gated on list
    When I send GET /api/v1/clusters/prod/resources/ingressclasses
    Then the response status is 200
    And the response body kind is "ingressclasses"
    And the SAR was asked for "list" on "ingressclasses" in group "networking.k8s.io" with namespace "None"

  @ingressclasses-api
  Scenario: The IngressClass list ignores the namespace param
    When I send GET /api/v1/clusters/prod/resources/ingressclasses?namespace=team-a
    Then the response status is 200
    And the cluster-scoped list call is used (no namespace)

  @ingressclasses-api
  Scenario: The IngressClass get-by-name returns 0 or 1 item
    Given an IngressClass "nginx" exists
    When I send GET /api/v1/clusters/prod/resources/ingressclasses?name=nginx
    Then the response status is 200
    And the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/ingressclasses?name=missing
    Then the response body items length is 0

  @ingressclasses-api
  Scenario: The IngressClass list denies SAR
    Given the user lacks "list" on "ingressclasses" in group "networking.k8s.io"
    When I send GET /api/v1/clusters/prod/resources/ingressclasses
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the IngressClass list client call was not made

  @ingressclasses-api
  Scenario: The IngressClass list is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/clusters/prod/resources/ingressclasses
    Then the response status is 404

  @ingressclasses-api
  Scenario: The singular IngressClass kind is rejected
    When I send GET /api/v1/clusters/prod/resources/ingressclass
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── GatewayClass list ────────────────────────────────────────────────────

  @gatewayclasses
  Scenario: The GatewayClass list resolves at /network/gateway-class
    When I open /network/gateway-class
    Then the page shows a table titled "GatewayClass List"
    And the columns are "Name", "Controller" and "Age"
    And the Controller cell shows the spec.controllerName value or "—"
    And the Age cell shows the human-readable age of creation

  @gatewayclasses
  Scenario: The GatewayClass list name links carry no namespace
    When the GatewayClass list shows an item named "istio"
    Then the "istio" Name cell links to /network/gateway-class/data?name=istio
    And the link URL does not contain a namespace parameter

  @gatewayclasses
  Scenario: The GatewayClass list empty state (also the CRD-absent state)
    When the cluster has no GatewayClasses
    And I open /network/gateway-class
    Then the page shows "No gateway classes found"

  @gatewayclasses
  Scenario: The GatewayClass list when the CRD is absent
    Given the GatewayClass CRD is not installed
    When I open /network/gateway-class
    Then the page shows "No gateway classes found"

  @gatewayclasses
  Scenario: The GatewayClass list no-cluster state
    Given no cluster is selected
    When I open /network/gateway-class
    Then the page shows "No cluster selected."

  # ── GatewayClass data ────────────────────────────────────────────────────

  @gatewayclass-data
  Scenario: The GatewayClass data page shows the metadata + JSON
    When I open /network/gateway-class/data?name=istio
    Then the page shows a detail table with "Name", "Controller", "Created", "Labels" and "Annotations"
    And the Controller row shows the spec.controllerName value or "—"
    And the page shows a full-object JSON block

  @gatewayclass-data
  Scenario: The GatewayClass data page not-found state (also the CRD-absent state)
    When I open /network/gateway-class/data?name=missing
    Then the page shows "No GatewayClass 'missing' found"
    And the message is not styled as an error

  @gatewayclass-data
  Scenario: The GatewayClass data page when the CRD is absent
    Given the GatewayClass CRD is not installed
    When I open /network/gateway-class/data?name=istio
    Then the page shows "No GatewayClass 'istio' found"

  @gatewayclass-data
  Scenario: The GatewayClass data page missing name
    When I open /network/gateway-class/data
    Then the page shows "Error: gateway class name not provided"

  # ── GatewayClass API (SAR + CRD seam) ────────────────────────────────────

  @gatewayclasses-api
  Scenario: The GatewayClass list is SAR-gated on list
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses
    Then the response status is 200
    And the response body kind is "gatewayclasses"
    And each item is a full custom object (spec and status intact, camelCase)
    And the SAR was asked for "list" on "gatewayclasses" in group "gateway.networking.k8s.io" with namespace "None"

  @gatewayclasses-api
  Scenario: The GatewayClass list is empty when the CRD is absent
    Given the GatewayClass CRD is not installed
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses
    Then the response status is 200
    And the response body items length is 0

  @gatewayclasses-api
  Scenario: The GatewayClass get-by-name returns 0 or 1 item
    Given a GatewayClass "istio" exists
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses?name=istio
    Then the response status is 200
    And the response body items length is 1
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses?name=missing
    Then the response body items length is 0

  @gatewayclasses-api
  Scenario: The GatewayClass get-by-name is empty when the CRD is absent
    Given the GatewayClass CRD is not installed
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses?name=istio
    Then the response status is 200
    And the response body items length is 0

  @gatewayclasses-api
  Scenario: The GatewayClass list denies SAR
    Given the user lacks "list" on "gatewayclasses" in group "gateway.networking.k8s.io"
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses
    Then the response status is 403
    And the error code is "RBAC_DENIED"
    And the GatewayClass list client call was not made

  @gatewayclasses-api
  Scenario: The GatewayClass list is 404 when unbound
    Given the user is not bound to the "prod" cluster
    When I send GET /api/v1/clusters/prod/resources/gatewayclasses
    Then the response status is 404

  @gatewayclasses-api
  Scenario: The singular GatewayClass kind is rejected
    When I send GET /api/v1/clusters/prod/resources/gatewayclass
    Then the response status is 400
    And the error code is "RESOURCE_KIND_NOT_SUPPORTED"

  # ── Routing and nav ──────────────────────────────────────────────────────

  @routing
  Scenario: Both nav leaves are added and routed
    When I open the sidebar Network group
    Then it contains an "IngressClass" leaf linked to /network/ingress-class
    And it contains a "GatewayClass" leaf linked to /network/gateway-class
    And /network/ingress-class resolves to the IngressClass list view
    And /network/ingress-class/data resolves to the IngressClass data view
    And /network/gateway-class resolves to the GatewayClass list view
    And /network/gateway-class/data resolves to the GatewayClass data view
    And neither path is a stub
