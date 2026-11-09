from app.services.gateway_convert import (
    GATEWAY_API_GROUP,
    GATEWAY_API_VERSION,
    convert_ingress,
    unsupported_annotations,
)


def _ingress(**overrides: object) -> dict:
    ingress: dict = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "web", "namespace": "team-a", "annotations": {}},
        "spec": {
            "ingressClassName": "nginx",
            "rules": [
                {
                    "host": "a.example.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/api",
                                "path_type": "Prefix",
                                "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                            }
                        ]
                    },
                }
            ],
        },
    }
    for key, value in overrides.items():
        if key == "spec":
            ingress["spec"] = value  # type: ignore[index]
        elif key == "metadata":
            ingress["metadata"] = value  # type: ignore[index]
        elif key == "metadata.annotations":
            ingress["metadata"]["annotations"] = value  # type: ignore[index]
        elif key.startswith("spec."):
            section = key.split(".", 1)[1]
            node: dict = ingress.setdefault("spec", {})
            if section == "rules":
                node["rules"] = value  # type: ignore[assignment]
            else:
                node[section] = value  # type: ignore[index]
        else:
            ingress[key] = value  # type: ignore[index]
    return ingress


def test_convert_emits_gatewayclass_gateway_httproute() -> None:
    resources, warnings = convert_ingress(_ingress())
    kinds = [r["kind"] for r in resources]
    assert kinds[0] == "GatewayClass"
    assert kinds[1] == "Gateway"
    assert kinds[2:] == ["HTTPRoute"]
    assert warnings == []
    gw_class = resources[0]
    assert gw_class["apiVersion"] == f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}"
    assert gw_class["spec"]["controllerName"] == "gateway.envoyproxy.io/gatewayclass-controller"
    gateway = resources[1]
    assert gateway["kind"] == "Gateway"
    assert gateway["metadata"]["namespace"] == "team-a"
    assert gateway["spec"]["gatewayClassName"] == "eg"
    listeners = {entry["name"]: entry for entry in gateway["spec"]["listeners"]}
    # Gateway API v1: GatewayListener.port is an int32 (NOT the Ingress
    # {"number": N} dict — the apiserver prunes the dict).
    assert listeners["http"]["port"] == 80
    assert isinstance(listeners["http"]["port"], int)
    assert listeners["http"]["allowedRoutes"]["namespaces"]["from"] == "All"
    route = resources[2]
    assert route["kind"] == "HTTPRoute"
    assert route["spec"]["parentRefs"][0]["name"] == "web"
    assert route["spec"]["parentRefs"][0]["namespace"] == "team-a"
    assert route["spec"]["parentRefs"][0]["kind"] == "Gateway"
    # No TLS on this host: the parentRef has NO sectionName key (minLength
    # 1 — an empty string would fail validation) and there is NO
    # spec-level sectionName on the v1 HTTPRouteSpec.
    assert "sectionName" not in route["spec"]["parentRefs"][0]
    assert "sectionName" not in route["spec"]
    assert route["spec"]["hostnames"] == ["a.example.com"]
    # v1 HTTPBackendRef: FLAT {"name", "port"} — no "backend.service" key.
    backend = route["spec"]["rules"][0]["backendRefs"][0]
    assert backend["name"] == "svc"
    assert backend["port"] == 80
    assert isinstance(backend["port"], int)
    assert "backend" not in backend


def test_convert_gateway_tls_listener_port_is_int() -> None:
    """A TLS secret adds the https-0 listener — its port is int 443 too."""
    ingress = _ingress(
        **{"spec.tls": [{"hosts": ["a.example.com"], "secret_name": "tls-secret"}]}
    )
    resources, _ = convert_ingress(ingress)
    listeners = {entry["name"]: entry for entry in resources[1]["spec"]["listeners"]}
    assert listeners["https-0"]["port"] == 443
    assert isinstance(listeners["https-0"]["port"], int)
    assert listeners["https-0"]["tls"] == {
        "mode": "Terminate",
        "certificateRefs": [{"name": "tls-secret"}],
    }


def test_convert_parentref_sectionname_only_for_tls_hosts() -> None:
    """The listener binding is the parentRef's sectionName: "https-0"
    (the TLS listener for the host's secret) when the host has a TLS
    secret; the key is ABSENT otherwise. Never a spec-level sectionName."""
    ingress = _ingress(
        **{"spec.tls": [{"hosts": ["a.example.com"], "secret_name": "tls-secret"}]}
    )
    resources, _ = convert_ingress(ingress)
    route = next(r for r in resources if r["kind"] == "HTTPRoute")
    assert route["spec"]["parentRefs"][0].get("sectionName") == "https-0"
    assert "sectionName" not in route["spec"]
    # No TLS: the key is gone entirely (an empty-string sectionName would
    # violate the CRD's minLength 1).
    no_tls, _ = convert_ingress(_ingress())
    no_tls_route = next(r for r in no_tls if r["kind"] == "HTTPRoute")
    assert "sectionName" not in no_tls_route["spec"]["parentRefs"][0]


def test_convert_canary_weight_on_flat_backendref() -> None:
    ingress = _ingress(
        **{"metadata.annotations": {"nginx.ingress.kubernetes.io/canary-weight": "30"}}
    )
    resources, _ = convert_ingress(ingress)
    route = next(r for r in resources if r["kind"] == "HTTPRoute")
    ref = route["spec"]["rules"][0]["backendRefs"][0]
    assert ref["weight"] == 30
    assert ref["name"] == "svc"
    assert ref["port"] == 80


def test_convert_annotation_mapping_parity() -> None:
    ingress = _ingress(
        **{
            "metadata.annotations": {
                "nginx.ingress.kubernetes.io/rewrite-target": "/svc/upstream",
                "nginx.ingress.kubernetes.io/canary-by-header": "foo",
                "nginx.ingress.kubernetes.io/canary-weight": "7",
                "nginx.ingress.kubernetes.io/enable-cors": "true",
                "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
                "nginx.ingress.kubernetes.io/cors-allow-methods": "GET",
                "nginx.ingress.kubernetes.io/cors-allow-headers": "Authorization",
                "nginx.ingress.kubernetes.io/cors-allow-credentials": "true",
                "nginx.ingress.kubernetes.io/cors-expose-headers": "X-Foo",
                "nginx.ingress.kubernetes.io/cors-max-age": "60",
                "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/ssl-redirect": "true",
                "nginx.ingress.kubernetes.io/proxy-read-timeout": "30",
            },
            "spec": {
                "rules": [
                    {
                        "host": "a.example.com",
                        "http": {
                            "paths": [
                                {
                                    "path": "/api",
                                    "path_type": "Prefix",
                                    "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                                }
                            ]
                        },
                    }
                ],
                "tls": [{"hosts": ["a.example.com"], "secret_name": "tls-secret"}],
            },
        }
    )
    resources, warnings = convert_ingress(ingress, provider="envoy")
    backend_route = next(
        r for r in resources if r["kind"] == "HTTPRoute" and r["metadata"]["name"] != "web-redirect"
    )
    rule = backend_route["spec"]["rules"][0]
    filters = {f["type"]: f for f in rule["filters"]}
    # v1 HTTPURLRewriteFilter: NO replacePrefixWith field — the target is
    # path.replaceFullPath (a ReplaceFullPath HTTPPathModifier).
    assert "URLRewrite" in filters
    assert filters["URLRewrite"]["urlRewrite"] == {
        "path": {"type": "ReplaceFullPath", "replaceFullPath": "/svc/upstream"}
    }
    # The v1 HTTPRouteFilter enum has NO CORS filter: the CORS annotations
    # are DROPPED (the keys come back in the warnings, not a filter).
    assert "CORS" not in filters
    assert "nginx.ingress.kubernetes.io/enable-cors" in warnings
    for key in (
        "nginx.ingress.kubernetes.io/cors-allow-origin",
        "nginx.ingress.kubernetes.io/cors-allow-methods",
        "nginx.ingress.kubernetes.io/cors-allow-headers",
        "nginx.ingress.kubernetes.io/cors-allow-credentials",
        "nginx.ingress.kubernetes.io/cors-expose-headers",
        "nginx.ingress.kubernetes.io/cors-max-age",
    ):
        assert key in warnings
    # v1 HTTPRouteSpec.timeouts.backendRequest is a Duration STRING.
    assert backend_route["spec"]["timeouts"]["backendRequest"] == "30s"
    redirect = next(
        r for r in resources if r["kind"] == "HTTPRoute" and r["metadata"]["name"] == "web-redirect"
    )
    redirect_rule = redirect["spec"]["rules"][0]
    # The v1 filter enum has NO "Redirect" — the redirect filter is
    # "RequestRedirect" / requestRedirect.
    assert redirect_rule["filters"][0]["type"] == "RequestRedirect"
    assert redirect_rule["filters"][0]["requestRedirect"] == {"scheme": "https", "statusCode": 301}
    # The redirect rides the PLAIN HTTP listener: the parentRef (NOT a
    # spec-level key) carries sectionName "http".
    assert redirect["spec"]["parentRefs"][0]["sectionName"] == "http"
    assert "sectionName" not in redirect["spec"]
    # The backend route binds the TLS listener via the parentRef.
    assert backend_route["spec"]["parentRefs"][0]["sectionName"] == "https-0"
    assert "sectionName" not in backend_route["spec"]
    assert backend_route["spec"]["rules"][0]["matches"][0]["path"]["type"] == "PathPrefix"


def test_convert_regex_path_is_regular_expression() -> None:
    ingress = _ingress(
        **{
            "spec": {
                "rules": [
                    {
                        "host": "a.example.com",
                        "http": {
                            "paths": [
                                {
                                    "path": "^/api/v\\d+/x",
                                    "path_type": "ImplementationSpecific",
                                    "backend": {"service": {"name": "svc", "port": {"number": 80}}},
                                }
                            ]
                        },
                    }
                ]
            }
        }
    )
    resources, _ = convert_ingress(ingress)
    backend_route = next(r for r in resources if r["kind"] == "HTTPRoute")
    assert backend_route["spec"]["rules"][0]["matches"][0]["path"]["type"] == "RegularExpression"
    assert backend_route["spec"]["rules"][0]["matches"][0]["path"]["value"] == "^/api/v\\d+/x"


def test_convert_warnings_for_unsupported_annotations() -> None:
    ingress = _ingress(
        **{
            "metadata": {
                "name": "web",
                "namespace": "team-a",
                "annotations": {"nginx.ingress.kubernetes.io/limit-rps": "10"},
            }
        }
    )
    assert unsupported_annotations(ingress) == ["nginx.ingress.kubernetes.io/limit-rps"]
    resources, warnings = convert_ingress(ingress)
    assert [r["kind"] for r in resources] == ["GatewayClass", "Gateway", "HTTPRoute"]
    # The warnings are the unsupported annotations (no CORS here).
    assert warnings == ["nginx.ingress.kubernetes.io/limit-rps"]


def test_convert_cors_keys_dropped_to_warnings_without_filter() -> None:
    """A CORS-only ingress (no rewrite): the emitted rule has NO filters at
    all and the sorted CORS keys (at least enable-cors) are the warnings."""
    ingress = _ingress(
        **{
            "metadata.annotations": {
                "nginx.ingress.kubernetes.io/enable-cors": "true",
                "nginx.ingress.kubernetes.io/cors-allow-origin": "*",
            }
        }
    )
    resources, warnings = convert_ingress(ingress)
    route = next(r for r in resources if r["kind"] == "HTTPRoute")
    assert route["spec"]["rules"][0]["filters"] == []
    assert warnings == [
        "nginx.ingress.kubernetes.io/cors-allow-origin",
        "nginx.ingress.kubernetes.io/enable-cors",
    ]
