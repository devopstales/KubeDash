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
    resources = convert_ingress(_ingress())
    kinds = [r["kind"] for r in resources]
    assert kinds[0] == "GatewayClass"
    assert kinds[1] == "Gateway"
    assert kinds[2:] == ["HTTPRoute"]
    gw_class = resources[0]
    assert gw_class["apiVersion"] == f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}"
    assert gw_class["spec"]["controllerName"] == "gateway.envoyproxy.io/gatewayclass-controller"
    gateway = resources[1]
    assert gateway["kind"] == "Gateway"
    assert gateway["metadata"]["namespace"] == "team-a"
    assert gateway["spec"]["gatewayClassName"] == "eg"
    listeners = {entry["name"]: entry for entry in gateway["spec"]["listeners"]}
    assert listeners["http"]["port"] == {"number": 80}
    assert listeners["http"]["allowedRoutes"]["namespaces"]["from"] == "All"
    route = resources[2]
    assert route["kind"] == "HTTPRoute"
    assert route["spec"]["parentRefs"][0]["name"] == "web"
    assert route["spec"]["parentRefs"][0]["namespace"] == "team-a"
    assert route["spec"]["parentRefs"][0]["kind"] == "Gateway"
    assert route["spec"]["hostnames"] == ["a.example.com"]
    backend = route["spec"]["rules"][0]["backendRefs"][0]["backend"]["service"]
    assert backend["name"] == "svc"


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
    resources = convert_ingress(ingress, provider="envoy")
    backend_route = next(
        r for r in resources if r["kind"] == "HTTPRoute" and r["metadata"]["name"] != "web-redirect"
    )
    rule = backend_route["spec"]["rules"][0]
    filters = {f["type"]: f for f in rule["filters"]}
    assert "URLRewrite" in filters
    assert filters["URLRewrite"]["urlRewrite"]["replacePrefixWith"] == "/svc/upstream"
    assert "CORS" in filters
    assert filters["CORS"]["cors"]["allowOrigin"] == ["*"]
    assert filters["CORS"]["cors"]["maxAge"] == 60
    assert backend_route["spec"]["timeouts"]["backendRequest"]["timeout"] == 30
    redirect = next(
        r for r in resources if r["kind"] == "HTTPRoute" and r["metadata"]["name"] == "web-redirect"
    )
    redirect_rule = redirect["spec"]["rules"][0]
    assert redirect_rule["filters"][0]["type"] == "Redirect"
    assert redirect_rule["filters"][0]["redirect"]["scheme"] == "https"
    assert redirect_rule["filters"][0]["redirect"]["statusCode"] == 301
    assert backend_route["spec"]["sectionName"] == "https-0"
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
    resources = convert_ingress(ingress)
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
    resources = convert_ingress(ingress)
    assert [r["kind"] for r in resources] == ["GatewayClass", "Gateway", "HTTPRoute"]
