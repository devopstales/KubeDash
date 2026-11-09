"""Pure Python Ingress → Gateway API converter (the ing-switch port).

NO kubernetes import here — the converter takes a parsed Ingress dict (the
``to_dict`` snake_case form produced by ``K8sClient.get_ingress``) plus a
provider and returns ``(resources, warnings)`` — the Gateway API v1
resource dicts + the dropped-annotation warnings. The endpoint
(``POST /api/v1/clusters/<id>/gateway-api/convert``) owns the Ingress read
via the ``get_ingress`` ``_GETTERS`` contract; the mapping itself is pure and
unit-testable without a cluster.

Only the k8s resources are emitted (GatewayClass + Gateway + HTTPRoutes) —
the controller/install/verify/cleanup files are out of scope (briefing R7).
"""

from typing import Any

GATEWAY_API_VERSION = "v1"
GATEWAY_API_GROUP = "gateway.networking.k8s.io"


GATEWAY_CLASS_NAME: dict[str, str] = {"envoy": "eg", "traefik": "traefik"}
GATEWAY_CLASS_CONTROLLER_NAME: dict[str, str] = {
    "envoy": "gateway.envoyproxy.io/gatewayclass-controller",
    "traefik": "traefik.io/gateway-controller",
}

HTTP_LISTENER_NAME = "http"
HTTPS_LISTENER_PREFIX = "https-"

SUPPORTED_ANNOTATION_PREFIXES: tuple[str, ...] = (
    "nginx.ingress.kubernetes.io/rewrite-target",
    "nginx.ingress.kubernetes.io/canary-by-header",
    "nginx.ingress.kubernetes.io/canary-by-header-value",
    "nginx.ingress.kubernetes.io/canary-weight",
    "nginx.ingress.kubernetes.io/enable-cors",
    "nginx.ingress.kubernetes.io/cors-allow-origin",
    "nginx.ingress.kubernetes.io/cors-allow-methods",
    "nginx.ingress.kubernetes.io/cors-allow-headers",
    "nginx.ingress.kubernetes.io/cors-allow-credentials",
    "nginx.ingress.kubernetes.io/cors-expose-headers",
    "nginx.ingress.kubernetes.io/cors-max-age",
    "nginx.ingress.kubernetes.io/force-ssl-redirect",
    "nginx.ingress.kubernetes.io/ssl-redirect",
    "nginx.ingress.kubernetes.io/proxy-read-timeout",
)


def _annotations(ingress: dict[str, Any]) -> dict[str, str]:
    meta = ingress.get("metadata") or {}
    annotations = meta.get("annotations") or {}
    return annotations if isinstance(annotations, dict) else {}


def _ingress_name(ingress: dict[str, Any]) -> str:
    return ((ingress.get("metadata") or {}).get("name") or "") or "ingress"


def _ingress_namespace(ingress: dict[str, Any]) -> str:
    return ((ingress.get("metadata") or {}).get("namespace") or "default") or "default"


def _ingress_hosts(ingress: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for rule in (ingress.get("spec") or {}).get("rules") or []:
        host = rule.get("host") or ""
        if host and host not in hosts:
            hosts.append(host)
    for tls in (ingress.get("spec") or {}).get("tls") or []:
        for host in tls.get("hosts") or []:
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def _ingress_paths(ingress: dict[str, Any]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for rule in (ingress.get("spec") or {}).get("rules") or []:
        http = rule.get("http") or {}
        for p in http.get("paths") or []:
            backend = p.get("backend") or {}
            service = backend.get("service") or {}
            port = service.get("port") or {}
            paths.append(
                {
                    "host": rule.get("host") or "",
                    "path": p.get("path") or "",
                    "path_type": p.get("path_type") or "Prefix",
                    "service_name": service.get("name") or "",
                    "service_port": port.get("number") or port.get("name") or 80,
                }
            )
    return paths


def _unsupported_annotations(ingress: dict[str, Any]) -> list[str]:
    annotations = _annotations(ingress)
    dropped: list[str] = []
    for key in sorted(annotations):
        if not key.startswith("nginx.ingress.kubernetes.io/"):
            continue
        if key not in SUPPORTED_ANNOTATION_PREFIXES and not any(
            key.startswith(prefix) for prefix in SUPPORTED_ANNOTATION_PREFIXES
        ):
            dropped.append(key)
    return dropped


def gateway_class(provider: str) -> dict[str, Any]:
    return {
        "kind": "GatewayClass",
        "apiVersion": f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}",
        "metadata": {"name": GATEWAY_CLASS_NAME.get(provider, GATEWAY_CLASS_NAME["envoy"])},
        "spec": {
            "controllerName": GATEWAY_CLASS_CONTROLLER_NAME.get(
                provider, GATEWAY_CLASS_CONTROLLER_NAME["envoy"]
            )
        },
    }


def gateway(ingress: dict[str, Any], provider: str, tls_secrets: list[str]) -> dict[str, Any]:
    gateway_name = _ingress_name(ingress)
    # Gateway API v1: GatewayListener.port is an int32 (the Ingress-shaped
    # {"number": N} dict is not a field — the apiserver prunes it).
    listeners: list[dict[str, Any]] = [
        {
            "name": HTTP_LISTENER_NAME,
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {"namespaces": {"from": "All"}},
        },
    ]
    for i, secret in enumerate(tls_secrets):
        listeners.append(
            {
                "name": f"{HTTPS_LISTENER_PREFIX}{i}",
                "port": 443,
                "protocol": "TLS",
                "tls": {"mode": "Terminate", "certificateRefs": [{"name": secret}]},
                "allowedRoutes": {"namespaces": {"from": "All"}},
            }
        )
    return {
        "kind": "Gateway",
        "apiVersion": f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}",
        "metadata": {"name": gateway_name, "namespace": _ingress_namespace(ingress)},
        "spec": {
            "gatewayClassName": GATEWAY_CLASS_NAME.get(provider, GATEWAY_CLASS_NAME["envoy"]),
            "listeners": listeners,
        },
    }


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _path_match_type(path: str, path_type: str, annotations: dict[str, str]) -> str:
    use_regex = str(annotations.get("nginx.ingress.kubernetes.io/use-regex") or "").lower()
    if use_regex == "true" or any(ch in path for ch in ("(", ")", "[", "]", "{", "}", "^", "$")):
        return "RegularExpression"
    if path_type == "Exact":
        return "Exact"
    if path_type == "ImplementationSpecific":
        return "ImplementationSpecific"
    return "PathPrefix"


# The CORS annotation family (the nginx ingress controller's CORS plugin).
# The Gateway API v1 HTTPRouteFilter enum has NO CORS filter — these
# annotations are DROPPED (reported in the warnings) instead of converted.
_CORS_ANNOTATION_PREFIXES: tuple[str, ...] = (
    "nginx.ingress.kubernetes.io/enable-cors",
    "nginx.ingress.kubernetes.io/cors-",
)


def _backend_filters(annotations: dict[str, str]) -> tuple[list[dict[str, Any]], list[str]]:
    """(v1 HTTPRouteFilters, dropped-CORS-annotation-keys).

    URLRewrite is the only convertible filter: v1 ``HTTPURLRewriteFilter``
    has no ``replacePrefixWith`` field — the target is
    ``path.replaceFullPath`` (a ReplaceFullPath HTTPPathModifier) or the
    apiserver prunes the whole filter, leaving the required ``path`` absent.
    The CORS family is NOT in the v1 filter enum: the sorted keys present on
    the ingress come back as ``dropped_cors_keys`` (the warnings) — at least
    the ``enable-cors`` key when CORS was requested.
    """
    filters: list[dict[str, Any]] = []
    if any(k.startswith("nginx.ingress.kubernetes.io/rewrite-target") for k in annotations):
        rewrite = next(
            (
                v
                for k, v in annotations.items()
                if k.startswith("nginx.ingress.kubernetes.io/rewrite-target")
            ),
            None,
        )
        if rewrite:
            filters.append(
                {
                    "type": "URLRewrite",
                    "urlRewrite": {"path": {"type": "ReplaceFullPath", "replaceFullPath": rewrite}},
                }
            )
    dropped_cors_keys = sorted(
        k for k in annotations if k.startswith(_CORS_ANNOTATION_PREFIXES)
    )
    return filters, dropped_cors_keys


def convert_ingress(
    ingress: dict[str, Any], provider: str = "envoy"
) -> tuple[list[dict[str, Any]], list[str]]:
    """Pure: Ingress dict → (resources, warnings).

    ``resources`` is [GatewayClass, Gateway, *HTTPRoutes]: ONE GatewayClass,
    ONE Gateway, and ONE HTTPRoute per ingress rule path (plus a
    redirect-only HTTPRoute when SSL redirect is forced) — all in Gateway
    API **v1** shapes (verified against the live v1 CRDs). ``warnings`` is
    the dropped-annotation list: the unsupported ``nginx`` annotations
    (``unsupported_annotations``) + the dropped CORS keys (the v1 filter
    enum has no CORS filter).
    """
    ingress_name = _ingress_name(ingress)
    namespace = _ingress_namespace(ingress)
    gateway_name = ingress_name
    gateway_class_obj = gateway_class(provider)
    tls_secrets = sorted(
        {
            (tls.get("secret_name") or "")
            for tls in (ingress.get("spec") or {}).get("tls") or []
            if tls.get("secret_name")
        }
    )
    tls_list: list[str] = list(dict.fromkeys(tls_secrets))
    tls_index_by_host: dict[str, int] = {}
    for tls in (ingress.get("spec") or {}).get("tls") or []:
        secret = tls.get("secret_name") or ""
        for host in tls.get("hosts") or []:
            if host and host not in tls_index_by_host and secret in tls_list:
                tls_index_by_host[host] = tls_list.index(secret)
    gateway_obj = gateway(ingress, provider, tls_secrets)
    resources: list[dict[str, Any]] = [gateway_class_obj, gateway_obj]

    paths = _ingress_paths(ingress)
    annotations = _annotations(ingress)
    backend_filters, dropped_cors_keys = _backend_filters(annotations)

    routes: list[dict[str, Any]] = []
    for idx, p in enumerate(paths):
        # Gateway API v1 HTTPBackendRef: FLAT {"name", "port"} (port is an
        # int) — the Ingress-shaped {"backend": {"service": {...}}} nesting
        # is not a v1 field.
        ref: dict[str, Any] = {
            "name": p["service_name"],
            "port": p["service_port"],
        }
        if any(k.startswith("nginx.ingress.kubernetes.io/canary-weight") for k in annotations):
            ref["weight"] = _int(annotations.get("nginx.ingress.kubernetes.io/canary-weight"))
        rule: dict[str, Any] = {
            "matches": [
                {
                    "path": {
                        "type": _path_match_type(p["path"], p["path_type"], annotations),
                        "value": p["path"],
                    }
                }
            ],
            "backendRefs": [ref],
            "filters": list(backend_filters),
        }
        if any(k.startswith("nginx.ingress.kubernetes.io/canary-by-header") for k in annotations):
            headers: list[dict[str, Any]] = []
            for key, value in sorted(annotations.items()):
                if not key.startswith("nginx.ingress.kubernetes.io/canary-by-header"):
                    continue
                short = key.split("nginx.ingress.kubernetes.io/", 1)[1]
                header_name = short.replace("canary-by-header-", "")
                headers.append({"type": "Header", "name": header_name, "value": value or "*"})
            if headers:
                rule["matches"][0]["headers"] = headers
        # Gateway API v1: there is NO spec-level "sectionName" on
        # HTTPRouteSpec — the listener binding goes on the parentRef
        # (sectionName, minLength 1 — the key is omitted entirely when the
        # host has no TLS secret; only the http listener applies).
        parent_ref: dict[str, Any] = {
            "name": gateway_name,
            "namespace": namespace,
            "kind": "Gateway",
        }
        if p["host"] in tls_index_by_host:
            parent_ref["sectionName"] = f"https-{tls_index_by_host[p['host']]}"
        route: dict[str, Any] = {
            "kind": "HTTPRoute",
            "apiVersion": f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}",
            "metadata": {"name": f"{ingress_name}-{idx}", "namespace": namespace},
            "spec": {
                "parentRefs": [parent_ref],
                "hostnames": _ingress_hosts(ingress),
                "rules": [rule],
            },
        }
        if any(k.startswith("nginx.ingress.kubernetes.io/proxy-read-timeout") for k in annotations):
            # v1 HTTPRouteSpec.timeouts.backendRequest is a Duration STRING
            # (pattern ^([0-9]{1,5}(h|m|s|ms)){1,4}$), not a numeric timeout.
            timeout_s = _int(annotations.get("nginx.ingress.kubernetes.io/proxy-read-timeout"))
            route["spec"]["timeouts"] = {"backendRequest": f"{timeout_s}s"}
        routes.append(route)
    resources.extend(routes)
    if any(
        k.startswith("nginx.ingress.kubernetes.io/force-ssl-redirect")
        or k.startswith("nginx.ingress.kubernetes.io/ssl-redirect")
        for k in annotations
    ):
        resources.append(
            {
                "kind": "HTTPRoute",
                "apiVersion": f"{GATEWAY_API_GROUP}/{GATEWAY_API_VERSION}",
                "metadata": {"name": f"{ingress_name}-redirect", "namespace": namespace},
                "spec": {
                    # The http→https redirect rides the PLAIN HTTP listener:
                    # the binding is the parentRef's sectionName ("http" —
                    # minLength 1, so the key is always present here).
                    "parentRefs": [
                        {
                            "name": gateway_name,
                            "namespace": namespace,
                            "kind": "Gateway",
                            "sectionName": HTTP_LISTENER_NAME,
                        }
                    ],
                    "hostnames": _ingress_hosts(ingress),
                    "rules": [
                        {
                            "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                            "backendRefs": [],
                            "filters": [
                                {
                                    # The v1 HTTPRouteFilter enum has NO
                                    # "Redirect" — the redirect filter is
                                    # "RequestRedirect" / requestRedirect.
                                    "type": "RequestRedirect",
                                    "requestRedirect": {
                                        "scheme": "https",
                                        "statusCode": 301,
                                    },
                                }
                            ],
                        }
                    ],
                },
            }
        )
    # The v1 CRD has no CORS filter: the dropped CORS keys join the
    # unsupported-annotation warnings (no overlap — the CORS keys are in
    # SUPPORTED_ANNOTATION_PREFIXES, so they never appear in both lists).
    warnings: list[str] = _unsupported_annotations(ingress) + dropped_cors_keys
    return resources, warnings


def unsupported_annotations(ingress: dict[str, Any]) -> list[str]:
    return _unsupported_annotations(ingress)
