"""kdlogin server-side push URL building."""

from unittest.mock import MagicMock

from lib.kdlogin_push import (
    KDLOGIN_PUSH_HOST_ENV,
    _host_for_http_url,
    _peer_closed_before_response_body,
    _push_host_candidates,
    client_ip_for_kdlogin_push,
    http_url_host_for_browser_handoff,
)


def test_host_for_http_url_ipv4_unchanged():
    assert _host_for_http_url("127.0.0.1") == "127.0.0.1"
    assert _host_for_http_url("192.168.1.1") == "192.168.1.1"


def test_host_for_http_url_ipv6_bracketed():
    assert _host_for_http_url("::1") == "[::1]"
    assert _host_for_http_url("2001:db8::1") == "[2001:db8::1]"


def test_host_for_http_url_hostname_unchanged():
    assert _host_for_http_url("localhost") == "localhost"


def test_http_url_host_for_browser_handoff_uses_plugin_ip():
    assert http_url_host_for_browser_handoff("192.168.9.68") == "192.168.9.68"


def test_http_url_host_for_browser_handoff_fallback_localhost_name():
    assert http_url_host_for_browser_handoff("") == "localhost"
    assert http_url_host_for_browser_handoff(None) == "localhost"


def test_push_host_candidates_docker_gateway():
    app = MagicMock()
    app.config = {}
    assert _push_host_candidates(app, "192.168.65.1") == ["192.168.65.1"]


def test_push_host_candidates_env_override(monkeypatch):
    app = MagicMock()
    app.config = {}
    monkeypatch.setenv(KDLOGIN_PUSH_HOST_ENV, "10.0.0.5")
    assert _push_host_candidates(app, "192.168.65.1") == ["10.0.0.5"]


def test_client_ip_prefers_first_usable_xff_over_loopback_remote():
    req = MagicMock()
    req.remote_addr = "127.0.0.1"
    req.environ = {"HTTP_X_FORWARDED_FOR": "10.0.0.5, 192.168.65.1"}
    req.access_route = []
    assert client_ip_for_kdlogin_push(req) == "10.0.0.5"


def test_client_ip_when_only_docker_gateway_in_xff_uses_it():
    req = MagicMock()
    req.remote_addr = "127.0.0.1"
    req.environ = {"HTTP_X_FORWARDED_FOR": "192.168.65.1"}
    req.access_route = []
    assert client_ip_for_kdlogin_push(req) == "192.168.65.1"


def test_push_host_candidates_plugin_host_only():
    app = MagicMock()
    app.config = {}
    assert _push_host_candidates(app, "192.168.65.1", plugin_client_host="192.168.9.68") == [
        "192.168.9.68",
    ]


def test_peer_closed_before_response_body_matches_urllib3_message():
    exc = Exception(
        "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))"
    )
    assert _peer_closed_before_response_body(exc) is True


def test_peer_closed_before_response_body_rejects_other_errors():
    assert _peer_closed_before_response_body(Exception("connection refused")) is False
