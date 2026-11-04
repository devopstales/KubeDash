"""ADR-0040 R4/R5 — the cross-tab deep-link handoff at the server seam.

The share form POSTs ``o=<token>`` to the list route. The SPA fallback
bounces the POST as a 303 to the same path and stashes the token in
Redis keyed by the authenticated user's JWT ``sub`` (``obj_incoming:<sub>``,
TTL 60 s = the client relay window). The first subsequent GET pops the
stash and injects it into ``index.html`` as
``<meta name="kd-object-incoming" content="<token>">``. The token never
appears in a URL (R1); the ref payload still crosses tabs through the
localStorage relay the client wrote before the POST (R5).

Same docker-free pattern as the rest of this directory: the api-tier app
with the monkeypatched ``_FakeRedis`` standing in for Redis.
"""

from __future__ import annotations

import os
from pathlib import Path

INDEX_HTML = (
    "<!doctype html>\n<html lang=\"en\">\n<head>\n"
    "<meta charset=\"utf-8\" />\n"
    "<title>KubeDash</title>\n"
    "<script type=\"module\" src=\"/assets/index-test.js\"></script>\n"
    "</head>\n<body>\n<div id=\"root\"></div>\n</body>\n</html>\n"
)


def _write_index() -> None:
    """The api-tier fixture home has no static dir; register_static's
    catch-all resolves <home>/static at request time, so drop a minimal
    index.html into it (the tests assert on the injected document)."""
    home = Path(os.environ["KUBEDASH_HOME"])
    static = home / "static"
    static.mkdir(exist_ok=True)
    (static / "index.html").write_text(INDEX_HTML, encoding="utf-8")


def _fake_redis():
    import app.extensions as ext

    return ext.redis_client


def test_post_bounces_303_to_the_same_path_and_stashes_the_token(auth_client) -> None:
    """The form POST (the share button's dispatch) must NOT 405 (the pre-fix
    behavior) and must not put the token anywhere in the URL: 303 to the
    exact same path, token stashed server-side under the session's JWT sub."""
    auth_client.login()
    _write_index()
    r = auth_client.post("/cluster/crd", data={"o": "abcd1234abcd1234"})
    assert r.status_code == 303
    assert r.headers["Location"] == "/cluster/crd"
    assert _fake_redis().store.get("obj_incoming:sub-oidc-1") == "abcd1234abcd1234"


def test_get_after_bounce_injects_the_meta_and_pops_the_stash(auth_client) -> None:
    """The fresh tab's GET (carrying the same session cookie) gets index.html
    with the one-shot meta injected, and the stash is consumed (GETDEL)."""
    auth_client.login()
    _write_index()
    auth_client.post("/cluster/crd", data={"o": "abcd1234abcd1234"})
    r = auth_client.get("/cluster/crd")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    body = r.get_data(as_text=True)
    assert '<meta name="kd-object-incoming" content="abcd1234abcd1234" />' in body
    # One-shot: the stash is gone after the first GET.
    assert "obj_incoming:sub-oidc-1" not in _fake_redis().store
    r2 = auth_client.get("/cluster/crd")
    assert "kd-object-incoming" not in r2.get_data(as_text=True)


def test_injected_document_is_no_store_and_plain_is_no_cache(auth_client) -> None:
    auth_client.login()
    _write_index()
    auth_client.post("/cluster/crd", data={"o": "abcd1234abcd1234"})
    r = auth_client.get("/cluster/crd")
    assert r.headers["Cache-Control"] == "no-store"
    # Plain document (no stash) keeps the current no-cache caching.
    r2 = auth_client.get("/other-resource/priorityclass")
    assert r2.headers["Cache-Control"] == "no-cache"


def test_get_without_stash_serves_plain_index(auth_client) -> None:
    auth_client.login()
    _write_index()
    r = auth_client.get("/cluster/crd")
    assert r.status_code == 200
    assert "kd-object-incoming" not in r.get_data(as_text=True)
    assert "<title>KubeDash</title>" in r.get_data(as_text=True)


def test_post_without_a_valid_session_bounces_but_does_not_stash(api_client) -> None:
    """An anonymous (or expired/revoked) session still gets the 303 bounce —
    the new tab then simply renders the list (no meta to hydrate)."""
    _write_index()
    r = api_client.post("/cluster/crd", data={"o": "abcd1234abcd1234"})
    assert r.status_code == 303
    assert _fake_redis().store == {}


def test_post_with_malformed_token_is_not_stashed(auth_client) -> None:
    auth_client.login()
    _write_index()
    for bad in ("XYZ", "", "g" * 20, "abcd1234abcd1234abcd1234abcd1234"):
        r = auth_client.post("/cluster/crd", data={"o": bad})
        assert r.status_code == 303
    assert _fake_redis().store == {}


def test_post_without_an_o_field_bounces_and_does_not_stash(auth_client) -> None:
    auth_client.login()
    _write_index()
    r = auth_client.post("/cluster/crd")
    assert r.status_code == 303
    assert _fake_redis().store == {}


def test_post_to_an_api_path_is_404_not_a_bounce(auth_client) -> None:
    auth_client.login()
    _write_index()
    r = auth_client.post("/api/v1/definitely-not-a-route", data={"o": "abcd1234abcd1234"})
    assert r.status_code == 404
    assert r.headers.get("Location") is None
    assert _fake_redis().store == {}


def test_root_get_consumes_a_stash(auth_client) -> None:
    """index() (/) uses the same render path: a stash left by a bounce is
    consumed by the first GET on / as well (uniform one-shot semantics)."""
    auth_client.login()
    _write_index()
    _fake_redis().set("obj_incoming:sub-oidc-1", "abcd1234abcd1234", ex=60)
    r = auth_client.get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert '<meta name="kd-object-incoming" content="abcd1234abcd1234" />' in html
    assert "obj_incoming:sub-oidc-1" not in _fake_redis().store
