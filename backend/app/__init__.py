from collections.abc import Mapping

from flask import Flask, Response, jsonify
from werkzeug.exceptions import HTTPException, Unauthorized

from app import models  # noqa: F401
from app.api import register_apis
from app.core.config import get_settings
from app.extensions import api, db, migrate, redis_client

# `app.models` is imported for side effect only: it registers every table on
# db.metadata so db.create_all() (conftest) and Alembic autogenerate see the
# models. The factory stays pure — the Leader election thread is started from
# wsgi.py / the RQ worker (Task 7), never here.


def create_app(config_overrides: Mapping[str, object] | None = None) -> Flask:
    settings = get_settings()
    overrides = config_overrides or {}
    app = Flask(__name__, static_folder=None)
    # The KUBEDASH_* names and the unprefixed ARCHITECTURE.md §3.8 names
    # (DATABASE_URL, REDIS_URL) are both accepted; where both spellings are
    # given the KUBEDASH_* form wins, and when neither is, the Settings
    # default applies. app.config is the runtime source of truth.
    app.config["SECRET_KEY"] = str(
        overrides.get("KUBEDASH_SECRET_KEY", settings.kubedash_secret_key)
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = str(
        overrides.get("KUBEDASH_DATABASE_URL", overrides.get("DATABASE_URL", settings.database_url))
    )
    app.config["KUBEDASH_REDIS_URL"] = str(
        overrides.get("KUBEDASH_REDIS_URL", overrides.get("REDIS_URL", settings.redis_url))
    )
    app.config["TESTING"] = bool(overrides.get("TESTING", False))
    # Static dir seam (ADR-0006 / OD-4): config_overrides (tests' fake dist) is
    # applied BEFORE register_static closes over it; the Dockerfile ENV
    # KUBEDASH_STATIC_DIR=/app/static is the production value.
    app.config.setdefault(
        "KUBEDASH_STATIC_DIR", str(overrides.get("KUBEDASH_STATIC_DIR", "/app/static"))
    )

    db.init_app(app)
    migrate.init_app(app, db)
    # flask-smorest has no url_prefix kwarg; the /api/v1 API namespace and the
    # /api/openapi.json path are selected via its OPENAPI_URL_PREFIX config key.
    # Domain Api subclasses (later tasks) register their routes on this Api and
    # each route path starts with /v1/ so it lands at /api/v1/....
    # Smorest also requires a title/version for the OpenAPI spec (API_TITLE /
    # API_VERSION / OPENAPI_VERSION app config keys).
    app.config.setdefault("API_TITLE", "KubeDash API")
    app.config.setdefault("API_VERSION", "v1")
    app.config.setdefault("OPENAPI_VERSION", "3.0.3")
    # apispec 6 MarshmallowPlugin: @blp.doc(responses=(...)) tuples would
    # confuse its resolver; smorest's default responses (400/404/405/500)
    # already cover the envelope, so keep doc() calls responses-free.
    app.config.setdefault("API_SPEC_OPTIONS", {"operationIdHelper": None})
    app.config["OPENAPI_URL_PREFIX"] = "/api"
    # Swagger UI needs BOTH the mount path and the CDN script URL to render;
    # setting only the path leaves the route unregistered (404). The path is
    # joined UNDER OPENAPI_URL_PREFIX, so "/docs" lands at /api/docs.
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/docs"
    app.config["OPENAPI_SWAGGER_UI_URL"] = (
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"
    )
    api.init_app(app)
    # Authlib binds the OIDC client to this app (Task 3). The client config is
    # Settings-driven; tests never reach the IdP (they patch the two seams).
    from app.core.security import init_oidc

    init_oidc(app)
    # A fresh underlying client per app, bound to THIS app. Never use the
    # module-global redis client with from_url in the factory: it would
    # rebind the first app's client when a second create_app runs (conftest
    # builds one app per test). flask-redis' init_app does exactly this.
    redis_client.init_app(app)

    # Register domain APIs (later tasks add their Api classes there).
    # Imported at module top, NOT here: an in-function `from app.api import …`
    # compiles to IMPORT_NAME "app.api", which binds the submodule as a global
    # named `api` and shadows the Smorest Api instance on the next line.
    register_apis(app, api)

    register_health(app)
    register_errors(app)
    register_static(app)
    return app


def register_health(app: Flask) -> None:
    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz() -> tuple[Response, int]:
        checks: dict[str, str] = {}
        with app.app_context():
            try:
                db.engine.connect().close()
                checks["database"] = "ok"
            except Exception:
                checks["database"] = "down"
            try:
                redis_client.ping()
                checks["redis"] = "ok"
            except Exception:
                checks["redis"] = "down"
        healthy = all(v == "ok" for v in checks.values())
        return jsonify(checks), (200 if healthy else 503)


def register_errors(app: Flask) -> None:
    from app.core.errors import UNAUTHORIZED_STATUS, KubeDashHttpError, StateMismatchError

    def on_http_error(err: HTTPException) -> tuple[Response, int]:
        # OD-1: stable codes win over the legacy name-based envelope.
        if isinstance(err, StateMismatchError):
            # consume_state failure is a client mistake (400), not an auth
            # failure (401) — the dedicated class keeps the mapping exact.
            return jsonify(error=err.as_dict()), 400
        if isinstance(err, KubeDashHttpError):
            return jsonify(error=err.as_dict()), err.code or 500
        if isinstance(err, Unauthorized):
            return (
                jsonify(
                    error={"code": "UNAUTHORIZED", "message": "missing or invalid token"}
                ),
                UNAUTHORIZED_STATUS,
            )
        return jsonify(error={"code": err.name, "message": err.description}), err.code or 500

    def on_unhandled(_err: Exception) -> tuple[Response, int]:
        # 10th frozen code: generic message, never the exception repr — no
        # stack-trace leak out of the envelope.
        return jsonify(error={"code": "INTERNAL_ERROR", "message": "internal server error"}), 500

    # Register via the method, not the @errorhandler decorator: Flask's
    # errorhandler is identity-typed (Callable[[T], T]) and rejects handler
    # return types other than what it infers for the argument.
    app.register_error_handler(HTTPException, on_http_error)
    app.register_error_handler(Exception, on_unhandled)


def register_static(app: Flask) -> None:
    """Last registration: /api/v1/* and /ws/* win over the SPA catch-all (OD-4).
    Idempotency-guarded: KUBEDASH_STATIC_DIR is read at registration time from
    app.config (set via config_overrides before create_app in tests)."""
    if app.config.get("_STATIC_REGISTERED"):
        return
    app.config["_STATIC_REGISTERED"] = True
    from flask import abort, send_from_directory
    static_dir = app.config.get("KUBEDASH_STATIC_DIR", "/app/static")

    @app.get("/assets/<path:filename>")
    def assets(filename: str) -> Response:
        resp = send_from_directory(str(static_dir), "assets/" + filename)
        resp.headers["Cache-Control"] = "immutable, max-age=31536000"
        return resp

    @app.get("/")
    def index() -> Response:
        return spa("")

    @app.get("/<path:path_>")
    def spa(path_: str) -> Response:
        if path_.startswith(("api/", "ws/")) or path_.endswith(
            (".js", ".css", ".ico", ".png", ".json", ".map")
        ):
            abort(404)
        resp = send_from_directory(str(static_dir), "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
