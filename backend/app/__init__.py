from collections.abc import Mapping

from flask import Flask, Response, jsonify
from werkzeug.exceptions import HTTPException

from app.core.config import get_settings
from app.extensions import api, db, migrate, redis_client


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
    app.config["OPENAPI_URL_PREFIX"] = "/api"
    api.init_app(app)
    redis_client.from_url(app.config["KUBEDASH_REDIS_URL"])

    # register domain APIs (later tasks add their lines; auth in Task 3)
    from app.api import register_apis

    register_apis(api)

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
    def on_http_error(err: HTTPException) -> tuple[Response, int]:
        return jsonify(error={"code": err.name, "message": err.description}), err.code or 500

    # Register via the method, not the @errorhandler decorator: Flask's
    # errorhandler is identity-typed (Callable[[T], T]) and rejects handler
    # return types other than what it infers for the argument.
    app.register_error_handler(HTTPException, on_http_error)


def register_static(app: Flask) -> None:
    """Registered last so /api/v1/* and /ws/* win. SPA fallback in Task 9."""
    pass
