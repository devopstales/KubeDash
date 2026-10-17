from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from app.core.config import get_settings
from app.extensions import api, db, migrate, redis_client


def create_app(config_overrides: dict | None = None) -> Flask:
    settings = get_settings()
    overrides = config_overrides or {}
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=overrides.get("KUBEDASH_SECRET_KEY", settings.kubedash_secret_key),
        SQLALCHEMY_DATABASE_URI=overrides.get("DATABASE_URL", settings.database_url),
        TESTING=overrides.get("TESTING", False),
        KUBEDASH_REDIS_URL=overrides.get("REDIS_URL", settings.redis_url),
    )
    db.init_app(app)
    migrate.init_app(app, db)
    api.init_app(app, url_prefix="/api/v1")
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
    def healthz() -> tuple[dict[str, str], int]:
        return jsonify(status="ok")

    @app.get("/readyz")
    def readyz() -> tuple[dict[str, str], int]:
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
    @app.errorhandler(HTTPException)
    def on_http_error(err: HTTPException) -> tuple[dict, int]:
        return jsonify(error={"code": err.name, "message": err.description}), err.code


def register_static(app: Flask) -> None:
    """Registered last so /api/v1/* and /ws/* win. SPA fallback in Task 9."""
    pass
