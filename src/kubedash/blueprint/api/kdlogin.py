"""Public API for kdlogin plugin: fetch kubeconfig by one-time code."""

from flask import current_app, jsonify, request
from flask.views import MethodView
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.kdlogin_exchange import (
    client_ip_for_rate_limit,
    pop_kdlogin_config_payload,
    rate_limit_exchange,
)

##############################################################
## Blueprint
##############################################################

kdlogin_api_bp = Blueprint(
    "kdlogin_api",
    "kdlogin_api",
    url_prefix="/kdlogin",
    description="kdlogin kubectl plugin — config exchange",
)

logger = get_logger()


@kdlogin_api_bp.route("/config")
class KdloginConfigByCode(MethodView):
    """GET /api/v1/kdlogin/config?code=... — single-use kubeconfig payload."""

    @kdlogin_api_bp.doc(tags=["kdlogin"])
    def get(self):
        code = (request.args.get("code") or "").strip()
        if not code:
            return jsonify({"error": "missing_code", "message": "Query parameter code is required"}), 400

        if not rate_limit_exchange(current_app, client_ip_for_rate_limit()):
            logger.warning("kdlogin config exchange rate limited ip=%s", client_ip_for_rate_limit())
            return jsonify({"error": "rate_limited", "message": "Too many requests"}), 429

        payload = pop_kdlogin_config_payload(current_app, code)
        if payload is None:
            return jsonify({"error": "not_found", "message": "Invalid or expired code"}), 404

        return jsonify(payload), 200
