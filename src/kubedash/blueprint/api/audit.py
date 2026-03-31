"""
Audit log API endpoints for query and export (compliance).
Admin-only. See Audit Logging PRD.
"""

import csv
import io
from contextlib import nullcontext
from datetime import datetime, timezone

from flask import Response, g, jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint
from lib.audit import AuditLog, log_audit_event
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

##############################################################
## Blueprint Definition
##############################################################

audit_api_bp = Blueprint(
    "audit_api",
    "audit_api",
    url_prefix="/audit",
    description="Audit log API - Query and export audit events (Admin only)",
)

logger = get_logger()
tracer = get_tracer()

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
MAX_EXPORT_ROWS = 10000


def _require_admin():
    """Return (error_response, status) if not admin, else (None, None)."""
    if session.get("user_role") != "Admin":
        return jsonify({"error": "Forbidden", "message": "Admin role required"}), 403
    return None, None


def _parse_filters():
    """Parse query params into filter dict and pagination."""
    user_id = request.args.get("user_id", "").strip() or None
    action = request.args.get("action", "").strip() or None
    resource = request.args.get("resource", "").strip() or None
    result = request.args.get("result", "").strip() or None
    date_from = request.args.get("date_from", "").strip() or None
    date_to = request.args.get("date_to", "").strip() or None
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    try:
        per_page = min(MAX_PAGE_SIZE, max(1, int(request.args.get("per_page", DEFAULT_PAGE_SIZE))))
    except ValueError:
        per_page = DEFAULT_PAGE_SIZE
    return {
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "result": result,
        "date_from": date_from,
        "date_to": date_to,
        "page": page,
        "per_page": per_page,
    }


def _apply_filters(query, filters):
    """Apply filters to AuditLog query."""
    if filters.get("user_id"):
        query = query.filter(AuditLog.user_id.ilike(f"%{filters['user_id']}%"))
    if filters.get("action"):
        query = query.filter(AuditLog.action.ilike(f"%{filters['action']}%"))
    if filters.get("resource"):
        query = query.filter(AuditLog.resource.ilike(f"%{filters['resource']}%"))
    if filters.get("result"):
        query = query.filter(AuditLog.result == filters["result"])
    if filters.get("date_from"):
        try:
            dt = datetime.fromisoformat(filters["date_from"].replace("Z", "+00:00"))
            query = query.filter(AuditLog.created_at >= dt)
        except ValueError:
            pass
    if filters.get("date_to"):
        try:
            dt = datetime.fromisoformat(filters["date_to"].replace("Z", "+00:00"))
            query = query.filter(AuditLog.created_at <= dt)
        except ValueError:
            pass
    return query


def _row_to_dict(row):
    """Convert AuditLog row to JSON-serializable dict."""
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "trace_id": row.trace_id,
        "user_id": row.user_id,
        "action": row.action,
        "resource": row.resource,
        "result": row.result,
        "details": row.details,
        "message": row.message,
    }


@audit_api_bp.route("")
class AuditLogListResource(MethodView):
    """
    List audit log entries with optional filters and pagination.
    Admin only.
    """

    @audit_api_bp.response(200, description="Paginated audit log list")
    @audit_api_bp.response(403, description="Admin role required")
    @audit_api_bp.doc(tags=["Audit"])
    @login_required
    def get(self):
        err, status = _require_admin()
        if err is not None:
            return err, status
        filters = _parse_filters()
        page = filters["page"]
        per_page = filters["per_page"]

        with tracer.start_as_current_span(
            "audit-log-list",
            attributes={"http.route": "/api/v1/audit", "http.method": "GET"},
        ) if tracer else nullcontext():
            query = AuditLog.query.order_by(AuditLog.created_at.desc())
            query = _apply_filters(query, filters)
            total = query.count()
            paginated = query.offset((page - 1) * per_page).limit(per_page).all()
            pages = (total + per_page - 1) // per_page if per_page else 0

            return jsonify({
                "data": [_row_to_dict(r) for r in paginated],
                "metadata": {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": pages,
                },
            })


@audit_api_bp.route("/export")
class AuditLogExportResource(MethodView):
    """
    Export audit log as CSV or JSON. Admin only.
    Query params: format=csv|json, plus same filters as list. Limited to MAX_EXPORT_ROWS.
    """

    @audit_api_bp.response(200, description="Audit log export (CSV or JSON)")
    @audit_api_bp.response(403, description="Admin role required")
    @audit_api_bp.doc(tags=["Audit"])
    @login_required
    def get(self):
        err, status = _require_admin()
        if err is not None:
            return err, status
        export_format = (request.args.get("format", "json") or "json").strip().lower()
        if export_format not in ("csv", "json"):
            return jsonify({"error": "Bad Request", "message": "format must be csv or json"}), 400

        filters = _parse_filters()
        # Export uses same filters but no pagination; cap at MAX_EXPORT_ROWS
        limit = min(MAX_EXPORT_ROWS, filters.get("per_page") or MAX_EXPORT_ROWS)
        query = AuditLog.query.order_by(AuditLog.created_at.desc())
        query = _apply_filters(query, filters)
        rows = query.limit(limit).all()

        actor = session.get("user_name", "unknown")
        log_audit_event(
            user_id=actor,
            action="audit_export",
            resource="audit_log",
            result="success",
            trace_id=getattr(g, "correlation_id", None),
            details={"format": export_format, "rows": len(rows)},
        )

        if export_format == "json":
            return jsonify({
                "data": [_row_to_dict(r) for r in rows],
                "metadata": {"total": len(rows), "exported_at": datetime.now(timezone.utc).isoformat()},
            })

        # CSV
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "created_at", "trace_id", "user_id", "action", "resource", "result", "details", "message"])
        for r in rows:
            details_str = ""
            if r.details:
                import json as _json
                details_str = _json.dumps(r.details) if isinstance(r.details, dict) else str(r.details)
            writer.writerow([
                r.id,
                r.created_at.isoformat() if r.created_at else "",
                r.trace_id or "",
                r.user_id or "",
                r.action or "",
                r.resource or "",
                r.result or "",
                details_str,
                (r.message or "").replace("\n", " "),
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
        )
