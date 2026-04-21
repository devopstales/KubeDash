"""
Exec Session Recording API endpoints.

Provides endpoints for:
- Receiving event batches from frontend session recorder
- Saving session metadata on finalize
- Listing sessions with filtering and pagination
- Retrieving session events for replay
"""
import uuid
from datetime import datetime, timezone

from flask import g, jsonify, request, session
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint
from sqlalchemy import desc, and_

from lib.components import db
from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from models.exec_session import ExecSession, ExecSessionEvent
from lib.user import User

exec_sessions_api_bp = Blueprint(
    "exec_sessions_api",
    "exec_sessions_api",
    url_prefix="/exec",
    description="Exec session recording and replay endpoints"
)

logger = get_logger()
tracer = get_tracer()


@exec_sessions_api_bp.route('/sessions/<session_id>/events', methods=['POST'])
class SessionEventsResource(MethodView):
    """
    Receive event batches from frontend SessionRecorder.
    
    Auth: Only the session owner can post events.
    """

    @login_required
    def post(self, session_id):
        """
        Receive a batch of exec session events.
        
        Path Parameters:
            session_id (str): UUID of the exec session
        
        Request Body:
            events (list): List of event objects with timestamp, event_type, data
        
        Returns:
            201 on success with count of events saved
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return jsonify({"error": "Invalid session ID format"}), 400

        # Verify session exists and belongs to user
        exec_session = db.session.get(ExecSession, session_uuid)
        if not exec_session:
            return jsonify({"error": "Session not found"}), 404
        
        if exec_session.user_id != current_user.id and session.get('user_role') != 'Admin':
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        if not data or 'events' not in data:
            return jsonify({"error": "Missing 'events' in request body"}), 400

        events = data['events']
        if not isinstance(events, list):
            return jsonify({"error": "'events' must be a list"}), 400

        # Save events
        saved_count = 0
        for event_data in events:
            try:
                event = ExecSessionEvent(
                    session_id=session_uuid,
                    timestamp=event_data.get('timestamp', 0),
                    event_type=event_data.get('event_type', 'output'),
                    data=event_data.get('data', '')
                )
                db.session.add(event)
                saved_count += 1
            except Exception as e:
                logger.warning(f"Failed to save exec event: {e}")
                continue

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to commit exec events: {e}")
            return jsonify({"error": "Failed to save events"}), 500

        return jsonify({
            "message": f"Saved {saved_count} events",
            "count": saved_count
        }), 201


@exec_sessions_api_bp.route('/sessions/<session_id>/metadata', methods=['PUT'])
class SessionMetadataResource(MethodView):
    """
    Save session metadata on finalize (exit status, duration, end time).
    
    Auth: Only the session owner can update metadata.
    """

    @login_required
    def put(self, session_id):
        """
        Update exec session metadata on completion.
        
        Path Parameters:
            session_id (str): UUID of the exec session
        
        Request Body:
            exit_status (str): normal, timeout, error, user-disconnect, connection-lost
            duration_ms (int): Session duration in milliseconds
            end_time (str): ISO 8601 timestamp
        
        Returns:
            200 on success
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return jsonify({"error": "Invalid session ID format"}), 400

        exec_session = db.session.get(ExecSession, session_uuid)
        if not exec_session:
            return jsonify({"error": "Session not found"}), 404
        
        if exec_session.user_id != current_user.id and session.get('user_role') != 'Admin':
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing request body"}), 400

        # Update metadata
        if 'exit_status' in data:
            exec_session.exit_status = data['exit_status']
        
        if 'duration_ms' in data:
            exec_session.duration_ms = data['duration_ms']
        
        if 'end_time' in data:
            try:
                exec_session.end_time = datetime.fromisoformat(data['end_time'])
            except ValueError:
                exec_session.end_time = datetime.now(timezone.utc)
        else:
            exec_session.end_time = datetime.now(timezone.utc)

        # Calculate duration if not provided
        if exec_session.start_time and exec_session.end_time and not exec_session.duration_ms:
            exec_session.duration_ms = int(
                (exec_session.end_time - exec_session.start_time).total_seconds() * 1000
            )

        try:
            db.session.commit()
            
            # Audit log
            log_audit_event(
                action='exec_session_finalize',
                username=session.get('user_role', 'unknown'),
                details={
                    'session_id': session_id,
                    'exit_status': exec_session.exit_status,
                    'duration_ms': exec_session.duration_ms
                }
            )
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to update session metadata: {e}")
            return jsonify({"error": "Failed to update metadata"}), 500

        return jsonify({
            "message": "Session metadata updated",
            "data": exec_session.to_dict()
        })


@exec_sessions_api_bp.route('/sessions', methods=['GET'])
class SessionsListResource(MethodView):
    """
    List exec sessions with filtering and pagination.
    
    Auth: Admin sees all sessions, users see only their own.
    """

    @login_required
    def get(self):
        """
        List exec sessions with optional filtering.
        
        Query Parameters:
            namespace (str): Filter by namespace
            pod (str): Filter by pod name
            exit_status (str): Filter by exit status
            date_from (str): Filter sessions from this date (ISO 8601)
            date_to (str): Filter sessions to this date (ISO 8601)
            page (int): Page number (default: 1)
            per_page (int): Items per page (default: 50, max: 100)
        
        Returns:
            Paginated list of sessions
        """
        # RBAC: Admin sees all, users see own
        is_admin = session.get('user_role') == 'Admin'
        
        query = db.session.query(ExecSession)
        if not is_admin:
            query = query.filter(ExecSession.user_id == current_user.id)

        # Apply filters
        namespace = request.args.get('namespace')
        if namespace:
            query = query.filter(ExecSession.namespace == namespace)

        pod = request.args.get('pod')
        if pod:
            query = query.filter(ExecSession.pod.ilike(f'%{pod}%'))

        exit_status = request.args.get('exit_status')
        if exit_status:
            query = query.filter(ExecSession.exit_status == exit_status)

        date_from = request.args.get('date_from')
        if date_from:
            try:
                date_from_dt = datetime.fromisoformat(date_from)
                query = query.filter(ExecSession.start_time >= date_from_dt)
            except ValueError:
                pass

        date_to = request.args.get('date_to')
        if date_to:
            try:
                date_to_dt = datetime.fromisoformat(date_to)
                query = query.filter(ExecSession.start_time <= date_to_dt)
            except ValueError:
                pass

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        per_page = min(per_page, 100)  # Cap at 100

        pagination = query.order_by(desc(ExecSession.start_time)).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return jsonify({
            "data": [s.to_dict(include_events=True) for s in pagination.items],
            "metadata": {
                "page": pagination.page,
                "per_page": pagination.per_page,
                "total": pagination.total,
                "pages": pagination.pages
            }
        })


@exec_sessions_api_bp.route('/sessions/<session_id>', methods=['GET'])
class SessionDetailResource(MethodView):
    """
    Get single session metadata (no events).
    """

    @login_required
    def get(self, session_id):
        """
        Get exec session metadata.
        
        Path Parameters:
            session_id (str): UUID of the exec session
        
        Returns:
            Session metadata
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return jsonify({"error": "Invalid session ID format"}), 400

        exec_session = db.session.get(ExecSession, session_uuid)
        if not exec_session:
            return jsonify({"error": "Session not found"}), 404

        # RBAC check
        is_admin = session.get('user_role') == 'Admin'
        if not is_admin and exec_session.user_id != current_user.id:
            return jsonify({"error": "Unauthorized"}), 403

        return jsonify({
            "data": exec_session.to_dict(include_events=True)
        })


@exec_sessions_api_bp.route('/sessions/<session_id>/events', methods=['GET'])
class SessionEventsListResource(MethodView):
    """
    Get session events for replay with pagination.
    """

    @login_required
    def get(self, session_id):
        """
        Get exec session events for replay.
        
        Path Parameters:
            session_id (str): UUID of the exec session
        
        Query Parameters:
            page (int): Page number (default: 1)
            per_page (int): Events per page (default: 1000, max: 5000)
        
        Returns:
            Paginated list of events
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return jsonify({"error": "Invalid session ID format"}), 400

        exec_session = db.session.get(ExecSession, session_uuid)
        if not exec_session:
            return jsonify({"error": "Session not found"}), 404

        # RBAC check
        is_admin = session.get('user_role') == 'Admin'
        if not is_admin and exec_session.user_id != current_user.id:
            return jsonify({"error": "Unauthorized"}), 403

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 1000, type=int)
        per_page = min(per_page, 5000)  # Cap at 5000

        query = db.session.query(ExecSessionEvent).filter(
            ExecSessionEvent.session_id == session_uuid
        ).order_by(ExecSessionEvent.timestamp)

        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            "data": [e.to_dict() for e in pagination.items],
            "metadata": {
                "page": pagination.page,
                "per_page": pagination.per_page,
                "total": pagination.total,
                "pages": pagination.pages,
                "session": exec_session.to_dict()
            }
        })
