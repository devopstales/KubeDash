#!/usr/bin/env python3
"""
AI Chat plugin API: chat message endpoint.

Registered under /api/v1/plugins/ai-chat/ (see initialize_plugin_apis).

Supports:
- OpenAI-compatible LLM providers (ChatGPT, Ollama, Gemini, Azure)
- Air-gapped mode with minimal chatbot (no external dependencies)
"""

import json
import re
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from flask import current_app, jsonify, request, session
from flask_login import login_required, current_user
from flask_smorest import Blueprint

from lib.components import db, csrf
from lib.helper_functions import get_logger, ErrorHandler
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token

from plugins.ai_chat.model import McpConversation, McpMessage
from plugins.ai_chat import chat as llm_chat
from plugins.ai_chat.intent_parser import parse_intent
from plugins.ai_chat.provider_registry import registry as provider_registry

##############################################################
## Blueprint
##############################################################

ai_chat_api_bp = Blueprint(
    "ai_chat_api",
    __name__,
    url_prefix="/ai-chat",
    description="AI Chat - Chat API for AI-backed cluster queries",
)
logger = get_logger()
tracer = get_tracer()

csrf.exempt(ai_chat_api_bp)


def _get_ai_chat_config() -> Dict[str, Any]:
    """Read [ai_chat] from kubedash.ini (read_only for write protection)."""
    try:
        ini = current_app.config.get("kubedash.ini")
        if not ini or "ai_chat" not in ini:
            return {"read_only": False}
        section = ini["ai_chat"]
        read_only = section.getboolean("read_only", fallback=False)
        return {"read_only": read_only}
    except Exception:
        return {"read_only": False}


def _get_or_create_conversation(user_id: int, conversation_id_str: Optional[str]) -> McpConversation:
    """Return existing conversation if valid and owned by user, else create and return a new one."""
    if conversation_id_str:
        try:
            cid = int(conversation_id_str)
            conv = McpConversation.query.filter_by(id=cid, user_id=user_id).first()
            if conv:
                return conv
        except (TypeError, ValueError):
            pass

    conv = McpConversation(user_id=user_id)
    db.session.add(conv)
    db.session.commit()
    return conv


def _save_message(conversation_id: int, role: str, content: str, 
                  tool_calls: Optional[List] = None, tool_results: Optional[List] = None):
    """Append a message to a conversation and bump updated_at."""
    msg = McpMessage(
        conversation_id=conversation_id,
        role=role,
        content=content,
        tool_calls=tool_calls,
        tool_results=tool_results,
    )
    db.session.add(msg)
    conv = McpConversation.query.get(conversation_id)
    if conv:
        conv.updated_at = datetime.now(timezone.utc)
    db.session.commit()


def _auto_generate_title(first_message: str) -> str:
    """Generate conversation title from first message."""
    if len(first_message) <= 50:
        return first_message

    # Try to find first sentence
    match = re.search(r'^(.+?[.!?])', first_message)
    if match:
        return match.group(1).strip()

    return first_message[:50] + '...'


def _run_minimal_intent_sync(
    content: str,
    conversation: McpConversation,
) -> Optional[Tuple[str, int]]:
    """
    If the message is a greeting or help intent, handle via minimal provider and return (reply, conversation_id).
    Returns None otherwise so the caller can use LLM.
    """
    intent = parse_intent(content)
    if not intent:
        return None
    intent_type = intent.get("type")
    if intent_type not in ("greeting", "help"):
        return None
    minimal = getattr(provider_registry, "minimal_provider", None)
    if not minimal:
        return None
    try:
        reply = minimal.handle_greeting_help_sync(intent_type, content)
        if reply is None:
            return None
        _save_message(conversation.id, "assistant", reply)
        return (reply, conversation.id)
    except Exception as e:
        logger.warning("Minimal intent execution failed: %s", e)
        return None


def run_k8s_intent_sync(
    content: str,
    conversation: McpConversation,
    config: Dict[str, Any],
) -> Optional[Tuple[str, int]]:
    """
    If the message is a recognized intent, execute it via k8s adapter (lib/k8s) and minimal provider.
    Returns (reply, conversation_id) or None if not a recognized intent.
    """
    intent = parse_intent(content)
    if not intent:
        return None

    intent_type = intent.get("type")
    read_only = config.get("read_only", False)
    write_intents = {"create_namespace", "delete_pod", "delete_deployment"}
    if read_only and intent_type in write_intents:
        reply = (
            "Write operations are disabled. AI Chat is configured in **read-only** mode."
        )
        _save_message(conversation.id, "assistant", reply)
        return (reply, conversation.id)

    minimal = getattr(provider_registry, "minimal_provider", None)
    if not minimal:
        return None

    # Greeting/help: use sync handler
    if intent_type in ("greeting", "help"):
        try:
            reply = minimal.handle_greeting_help_sync(intent_type, content)
            if reply is None:
                return None
            _save_message(conversation.id, "assistant", reply)
            return (reply, conversation.id)
        except Exception as e:
            logger.warning("Minimal intent execution failed: %s", e)
            return None

    # Build params from intent (parse_intent sets namespace/name, minimal_provider expects params)
    intent = dict(intent)
    if "params" not in intent:
        intent["params"] = {}
    intent["params"].setdefault("namespace", intent.get("namespace") or "default")
    intent["params"].setdefault("name", intent.get("name"))

    # Map list_* intents to resources_list so minimal_provider can handle them
    _LIST_TO_RESOURCE = {
        "list_deployments": "deployment",
        "list_daemonsets": "daemonset",
        "list_statefulsets": "statefulset",
        "list_services": "service",
        "list_configmaps": "configmap",
        "list_secrets": "secret",
    }
    if intent_type in _LIST_TO_RESOURCE:
        intent["type"] = "resources_list"
        intent["params"]["resource_type"] = _LIST_TO_RESOURCE[intent_type]
        intent["params"]["namespace"] = intent.get("namespace") or "default"

    # All other intents: run minimal provider _execute_intent (uses k8s_adapter)
    try:
        reply = asyncio.run(minimal._execute_intent(intent, content, []))
        _save_message(conversation.id, "assistant", reply)
        return (reply, conversation.id)
    except Exception as e:
        logger.error("K8s intent execution failed: %s", e, exc_info=True)
        reply = f"Error executing operation: {str(e)}"
        _save_message(conversation.id, "assistant", reply)
        return (reply, conversation.id)


@ai_chat_api_bp.route('/chat/message', methods=['POST'])
@login_required
def chat_message():
    """
    Send a chat message and get response.

    Request body:
        - content: Message content (required)
        - conversation_id: Optional conversation ID

    Response:
        - conversation_id: Conversation ID
        - message: Assistant response message
    """
    with tracer.start_as_current_span("ai_chat.chat_message") as span:
        try:
            # Set span attributes
            span.set_attribute("user.id", session.get('user_id', 'unknown'))
            span.set_attribute("user.role", session.get('user_role', 'unknown'))

            data = request.get_json(force=True, silent=True) or {}
            content = (data.get("content") or "").strip()

            if not content:
                span.set_attribute("error", "content is required")
                return jsonify({"error": "BadRequest", "message": "content is required"}), 400

            span.set_attribute("message.length", len(content))

            conversation = _get_or_create_conversation(current_user.id, data.get("conversation_id"))

            # Auto-generate title from first message
            if not conversation.title and conversation.messages.count() == 0:
                conversation.title = _auto_generate_title(content)
                db.session.commit()

            # Save user message
            _save_message(conversation.id, "user", content)

            # Recognized intents: run via k8s adapter (lib/k8s) + minimal provider
            config = _get_ai_chat_config()
            k8s_result = run_k8s_intent_sync(content, conversation, config)
            if k8s_result is not None:
                reply, _ = k8s_result
                span.set_attribute("response.source", "k8s_intent")
                return jsonify({
                    "conversation_id": str(conversation.id),
                    "message": {"role": "assistant", "content": reply},
                }), 200

            # LLM or minimal fallback
            try:
                messages = [{"role": "user", "content": content}]
                llm_response = asyncio.run(llm_chat(messages, None))

                if llm_response and llm_response.content:
                    _save_message(conversation.id, "assistant", llm_response.content)
                    span.set_attribute("response.source", "llm")
                    return jsonify({
                        "conversation_id": str(conversation.id),
                        "message": {"role": "assistant", "content": llm_response.content},
                    }), 200

            except Exception as e:
                logger.debug("LLM not available: %s", e)
                span.set_attribute("response.source", "llm_unavailable")

            # Fallback when LLM not available
            reply = "I'm here to help! Either configure an LLM provider for general questions, or use commands like 'list pods in default', 'list namespaces', 'helm list'."
            _save_message(conversation.id, "assistant", reply)
            span.set_attribute("response.source", "fallback")
            return jsonify({
                "conversation_id": str(conversation.id),
                "message": {"role": "assistant", "content": reply},
            }), 200

        except Exception as e:
            logger.error("Chat message error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat chat_message")
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@ai_chat_api_bp.route('/chat/conversations', methods=['GET'])
@login_required
def list_conversations():
    """List user's conversations."""
    with tracer.start_as_current_span("ai_chat.list_conversations") as span:
        try:
            span.set_attribute("user.id", session.get('user_id', 'unknown'))
            conversations = McpConversation.query.filter_by(
                user_id=current_user.id
            ).order_by(McpConversation.updated_at.desc()).all()
            result = []
            for c in conversations:
                try:
                    result.append(c.to_dict())
                except Exception as e:
                    logger.warning(f"Failed to serialize conversation {c.id}: {e}")
                    result.append({
                        'id': c.id,
                        'user_id': c.user_id,
                        'title': c.title or 'New Conversation',
                        'message_count': 0
                    })
            span.set_attribute("conversations.count", len(result))
            return jsonify(result)
        except Exception as e:
            logger.error("List conversations error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat list_conversations")
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@ai_chat_api_bp.route('/chat/conversations/<int:conv_id>', methods=['GET'])
@login_required
def get_conversation(conv_id):
    """Get conversation with messages."""
    with tracer.start_as_current_span("ai_chat.get_conversation") as span:
        try:
            span.set_attribute("user.id", session.get('user_id', 'unknown'))
            span.set_attribute("conversation.id", conv_id)
            conversation = McpConversation.query.filter_by(
                id=conv_id, user_id=current_user.id
            ).first()
            if not conversation:
                span.set_attribute("operation.status", "not_found")
                return jsonify({"error": "NotFound", "message": "Conversation not found"}), 404
            messages = []
            for m in conversation.messages.order_by(McpMessage.created_at.asc()).all():
                try:
                    messages.append(m.to_dict())
                except Exception as e:
                    logger.warning(f"Failed to serialize message {m.id}: {e}")
                    messages.append({
                        'id': m.id,
                        'conversation_id': m.conversation_id,
                        'role': m.role,
                        'content': m.content or '',
                        'created_at': None
                    })
            span.set_attribute("messages.count", len(messages))
            return jsonify({
                'conversation': conversation.to_dict(),
                'messages': messages,
            })
        except Exception as e:
            logger.error("Get conversation error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat get_conversation")
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@ai_chat_api_bp.route('/chat/conversations/<int:conv_id>', methods=['DELETE'])
@login_required
def delete_conversation(conv_id):
    """Delete a conversation."""
    with tracer.start_as_current_span("ai_chat.delete_conversation") as span:
        try:
            span.set_attribute("user.id", session.get('user_id', 'unknown'))
            span.set_attribute("conversation.id", conv_id)
            conversation = McpConversation.query.filter_by(
                id=conv_id, user_id=current_user.id
            ).first()
            if not conversation:
                span.set_attribute("operation.status", "not_found")
                return jsonify({"error": "NotFound", "message": "Conversation not found"}), 404
            db.session.delete(conversation)
            db.session.commit()
            span.set_attribute("operation.status", "success")
            return jsonify({'status': 'deleted'})
        except Exception as e:
            logger.error("Delete conversation error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat delete_conversation")
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@ai_chat_api_bp.route('/provider/info', methods=['GET'])
@login_required
def provider_info():
    """Get current provider information."""
    with tracer.start_as_current_span("ai_chat.provider_info") as span:
        try:
            info = provider_registry.get_provider_info()
            span.set_attribute("provider.type", info.get('provider_type'))
            span.set_attribute("provider.air_gapped", info.get('air_gapped', False))
            return jsonify(info)
        except Exception as e:
            logger.error("Provider info error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat provider_info")
            return jsonify({"error": "InternalError", "message": str(e)}), 500


@ai_chat_api_bp.route('/provider/health', methods=['GET'])
@login_required
def provider_health():
    """Get provider health status."""
    with tracer.start_as_current_span("ai_chat.provider_health") as span:
        try:
            is_healthy = asyncio.run(provider_registry.health_check())
            info = provider_registry.get_provider_info()
            span.set_attribute("provider.healthy", is_healthy)
            return jsonify({
                'healthy': is_healthy,
                'provider': info,
            })
        except Exception as e:
            logger.error("Provider health error: %s", e, exc_info=True)
            ErrorHandler(logger, e, "ai_chat provider_health")
            return jsonify({"error": "InternalError", "message": str(e)}), 500
