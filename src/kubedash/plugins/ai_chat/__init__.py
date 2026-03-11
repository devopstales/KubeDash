#!/usr/bin/env python3
"""
AI Chat plugin for KubeDash.

Provides an in-app AI chatbot for natural-language Kubernetes cluster queries and actions.
Cluster operations use lib/k8s (same auth as the rest of KubeDash). No MCP server.

Supports:
- OpenAI-compatible LLM providers (ChatGPT, Ollama, Gemini, Azure)
- Air-gapped mode with minimal chatbot (pattern-based; no external LLM)
- Streaming responses for real-time feedback
"""

from flask import Blueprint, render_template, session
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

##############################################################
## Variables
##############################################################

ai_chat_bp = Blueprint(
    "ai_chat",
    __name__,
    url_prefix="/plugins",
    template_folder="templates",
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Routes
##############################################################

@ai_chat_bp.route("/ai-chat", methods=["GET"])
@login_required
def chat_page():
    """AI Chat main page: in-app AI chatbot UI with message thread and input."""
    logger.debug("AI Chat plugin: serving chat page")
    with tracer.start_as_current_span("ai_chat.page_view") as span:
        span.set_attribute("user.id", session.get('user_id', 'unknown'))
        return render_template("ai-chat.html.j2")

# LLM Provider Registry - initialized on app startup
llm_registry = None


def initialize_llm_provider(app=None):
    """
    Initialize LLM provider based on configuration.

    Called during app initialization to set up the LLM provider.
    If llm_base_url is not configured, uses minimal chatbot mode.

    Args:
        app: Flask app instance (optional)
    """
    global llm_registry

    try:
        from .provider_registry import registry

        # Get AI chat configuration from app config
        config = {}
        if app and hasattr(app, 'config'):
            if app.config.get('ai_chat'):
                config = dict(app.config.get('ai_chat', {}))
            elif hasattr(app.config, 'get') and 'kubedash.ini' in app.config:
                kubedash_ini = app.config['kubedash.ini']
                if hasattr(kubedash_ini, 'get') and 'ai_chat' in kubedash_ini:
                    config = dict(kubedash_ini['ai_chat'])

        # Initialize registry with configuration
        registry.initialize(config)
        llm_registry = registry

        # Log provider info
        info = registry.get_provider_info()
        if app and hasattr(app, 'logger'):
            if info.get('air_gapped'):
                app.logger.info("    AI Chat: Initialized in air-gapped mode (minimal chatbot)")
            else:
                app.logger.info(f"    AI Chat: Initialized with LLM provider: {info.get('model')} @ {info.get('base_url')}")

    except Exception as e:
        if app and hasattr(app, 'logger'):
            app.logger.error(f"    Failed to initialize AI Chat LLM provider: {e}")
        llm_registry = None


def get_llm_provider():
    """
    Get the current LLM provider.

    Returns:
        LLM provider instance or None if not initialized
    """
    if llm_registry is None:
        initialize_llm_provider()
    return llm_registry.provider if llm_registry else None


async def chat(messages, tools=None):
    """
    Send chat message using configured provider.

    Args:
        messages: List of message dicts with 'role' and 'content'
        tools: Optional list of tool definitions

    Returns:
        LLMResponse from provider
    """
    if llm_registry is None:
        initialize_llm_provider()

    if llm_registry is None:
        # Fallback to minimal provider if registry still not initialized
        from .minimal_provider import MinimalChatbotProvider
        provider = MinimalChatbotProvider()
        return await provider.chat(messages, tools)

    return await llm_registry.chat(messages, tools)
