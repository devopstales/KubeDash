#!/usr/bin/env python3
"""
LLM Provider Registry for AI Chat plugin.

Manages provider selection, initialization, and automatic fallback to minimal provider.
"""

from typing import Optional, Dict, Any
from lib.helper_functions import get_logger

from .llm_provider import (
    LLMProvider,
    LLMResponse,
    OpenAICompatibleProvider,
    OllamaProvider,
    GeminiProvider,
    AzureOpenAIProvider,
)
from .minimal_provider import MinimalChatbotProvider

logger = get_logger()


class ProviderRegistry:
    """
    Registry for LLM providers with automatic fallback.

    Manages:
    - Provider initialization based on configuration
    - Automatic fallback to minimal provider when LLM is unavailable
    - Air-gapped mode detection
    - Provider health monitoring
    """

    def __init__(self):
        """Initialize provider registry."""
        self.provider: Optional[LLMProvider] = None
        self.minimal_provider: Optional[MinimalChatbotProvider] = None
        self.config: Dict[str, Any] = {}
        self.air_gapped: bool = False

    def initialize(self, config: Dict[str, Any]):
        """
        Initialize provider based on configuration.

        Args:
            config: Configuration dictionary with:
                - llm_provider: Provider type (openai, ollama, gemini, azure)
                - llm_base_url: LLM API base URL
                - llm_api_key: API key (optional for some providers)
                - llm_model: Model name
                - llm_timeout: Request timeout
                - llm_max_tokens: Maximum response tokens
        """
        self.config = config.copy()

        # Initialize minimal provider (always available as fallback; uses lib/k8s via k8s_adapter)
        self.minimal_provider = MinimalChatbotProvider()

        # Check if LLM is configured
        llm_base_url = config.get('llm_base_url', '').strip()

        if not llm_base_url:
            # No LLM configured - use air-gapped mode
            self.air_gapped = True
            self.provider = None
            logger.info("AI Chat: No LLM configured, using air-gapped mode (minimal chatbot)")
            return

        # Initialize LLM provider based on type (coerce numbers from ini strings)
        provider_type = config.get('llm_provider', 'openai').lower()
        llm_api_key = config.get('llm_api_key', '').strip()
        llm_model = config.get('llm_model', '')
        try:
            llm_timeout = int(config.get('llm_timeout', 30))
        except (TypeError, ValueError):
            llm_timeout = 30
        try:
            llm_max_tokens = int(config.get('llm_max_tokens', 1000))
        except (TypeError, ValueError):
            llm_max_tokens = 1000

        try:
            if provider_type == 'ollama':
                self.provider = OllamaProvider(
                    base_url=llm_base_url,
                    model=llm_model or 'llama2',
                    timeout=llm_timeout,
                )
            elif provider_type == 'gemini':
                if not llm_api_key:
                    logger.warning("Gemini API key not provided, using minimal provider")
                    self.air_gapped = True
                    return
                self.provider = GeminiProvider(
                    api_key=llm_api_key,
                    model=llm_model or 'gemini-pro',
                    timeout=llm_timeout,
                )
            elif provider_type == 'azure':
                if not llm_api_key:
                    logger.warning("Azure API key not provided, using minimal provider")
                    self.air_gapped = True
                    return
                self.provider = AzureOpenAIProvider(
                    endpoint=llm_base_url,
                    api_key=llm_api_key,
                    deployment=llm_model,
                    timeout=llm_timeout,
                )
            else:  # openai or default
                self.provider = OpenAICompatibleProvider(
                    base_url=llm_base_url,
                    api_key=llm_api_key,
                    model=llm_model or 'gpt-3.5-turbo',
                    timeout=llm_timeout,
                    max_tokens=llm_max_tokens,
                )

            self.air_gapped = False

        except Exception as e:
            logger.error("Failed to initialize LLM provider: %s", e)
            self.air_gapped = True
            self.provider = None

    async def chat(self, messages: list, tools: list = None) -> LLMResponse:
        """
        Send chat using current provider.

        Args:
            messages: List of message dicts
            tools: Optional list of tool definitions

        Returns:
            LLMResponse from provider
        """
        # Try LLM provider first (if not in air-gapped mode)
        if self.provider and not self.air_gapped:
            try:
                response = await self.provider.chat(messages, tools)
                return response
            except Exception as e:
                logger.warning("LLM provider failed, falling back to minimal: %s", e)
                self.air_gapped = True

        # Fallback to minimal provider
        if self.minimal_provider:
            try:
                response = await self.minimal_provider.chat(messages, tools)
                return response
            except Exception as e:
                logger.error("Minimal provider also failed: %s", e)

        raise Exception("No chat provider available")

    def get_provider_info(self) -> Dict[str, Any]:
        """
        Get current provider information.

        Returns:
            Dictionary with provider details
        """
        if self.air_gapped or not self.provider:
            return {
                'air_gapped': True,
                'provider_type': 'minimal',
                'model': 'N/A (pattern-based)',
                'base_url': 'N/A',
                'cluster_operations': True,  # always via lib/k8s
            }

        provider_type = self.config.get('llm_provider', 'openai')
        return {
            'air_gapped': False,
            'provider_type': provider_type,
            'model': self.config.get('llm_model', 'default'),
            'base_url': self.config.get('llm_base_url', 'N/A'),
            'cluster_operations': True,  # always via lib/k8s
        }

    async def health_check(self) -> bool:
        """
        Check provider health.

        Returns:
            True if current provider is healthy
        """
        if self.air_gapped or not self.provider:
            return True

        try:
            return await self.provider.health_check()
        except Exception:
            return False


# Global registry instance
registry = ProviderRegistry()


def get_provider_info() -> Dict[str, Any]:
    """Get current provider information (convenience function)."""
    return registry.get_provider_info()
