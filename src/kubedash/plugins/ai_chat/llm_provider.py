#!/usr/bin/env python3
"""
LLM Provider implementations for AI Chat plugin.

Supports multiple LLM backends:
- OpenAI-compatible APIs (OpenAI, Ollama, LocalAI)
- Google Gemini
- Azure OpenAI
"""

import json
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from lib.helper_functions import get_logger

logger = get_logger()


@dataclass
class LLMResponse:
    """Response from LLM provider."""
    content: str
    tool_calls: Optional[List[Dict]] = None
    model: str = ""
    usage: Optional[Dict] = None

    def to_message(self) -> Dict:
        """Convert response to message format for conversation history."""
        message = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = self.tool_calls
        return message


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def chat(self, messages: List[Dict], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """
        Send chat message and get response.

        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions for function calling

        Returns:
            LLMResponse with content and optional tool calls
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if provider is healthy.

        Returns:
            True if provider is reachable and responding
        """
        pass


class OpenAICompatibleProvider(LLMProvider):
    """
    Provider for OpenAI-compatible APIs.

    Supports:
    - OpenAI ChatGPT
    - Ollama (local LLM)
    - LocalAI
    - LM Studio
    - Any OpenAI-compatible API
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: int = 30,
        max_tokens: int = 1000,
    ):
        """
        Initialize OpenAI-compatible provider.

        Args:
            base_url: API base URL (e.g. https://api.openai.com/v1 or http://localhost:11434/v1)
            api_key: API key (can be empty for local providers like Ollama)
            model: Model name to use
            timeout: Request timeout in seconds
            max_tokens: Maximum response tokens
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        try:
            self.timeout = int(timeout)
        except (TypeError, ValueError):
            self.timeout = 30
        try:
            self.max_tokens = int(max_tokens)
        except (TypeError, ValueError):
            self.max_tokens = 1000
        self._session = None

    async def chat(self, messages: List[Dict], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to OpenAI-compatible API."""
        import aiohttp

        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": self.max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error("LLM API error %s: %s", resp.status, error_text)
                        raise Exception(f"LLM API error: {resp.status} - {error_text}")

                    data = await resp.json()
                    choice = data["choices"][0]
                    message = choice["message"]

                    tool_calls = None
                    if "tool_calls" in message and message["tool_calls"]:
                        tool_calls = message["tool_calls"]

                    return LLMResponse(
                        content=message.get("content", ""),
                        tool_calls=tool_calls,
                        model=data.get("model", self.model),
                        usage=data.get("usage"),
                    )

        except aiohttp.ClientError as e:
            logger.error("LLM connection error: %s", e)
            raise Exception(f"LLM connection failed: {e}")
        except TimeoutError:
            logger.error("LLM request timed out after %ds", self.timeout)
            raise Exception(f"LLM request timed out after {self.timeout} seconds")

    async def health_check(self) -> bool:
        """Check provider health with a simple message."""
        try:
            response = await self.chat([{"role": "user", "content": "Hello"}])
            return bool(response.content)
        except Exception as e:
            logger.debug("LLM health check failed: %s", e)
            return False


class OllamaProvider(OpenAICompatibleProvider):
    """
    Provider for Ollama (local LLM runner).

    Uses OpenAI-compatible API that Ollama provides.
    """

    def __init__(self, base_url: str, model: str, timeout: int = 60):
        """
        Initialize Ollama provider.

        Args:
            base_url: Ollama URL (e.g. http://localhost:11434)
            model: Model name (e.g. llama2, mistral, codellama)
            timeout: Request timeout (default 60s for local LLM)
        """
        super().__init__(
            base_url=base_url,
            api_key="",  # Ollama doesn't require API key
            model=model,
            timeout=timeout,
        )


class GeminiProvider(LLMProvider):
    """
    Provider for Google Gemini API.

    Requires google-generativeai package.
    """

    def __init__(self, api_key: str, model: str = "gemini-pro", timeout: int = 30):
        """
        Initialize Gemini provider.

        Args:
            api_key: Google API key
            model: Gemini model name
            timeout: Request timeout
        """
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._client = None

    def _get_client(self):
        """Get or create Gemini client."""
        if self._client is None:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            except ImportError:
                logger.error("google-generativeai package not installed")
                raise Exception("Google Gemini package not installed. Install with: pip install google-generativeai")
        return self._client

    async def chat(self, messages: List[Dict], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to Gemini API."""
        import asyncio

        client = self._get_client()

        # Convert messages to Gemini format
        gemini_messages = []
        for msg in messages:
            role = msg.get('role', 'user')
            content = msg.get('content', '')

            if role == 'assistant':
                gemini_messages.append({'role': 'model', 'parts': [content]})
            else:
                gemini_messages.append({'role': 'user', 'parts': [content]})

        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.generate_content(
                    gemini_messages,
                    generation_config={
                        'temperature': 0.7,
                        'max_output_tokens': 1000,
                    },
                )
            )

            return LLMResponse(
                content=response.text,
                model=self.model,
            )

        except Exception as e:
            logger.error("Gemini API error: %s", e)
            raise Exception(f"Gemini API error: {e}")

    async def health_check(self) -> bool:
        """Check provider health."""
        try:
            response = await self.chat([{"role": "user", "content": "Hello"}])
            return bool(response.content)
        except Exception:
            return False


class AzureOpenAIProvider(OpenAICompatibleProvider):
    """
    Provider for Azure OpenAI Service.

    Uses OpenAI-compatible API with Azure-specific endpoint format.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str = "2024-02-15-preview",
        timeout: int = 30,
    ):
        """
        Initialize Azure OpenAI provider.

        Args:
            endpoint: Azure OpenAI endpoint (e.g. https://my-resource.openai.azure.com)
            api_key: Azure API key
            deployment: Deployment name
            api_version: API version
            timeout: Request timeout
        """
        # Construct OpenAI-compatible URL
        base_url = f"{endpoint.rstrip('/')}/openai/deployments/{deployment}"

        super().__init__(
            base_url=base_url,
            api_key=api_key,
            model=deployment,
            timeout=timeout,
        )

        # Add API version to query params
        self.api_version = api_version

    async def chat(self, messages: List[Dict], tools: Optional[List[Dict]] = None) -> LLMResponse:
        """Send chat to Azure OpenAI API."""
        import aiohttp

        url = f"{self.base_url}/chat/completions?api-version={self.api_version}"
        headers = {
            "Content-Type": "application/json",
            "api-key": self.api_key,
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": self.max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error("Azure OpenAI error %s: %s", resp.status, error_text)
                        raise Exception(f"Azure OpenAI error: {resp.status} - {error_text}")

                    data = await resp.json()
                    choice = data["choices"][0]
                    message = choice["message"]

                    tool_calls = None
                    if "tool_calls" in message and message["tool_calls"]:
                        tool_calls = message["tool_calls"]

                    return LLMResponse(
                        content=message.get("content", ""),
                        tool_calls=tool_calls,
                        model=data.get("model", self.model),
                        usage=data.get("usage"),
                    )

        except aiohttp.ClientError as e:
            logger.error("Azure OpenAI connection error: %s", e)
            raise Exception(f"Azure OpenAI connection failed: {e}")
        except TimeoutError:
            logger.error("Azure OpenAI request timed out after %ds", self.timeout)
            raise Exception(f"Azure OpenAI request timed out after {self.timeout} seconds")
