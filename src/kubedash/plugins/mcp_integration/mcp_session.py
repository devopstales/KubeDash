"""
MCP integration using the official Python MCP SDK (ClientSession + transports).

Transports tried in order: Streamable HTTP (/mcp), SSE (/sse), then raw HTTP POST.
Streamable HTTP does proper session initialization (required by e.g. Kubernetes MCP server).
See: https://github.com/modelcontextprotocol/python-sdk
"""

import asyncio
import concurrent.futures
from contextlib import nullcontext
from typing import Optional

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer

logger = get_logger()
tracer = get_tracer()

# Thread pool for running async MCP code from sync Flask (avoids eventlet/asyncio conflicts)
_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None


def _get_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="mcp")
    return _executor


def _run_anyio(async_main):
    """Run an async callable (no-arg async def) with anyio. Pass the function, not the coroutine – anyio.run() expects a callable it will invoke."""
    try:
        import anyio
        return anyio.run(async_main, backend="asyncio")
    except ImportError:
        return asyncio.run(async_main())


def _run_async(coro):
    """Run an async coroutine from sync code. Prefer _run_anyio for SDK transports (SSE/Streamable HTTP)."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


async def _query_mcp_tool_streamable_async(mcp_url: str, tool_name: str, arguments: dict, timeout: float = 30.0) -> str:
    """
    Connect via Streamable HTTP (POST /mcp with session init), then call tool.
    Use this for servers that require session initialization (e.g. Kubernetes MCP server).
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    logger.info("MCP Streamable HTTP: connecting to %s, tool=%s", mcp_url, tool_name)
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            logger.debug("MCP Streamable HTTP: session initialized, calling tool %s", tool_name)
            result = await session.call_tool(tool_name, arguments or {}, read_timeout_seconds=timeout)
            if result.is_error:
                logger.warning("MCP Streamable HTTP: tool %s returned error: %s", tool_name, result)
                raise RuntimeError(getattr(result, "content", str(result)) or "Tool returned error")
            parts = []
            for item in (result.content or []):
                if getattr(item, "type", None) == "text":
                    parts.append(getattr(item, "text", ""))
            out = "\n".join(parts).strip() if parts else ""
            logger.info("MCP Streamable HTTP: tool %s succeeded, result length=%s", tool_name, len(out))
            return out


async def _query_mcp_tool_sse_async(sse_url: str, tool_name: str, arguments: dict, timeout: float = 30.0) -> str:
    """
    Connect to MCP server via SSE (/sse), initialize session, call tool. Returns result text or raises.
    """
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    logger.info("MCP SSE: connecting to %s, tool=%s", sse_url, tool_name)
    headers = {"Accept": "application/json, text/event-stream"}
    async with sse_client(sse_url, headers=headers, timeout=timeout, sse_read_timeout=timeout) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            logger.debug("MCP SSE: session initialized, calling tool %s with args %s", tool_name, arguments)
            result = await session.call_tool(tool_name, arguments or {}, read_timeout_seconds=timeout)
            if result.is_error:
                logger.warning("MCP SSE: tool %s returned error: %s", tool_name, result)
                raise RuntimeError(getattr(result, "content", str(result)) or "Tool returned error")
            parts = []
            for item in (result.content or []):
                if getattr(item, "type", None) == "text":
                    parts.append(getattr(item, "text", ""))
            out = "\n".join(parts).strip() if parts else ""
            logger.info("MCP SSE: tool %s succeeded, result length=%s", tool_name, len(out))
            return out


def query_mcp_tool(mcp_server_url: str, tool_name: str, arguments: dict, use_sdk: bool = True) -> str:
    """
    Call an MCP tool. Tries Streamable HTTP (/mcp with session init), then SSE (/sse), then raw HTTP.

    Args:
        mcp_server_url: Base URL (e.g. http://127.0.0.1:8082)
        tool_name: Tool name (e.g. pods_list_in_namespace)
        arguments: Tool arguments
        use_sdk: If True, try SDK transports first; if False or both fail, use raw HTTP.

    Returns:
        Tool result as text.
    """
    base = (mcp_server_url or "").rstrip("/")
    if not base:
        raise RuntimeError("MCP server URL is not configured")

    args = arguments or {}
    span_attrs = {
        "mcp.tool": tool_name,
        "mcp.server_url": base,
    }
    with tracer.start_as_current_span(
        "mcp-tool-call",
        attributes=span_attrs,
    ) if tracer else nullcontext():
        # 0. Sync Streamable HTTP (initialize -> notifications/initialized -> tools/call) – no event loop
        try:
            from plugins.mcp_integration.mcp_client import streamable_http_call_tool
            out = streamable_http_call_tool(base, tool_name, args)
            if tracer:
                try:
                    from opentelemetry import trace
                    current = trace.get_current_span()
                    if current.is_recording():
                        current.set_attribute("mcp.transport", "streamable_http_sync")
                except Exception:
                    pass
            return out
        except ImportError:
            pass
        except Exception as e:
            logger.info("MCP sync Streamable HTTP failed, trying SDK/SSE/HTTP: %s", e)

        if use_sdk:
            # 1. Streamable HTTP via SDK (POST /mcp with session init)
            try:
                mcp_url = base + "/mcp"
                logger.debug("MCP: attempting Streamable HTTP (SDK) to %s", mcp_url)

                async def run_streamable():
                    return await _query_mcp_tool_streamable_async(mcp_url, tool_name, args, timeout=30.0)

                out = _get_executor().submit(_run_anyio, run_streamable).result(timeout=35)
                logger.debug("MCP: Streamable HTTP tool call completed for %s", tool_name)
                if tracer:
                    try:
                        from opentelemetry import trace
                        current = trace.get_current_span()
                        if current.is_recording():
                            current.set_attribute("mcp.transport", "streamable_http")
                    except Exception:
                        pass
                return out
            except ImportError as e:
                logger.debug("MCP SDK not available, using HTTP: %s", e)
            except Exception as e:
                logger.error("MCP Streamable HTTP (SDK) failed, trying SSE: %s", e)
                logger.debug("MCP Streamable HTTP failure detail: %s", e, exc_info=True)

            # 2. SSE (/sse) – legacy transport
            try:
                sse_url = base + "/sse"
                logger.debug("MCP: attempting SSE to %s", sse_url)

                async def run_sse():
                    return await _query_mcp_tool_sse_async(sse_url, tool_name, args, timeout=30.0)
                out = _get_executor().submit(_run_anyio, run_sse).result(timeout=35)
                if tracer:
                    try:
                        from opentelemetry import trace
                        current = trace.get_current_span()
                        if current.is_recording():
                            current.set_attribute("mcp.transport", "sse")
                    except Exception:
                        pass
                return out
            except Exception as e:
                logger.error("MCP SSE session failed, falling back to sync Streamable HTTP: %s", e)

        # 4. Retry sync Streamable HTTP (full handshake – never raw tools/call)
        logger.info("MCP: retrying sync Streamable HTTP for tool %s at %s", tool_name, base)
        if tracer:
            try:
                from opentelemetry import trace
                current = trace.get_current_span()
                if current.is_recording():
                    current.set_attribute("mcp.transport", "streamable_http_sync_retry")
            except Exception:
                pass
        from plugins.mcp_integration.mcp_client import streamable_http_call_tool
        return streamable_http_call_tool(base, tool_name, args)
