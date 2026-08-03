"""A thin Anthropic Messages API client over httpx — no SDK dependency.

Only what Sentinel needs: one structured call that forces a tool result, with
prompt caching on the system block and hard graceful degradation. Any failure —
timeout, network, non-200, malformed response — returns ok=False with zeroed
usage, never raises. The caller then keeps the deterministic verdict and tags the
output "(analiză AI indisponibilă)". The API being down must never break
detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from sentinel.logging_setup import get_logger

log = get_logger(__name__)

_URL = "https://api.anthropic.com/v1/messages"
_VERSION = "2023-06-01"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0


@dataclass
class Result:
    ok: bool
    tool_input: dict[str, Any] | None = None
    usage: Usage = field(default_factory=Usage)
    error: str | None = None


async def call_structured(
    api_key: str, *, model: str, system: str, user: str, tool: dict[str, Any],
    max_tokens: int = 1024, timeout: int = 60,
) -> Result:
    """One call that MUST come back as a `tool` invocation. Returns the tool's
    input dict on success. Never raises."""
    body = {
        "model": model,
        "max_tokens": max_tokens,
        # A list block so prompt caching can pin the (stable) system prompt.
        "system": [{"type": "text", "text": system,
                    "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user}],
        "tools": [tool],
        "tool_choice": {"type": "tool", "name": tool["name"]},
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": _VERSION,
        "content-type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(_URL, json=body, headers=headers)
        if resp.status_code != 200:
            detail = resp.text[:200]
            log.warning("anthropic non-200", extra={"status": resp.status_code, "detail": detail})
            return Result(ok=False, error=f"http {resp.status_code}: {detail}")
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - degrade, never crash the worker
        log.warning("anthropic call failed", extra={"detail": str(exc)})
        return Result(ok=False, error=str(exc)[:200])

    u = data.get("usage", {}) or {}
    usage = Usage(
        input_tokens=int(u.get("input_tokens", 0)),
        output_tokens=int(u.get("output_tokens", 0)),
        cached_tokens=int(u.get("cache_read_input_tokens", 0)),
    )
    tool_input = None
    for block in data.get("content", []) or []:
        if block.get("type") == "tool_use" and block.get("name") == tool["name"]:
            tool_input = block.get("input")
            break
    if tool_input is None:
        return Result(ok=False, usage=usage, error="model did not call the tool")
    return Result(ok=True, tool_input=tool_input, usage=usage)
