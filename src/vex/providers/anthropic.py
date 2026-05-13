"""Anthropic provider — talks to Claude via the official SDK.

Installation::

    pip install "vex[anthropic]"

Environment::

    export ANTHROPIC_API_KEY=sk-ant-...
"""

from __future__ import annotations

import os
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from vex.core.models import Conversation, Role
from vex.providers.base import Provider


class AnthropicProvider(Provider):
    """Provider for Anthropic Claude models."""

    name = "anthropic"

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        try:
            from anthropic import AsyncAnthropic
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "Anthropic provider requires the 'anthropic' package. "
                "Install with: pip install 'vex[anthropic]'"
            ) from e

        self._client = AsyncAnthropic(
            api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"),
            base_url=base_url,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def complete(
        self,
        *,
        conversation: Conversation,
        model: str,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        extra: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        # Anthropic separates system prompt from messages. Pull it out of the
        # conversation if present, and skip messages with role=SYSTEM.
        system = system_prompt
        messages: list[dict[str, str]] = []
        for msg in conversation.messages:
            if msg.role == Role.SYSTEM:
                if system is None:
                    system = msg.content
                continue
            if msg.role == Role.TOOL:
                # Tool messages are not modeled in v0.1 — placeholder.
                continue
            messages.append({"role": msg.role.value, "content": msg.content})

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system:
            kwargs["system"] = system
        if extra:
            kwargs.update(extra)

        response = await self._client.messages.create(**kwargs)

        # Concatenate text blocks. Tool use blocks would need richer handling.
        text_parts = []
        for block in response.content:
            if hasattr(block, "text"):
                text_parts.append(block.text)
        text = "".join(text_parts)

        return text, response.model_dump(mode="json")

    async def aclose(self) -> None:
        await self._client.close()
