"""OpenAI provider — talks to GPT models via the official SDK.

Installation::

    pip install "vex[openai]"

Environment::

    export OPENAI_API_KEY=sk-...

Also works with OpenAI-compatible endpoints (Groq, Together, OpenRouter, local
vLLM/llama.cpp servers) by passing ``base_url``.
"""

from __future__ import annotations

import os
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from vex.core.models import Conversation, Role
from vex.providers.base import Provider


class OpenAIProvider(Provider):
    """Provider for OpenAI and OpenAI-compatible chat APIs."""

    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        provider_name: str | None = None,
    ) -> None:
        try:
            from openai import AsyncOpenAI
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "OpenAI provider requires the 'openai' package. "
                "Install with: pip install 'vex[openai]'"
            ) from e

        self._client = AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=base_url,
        )
        if provider_name:
            # Allow re-labeling for OpenAI-compatible endpoints.
            self.name = provider_name

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
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        for msg in conversation.messages:
            if msg.role == Role.TOOL:
                continue
            messages.append({"role": msg.role.value, "content": msg.content})

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if extra:
            kwargs.update(extra)

        response = await self._client.chat.completions.create(**kwargs)
        text = response.choices[0].message.content or ""

        return text, response.model_dump(mode="json")

    async def aclose(self) -> None:
        await self._client.close()
