"""Ollama provider — talks to local models via Ollama's HTTP API.

Why this matters for a red team tool: many destructive attacks shouldn't be
sent to commercial APIs (cost, ToS, rate limits). Running against a local
Llama / Qwen / Mistral via Ollama is the right way to develop attacks before
escalating to commercial targets.

Installation::

    # Ollama itself: https://ollama.com
    ollama pull llama3.2
    ollama serve

Environment::

    export OLLAMA_HOST=http://localhost:11434
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from vex.core.models import Conversation, Role
from vex.providers.base import Provider


class OllamaProvider(Provider):
    """Provider for local Ollama-hosted models.

    No SDK dependency — uses ``httpx`` directly against Ollama's chat endpoint.
    """

    name = "ollama"

    def __init__(self, base_url: str | None = None, timeout: float = 120.0) -> None:
        self._base_url = (
            base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        ).rstrip("/")
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

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

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if extra:
            payload.update(extra)

        response = await self._client.post("/api/chat", json=payload)
        response.raise_for_status()
        body = response.json()
        text = body.get("message", {}).get("content", "")
        return text, body

    async def aclose(self) -> None:
        await self._client.aclose()
