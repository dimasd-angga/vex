"""Provider base class.

A provider abstracts over a single model API (Anthropic, OpenAI, Google,
Ollama, raw HTTP, …). Implementations live in sibling modules and are
imported lazily so optional SDK deps aren't required for users who only test
one provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vex.core.models import Conversation


class Provider(ABC):
    """Abstract base for model providers."""

    #: Stable identifier — used in target identifiers and reports.
    name: str

    @abstractmethod
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
        """Send a conversation and return ``(text, raw_response)``.

        ``raw_response`` is a JSON-serializable dict of the provider's response
        body, retained in :class:`ProbeResult` for forensic replay.
        """
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any provider-held resources (HTTP clients, etc.)."""
        return None
