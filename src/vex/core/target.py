"""Target — the system under test.

A ``Target`` wraps a :class:`Provider` plus configuration (model name, system
prompt, sampling parameters, tool definitions, etc.). Attacks send probes to
targets; targets execute the probe and return the response.

Targets are intentionally lightweight — they're a configuration object plus
``send(conversation) -> response``. Anything beyond that lives in
:class:`Provider` subclasses.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from vex.core.models import Conversation
from vex.providers.base import Provider


class Target(BaseModel):
    """A target system under test.

    Example
    -------
    >>> from vex.providers.anthropic import AnthropicProvider
    >>> target = Target(
    ...     name="claude-sonnet-prod",
    ...     provider=AnthropicProvider(),
    ...     model="claude-sonnet-4-5-20250929",
    ...     system_prompt="You are a helpful customer support agent...",
    ... )
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    provider: Provider
    model: str
    system_prompt: str | None = None
    temperature: float = 0.0
    max_tokens: int = 1024
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def identifier(self) -> str:
        """Stable identifier used in reports — ``<provider>:<model>``."""
        return f"{self.provider.name}:{self.model}"

    async def send(self, conversation: Conversation) -> tuple[str, dict[str, Any]]:
        """Send a conversation to the target. Returns ``(text, raw_response)``."""
        return await self.provider.complete(
            conversation=conversation,
            model=self.model,
            system_prompt=self.system_prompt,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            extra=self.extra,
        )
