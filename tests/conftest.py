"""Shared test fixtures — most importantly, a deterministic mock provider."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from vex.core.models import Conversation
from vex.core.target import Target
from vex.providers.base import Provider


class MockProvider(Provider):
    """Provider that returns scripted responses — no network calls.

    Pass a ``responder`` callable that takes the conversation and returns
    the response text. If no responder is given, all responses are empty.
    """

    name = "mock"

    def __init__(self, responder: Callable[[Conversation], str] | None = None) -> None:
        self._responder = responder or (lambda _conv: "")
        self.calls: list[Conversation] = []

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
        self.calls.append(conversation)
        text = self._responder(conversation)
        return text, {"mock": True, "text": text}


@pytest.fixture
def mock_provider() -> MockProvider:
    return MockProvider()


@pytest.fixture
def make_target() -> Callable[..., Target]:
    """Factory fixture for building :class:`Target` instances around a MockProvider."""

    def _make(responder: Callable[[Conversation], str] | None = None) -> Target:
        return Target(
            name="mock-target",
            provider=MockProvider(responder=responder),
            model="mock-model",
        )

    return _make
