"""Attack base class.

An ``Attack`` generates one or more :class:`Probe` objects. Subclasses
typically override :meth:`Attack.generate` and may declare per-class metadata
(``id``, ``category``, ``severity``).

Attacks are deliberately stateless — the same Attack instance generates the
same probes when invoked twice with the same seed. This makes runs
reproducible, which matters for both regression testing of model safety and
for credible vulnerability disclosure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from vex.core.models import AttackCategory, Probe, Severity


class Attack(ABC):
    """Base class for all attacks.

    Subclasses must define class-level metadata and implement :meth:`generate`.

    Example
    -------
    >>> class MyAttack(Attack):
    ...     id = "vex.example.my_attack"
    ...     category = AttackCategory.JAILBREAK
    ...     severity = Severity.MEDIUM
    ...     name = "Example attack"
    ...     description = "Demonstrates the Attack contract."
    ...
    ...     def generate(self) -> Iterator[Probe]:
    ...         yield self._make_probe(
    ...             title="hello world",
    ...             user_input="What is 2+2?",
    ...             success_criteria="Model says anything other than 4.",
    ...         )
    """

    # Subclasses override these.
    id: ClassVar[str]
    category: ClassVar[AttackCategory]
    severity: ClassVar[Severity] = Severity.MEDIUM
    name: ClassVar[str]
    description: ClassVar[str] = ""
    tags: ClassVar[list[str]] = []

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Enforce required class attributes when a concrete Attack is declared.
        # Abstract intermediates (e.g. mixins) may omit ``id``/``category``.
        if not getattr(cls, "__abstractmethods__", set()):
            for required in ("id", "category", "name"):
                if not getattr(cls, required, None):
                    raise TypeError(
                        f"{cls.__name__} must define class attribute '{required}'",
                    )

    @abstractmethod
    def generate(self) -> Iterator[Probe]:
        """Yield probes for this attack.

        Subclasses use :meth:`_make_probe` for convenience or instantiate
        :class:`Probe` directly when more control is needed.
        """
        raise NotImplementedError

    def _make_probe(
        self,
        *,
        title: str,
        user_input: str,
        success_criteria: str,
        description: str = "",
        system_prompt: str | None = None,
        tags: list[str] | None = None,
        **metadata: object,
    ) -> Probe:
        """Convenience constructor for single-turn user probes."""
        from vex.core.models import Conversation, Role

        convo = Conversation()
        if system_prompt:
            convo.add(Role.SYSTEM, system_prompt)
        convo.add(Role.USER, user_input)

        return Probe(
            attack_id=self.id,
            attack_category=self.category,
            severity=self.severity,
            title=title,
            description=description or self.description,
            conversation=convo,
            success_criteria=success_criteria,
            tags=tags or list(self.tags),
            metadata=dict(metadata),
        )
