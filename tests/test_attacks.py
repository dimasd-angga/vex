"""Tests for the built-in attack modules."""

from __future__ import annotations

from vex.attacks import BUILTIN_ATTACKS
from vex.attacks.jailbreaks.encoding import CANARY_PHRASE, EncodingJailbreakAttack
from vex.attacks.prompt_injection.unicode_smuggling import (
    UnicodeSmugglingAttack,
)
from vex.core.models import AttackCategory, Role


def test_builtin_attacks_all_instantiable() -> None:
    """Every registered builtin should construct without arguments and yield probes."""
    for cls in BUILTIN_ATTACKS:
        attack = cls()
        probes = list(attack.generate())
        assert probes, f"{cls.__name__} produced zero probes"
        for probe in probes:
            assert probe.attack_id == cls.id
            assert probe.attack_category == cls.category
            assert any(m.role == Role.USER for m in probe.conversation.messages)


def test_encoding_attack_includes_canary() -> None:
    """Every encoding-jailbreak probe should reference the canary phrase in success criteria."""
    for probe in EncodingJailbreakAttack().generate():
        assert CANARY_PHRASE in probe.success_criteria


def test_unicode_smuggling_payload_contains_invisible_chars() -> None:
    """At least one unicode smuggling probe must include non-printable codepoints."""
    found_invisible = False
    for probe in UnicodeSmugglingAttack().generate():
        user_msg = next(m for m in probe.conversation.messages if m.role == Role.USER)
        if any(
            0xE0000 <= ord(c) <= 0xE007F or ord(c) in (0x200D, 0x202E) for c in user_msg.content
        ):
            found_invisible = True
            break
    assert found_invisible, "no smuggling payload contained expected invisible Unicode"


def test_attack_categories_match_taxonomy() -> None:
    """All builtin categories should be members of the AttackCategory enum."""
    for cls in BUILTIN_ATTACKS:
        assert isinstance(cls.category, AttackCategory)
