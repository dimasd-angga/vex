"""Built-in attacks bundled with Vex.

Every concrete attack class is registered in :data:`BUILTIN_ATTACKS` so the
CLI and discovery utilities can enumerate them without runtime imports of
every module. Third-party attacks register themselves via the entry-point
group ``vex.attacks`` (see ``docs/plugin_guide.md``).
"""

from vex.attacks.agent_attacks.indirect_tool_injection import IndirectToolInjectionAttack
from vex.attacks.agent_attacks.system_prompt_leak import SystemPromptLeakAttack
from vex.attacks.jailbreaks.encoding import EncodingJailbreakAttack
from vex.attacks.jailbreaks.role_play import RolePlayJailbreakAttack
from vex.attacks.prompt_injection.unicode_smuggling import UnicodeSmugglingAttack
from vex.core.attack import Attack

BUILTIN_ATTACKS: list[type[Attack]] = [
    RolePlayJailbreakAttack,
    EncodingJailbreakAttack,
    UnicodeSmugglingAttack,
    IndirectToolInjectionAttack,
    SystemPromptLeakAttack,
]

__all__ = [
    "BUILTIN_ATTACKS",
    "EncodingJailbreakAttack",
    "IndirectToolInjectionAttack",
    "RolePlayJailbreakAttack",
    "SystemPromptLeakAttack",
    "UnicodeSmugglingAttack",
]
