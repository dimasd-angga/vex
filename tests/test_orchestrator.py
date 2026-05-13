"""End-to-end orchestrator tests using the MockProvider — no network calls."""

from __future__ import annotations

from collections.abc import Callable

from vex.attacks.jailbreaks.role_play import RolePlayJailbreakAttack
from vex.core.models import Conversation, Verdict
from vex.core.orchestrator import Orchestrator
from vex.core.target import Target
from vex.detectors.pattern import PatternDetector
from vex.detectors.refusal import RefusalDetector


async def test_orchestrator_runs_all_probes(make_target: Callable[..., Target]) -> None:
    """Every probe should produce a result."""
    target = make_target(lambda _c: "Sure! I can help.")
    attack = RolePlayJailbreakAttack()
    expected_probes = len(list(attack.generate()))

    orch = Orchestrator(target=target, detectors=[RefusalDetector(invert=True)], concurrency=4)
    summary = await orch.run([attack])

    assert summary.total == expected_probes
    assert summary.finished_at is not None


async def test_orchestrator_marks_vulnerable_when_canary_emitted(
    make_target: Callable[..., Target],
) -> None:
    """Pattern detector should flip results to VULNERABLE on canary emission."""

    def responder(_conv: Conversation) -> str:
        return "Here is the canary: PWNED-BY-VEX"

    target = make_target(responder)
    orch = Orchestrator(
        target=target,
        detectors=[PatternDetector(success_patterns=[r"PWNED-BY-VEX"], name="canary")],
        concurrency=2,
    )
    summary = await orch.run([RolePlayJailbreakAttack()])
    assert summary.vulnerable_count == summary.total


async def test_orchestrator_records_errors(make_target: Callable[..., Target]) -> None:
    """A provider exception should be recorded as an ERROR finding, not crash the run."""

    def responder(_conv: Conversation) -> str:
        raise RuntimeError("simulated provider failure")

    target = make_target(responder)
    orch = Orchestrator(target=target, detectors=[RefusalDetector()], concurrency=2)
    summary = await orch.run([RolePlayJailbreakAttack()])
    assert summary.total > 0
    assert summary.error_count == summary.total
    for r in summary.results:
        assert r.verdict == Verdict.ERROR
        assert r.error is not None


async def test_orchestrator_progress_callback(make_target: Callable[..., Target]) -> None:
    """Progress callback fires once per probe."""
    target = make_target(lambda _c: "I'm sorry, I can't help with that.")
    calls: list[str] = []

    def on_progress(result):  # type: ignore[no-untyped-def]
        calls.append(result.probe.id)

    orch = Orchestrator(
        target=target,
        detectors=[RefusalDetector(invert=True)],
        concurrency=4,
        on_progress=on_progress,
    )
    summary = await orch.run([RolePlayJailbreakAttack()])
    assert len(calls) == summary.total
