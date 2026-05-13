"""Orchestrator — runs attack suites against a target.

Responsibilities:
* Iterate attacks → generate probes → send to target → collect responses
* Run detectors against each response
* Aggregate everything into a :class:`RunSummary`
* Honor concurrency limits and graceful cancellation
* Surface progress events to the UI layer (CLI uses these for live progress)
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Iterable
from datetime import datetime, timezone

from vex.core.attack import Attack
from vex.core.detector import Detector
from vex.core.models import (
    DetectorFinding,
    Probe,
    ProbeResult,
    RunSummary,
    Verdict,
    VerdictMode,
)
from vex.core.target import Target

logger = logging.getLogger(__name__)


ProgressCallback = Callable[[ProbeResult], None]


class Orchestrator:
    """Runs a suite of attacks against a target with bounded concurrency.

    Parameters
    ----------
    target : Target
        System under test.
    detectors : list[Detector]
        Detectors that judge each probe response. All detectors run on every
        probe; aggregate verdict is computed in :class:`ProbeResult`.
    concurrency : int
        Max concurrent probes in flight. Tune to the target's rate limits.
    on_progress : ProgressCallback, optional
        Called once per completed probe — useful for CLI progress bars.
    """

    def __init__(
        self,
        *,
        target: Target,
        detectors: Iterable[Detector],
        concurrency: int = 8,
        on_progress: ProgressCallback | None = None,
        verdict_mode: VerdictMode | None = None,
    ) -> None:
        self.target = target
        self.detectors: list[Detector] = list(detectors)
        self.concurrency = max(1, concurrency)
        self.on_progress = on_progress
        # Default verdict mode: JUDGE_PRIORITY if a judge-style detector is
        # present, else STRICTEST. Explicit override always wins.
        if verdict_mode is not None:
            self.verdict_mode = verdict_mode
        elif any("judge" in getattr(d, "name", "").lower() for d in self.detectors):
            self.verdict_mode = VerdictMode.JUDGE_PRIORITY
        else:
            self.verdict_mode = VerdictMode.STRICTEST

    async def run(self, attacks: Iterable[Attack]) -> RunSummary:
        """Run ``attacks`` against the target. Returns the aggregated summary."""
        summary = RunSummary(target=self.target.identifier)
        sem = asyncio.Semaphore(self.concurrency)

        probes = list(self._collect_probes(attacks))
        if not probes:
            summary.finished_at = datetime.now(timezone.utc)
            return summary

        async def _run_one(probe: Probe) -> ProbeResult:
            async with sem:
                result = await self._execute_probe(probe)
                if self.on_progress is not None:
                    try:
                        self.on_progress(result)
                    except Exception:
                        logger.exception("on_progress callback raised")
                return result

        tasks = [asyncio.create_task(_run_one(p)) for p in probes]
        try:
            for coro in asyncio.as_completed(tasks):
                result = await coro
                summary.results.append(result)
        finally:
            summary.finished_at = datetime.now(timezone.utc)

        return summary

    async def stream(self, attacks: Iterable[Attack]) -> AsyncIterator[ProbeResult]:
        """Yield :class:`ProbeResult` objects as they complete.

        Useful for long runs where the caller wants to react incrementally
        (CLI streaming, web UI live updates).
        """
        sem = asyncio.Semaphore(self.concurrency)
        probes = list(self._collect_probes(attacks))

        async def _run_one(probe: Probe) -> ProbeResult:
            async with sem:
                return await self._execute_probe(probe)

        tasks = [asyncio.create_task(_run_one(p)) for p in probes]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if self.on_progress is not None:
                try:
                    self.on_progress(result)
                except Exception:
                    logger.exception("on_progress callback raised")
            yield result

    # ------------------------------------------------------------------ private

    @staticmethod
    def _collect_probes(attacks: Iterable[Attack]) -> Iterable[Probe]:
        for attack in attacks:
            yield from attack.generate()

    async def _execute_probe(self, probe: Probe) -> ProbeResult:
        result = ProbeResult(
            probe=probe,
            target=self.target.identifier,
            verdict_mode=self.verdict_mode,
        )

        try:
            text, raw = await self.target.send(probe.conversation)
            result.response = text
            result.raw_response = raw
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            result.finished_at = datetime.now(timezone.utc)
            result.duration_ms = _duration_ms(result.started_at, result.finished_at)
            result.findings.append(
                DetectorFinding(
                    detector="provider",
                    verdict=Verdict.ERROR,
                    confidence=1.0,
                    rationale=result.error,
                )
            )
            return result

        # Run all detectors against the response.
        for detector in self.detectors:
            try:
                finding = await detector.evaluate(probe, result.response or "")
            except Exception as e:
                finding = DetectorFinding(
                    detector=getattr(detector, "name", detector.__class__.__name__),
                    verdict=Verdict.ERROR,
                    confidence=0.0,
                    rationale=f"Detector raised: {type(e).__name__}: {e}",
                )
            result.findings.append(finding)

        result.finished_at = datetime.now(timezone.utc)
        result.duration_ms = _duration_ms(result.started_at, result.finished_at)
        return result


def _duration_ms(start: datetime, end: datetime) -> int:
    return int((end - start).total_seconds() * 1000)
