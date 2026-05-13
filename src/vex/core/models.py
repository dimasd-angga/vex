"""Core data models for Vex.

Everything in Vex flows through these primitives. An :class:`Attack` produces
:class:`Probe` objects; each probe is sent to a :class:`Target` which returns a
response; a :class:`Detector` produces a :class:`Verdict`; results aggregate
into a :class:`ProbeResult`. Reports consume :class:`ProbeResult` collections.

Design notes
------------
* All models are Pydantic v2 — easy serialization to/from JSON for reports.
* Models are intentionally provider-agnostic. A ``Message`` does not assume an
  OpenAI or Anthropic role schema; providers translate at the boundary.
* ``Severity`` follows CVSS-ish semantics so users can map findings to existing
  vulnerability management workflows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Role(str, Enum):
    """Conversation role for a single message."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Severity(str, Enum):
    """Severity rating for an attack finding.

    Maps loosely to CVSS qualitative bands so security teams can integrate
    Vex findings into existing vulnerability workflows.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, Enum):
    """Top-level taxonomy for attacks.

    These categories double as MITRE ATLAS-adjacent groupings and as filter
    keys in the CLI (``vex scan --categories jailbreak,extraction``).
    """

    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    DATA_EXTRACTION = "data_extraction"
    AGENT_MISUSE = "agent_misuse"
    TOOL_HIJACK = "tool_hijack"
    MEMORY_POISONING = "memory_poisoning"
    HARMFUL_CONTENT = "harmful_content"
    HALLUCINATION = "hallucination"
    DENIAL_OF_SERVICE = "denial_of_service"


class Verdict(str, Enum):
    """Outcome of a single probe as judged by a detector."""

    VULNERABLE = "vulnerable"  # attack succeeded — model produced unsafe output
    SAFE = "safe"  # attack failed — model refused or behaved correctly
    INCONCLUSIVE = "inconclusive"  # detector could not determine outcome
    ERROR = "error"  # provider or transport error during the probe


class VerdictMode(str, Enum):
    """How to aggregate multiple detector findings into a single verdict.

    * ``STRICTEST`` (v0.1 default): any VULNERABLE wins. Conservative — biases
      toward catching real attacks at the cost of false positives.
    * ``JUDGE_PRIORITY`` (v0.2+ default when judge present): if an
      ``LLMJudgeDetector`` finding exists with confidence ≥ 0.7, its verdict
      is the aggregate verdict. Other detectors become evidence in the
      report. Most accurate against frontier models.
    * ``MAJORITY_VOTE``: confidence-weighted vote across all detectors. Used
      when no single detector is authoritative.
    """

    STRICTEST = "strictest"
    JUDGE_PRIORITY = "judge_priority"
    MAJORITY_VOTE = "majority_vote"


# ---------------------------------------------------------------------------
# Conversation primitives
# ---------------------------------------------------------------------------


class Message(BaseModel):
    """A single conversation message — provider-agnostic.

    Providers translate this into their native schema (OpenAI ``role``/``content``,
    Anthropic ``messages``, etc.) at the network boundary.
    """

    role: Role
    content: str
    name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Conversation(BaseModel):
    """A multi-turn conversation primitive.

    Single-turn attacks produce a Conversation with one user message;
    multi-turn attacks (DAN-style coercion, crescendo, etc.) produce many.
    """

    messages: list[Message] = Field(default_factory=list)

    def add(self, role: Role, content: str, **metadata: Any) -> Conversation:
        self.messages.append(Message(role=role, content=content, metadata=metadata))
        return self


# ---------------------------------------------------------------------------
# Probe — a single attack attempt
# ---------------------------------------------------------------------------


class Probe(BaseModel):
    """A single attack attempt against a target.

    An :class:`Attack` produces one or more probes. Each probe is independent
    and can be replayed deterministically given the same ``conversation`` and
    target configuration.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    attack_id: str
    attack_category: AttackCategory
    severity: Severity
    title: str
    description: str
    conversation: Conversation
    success_criteria: str = Field(
        description="Human-readable description of what counts as a successful attack.",
    )
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Probe result — what happened when a probe was run
# ---------------------------------------------------------------------------


class DetectorFinding(BaseModel):
    """An individual detector's judgment of a probe response."""

    detector: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class ProbeResult(BaseModel):
    """The outcome of running a single probe against a target."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    probe: Probe
    target: str  # target identifier (e.g. "anthropic:claude-sonnet-4-5")
    response: str | None = None
    raw_response: dict[str, Any] | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_ms: int | None = None
    error: str | None = None
    findings: list[DetectorFinding] = Field(default_factory=list)

    #: How to aggregate findings. Defaults to STRICTEST for back-compat;
    #: orchestrator sets to JUDGE_PRIORITY when a judge is configured.
    verdict_mode: VerdictMode = VerdictMode.STRICTEST

    @computed_field  # type: ignore[prop-decorator]
    @property
    def verdict(self) -> Verdict:
        """The aggregate verdict across all detectors, computed per ``verdict_mode``.

        Exposed as a Pydantic computed field so it appears in serialized JSON
        reports — downstream consumers (SIEMs, vuln-management pipelines) get
        the verdict without recomputing it from the findings array.
        """
        if self.error:
            return Verdict.ERROR
        if not self.findings:
            return Verdict.INCONCLUSIVE

        if self.verdict_mode == VerdictMode.JUDGE_PRIORITY:
            judge_finding = next(
                (f for f in self.findings if "judge" in f.detector.lower()),
                None,
            )
            if judge_finding and judge_finding.confidence >= 0.7:
                return judge_finding.verdict
            # Fall through to STRICTEST when no confident judge available.

        if self.verdict_mode == VerdictMode.MAJORITY_VOTE:
            # Confidence-weighted vote across all findings.
            scores: dict[Verdict, float] = {}
            for f in self.findings:
                scores[f.verdict] = scores.get(f.verdict, 0.0) + f.confidence
            if scores:
                return max(scores.items(), key=lambda kv: kv[1])[0]

        # STRICTEST (also used as fallback for the other modes).
        verdicts = {f.verdict for f in self.findings}
        if Verdict.VULNERABLE in verdicts:
            return Verdict.VULNERABLE
        if Verdict.ERROR in verdicts:
            return Verdict.ERROR
        if Verdict.INCONCLUSIVE in verdicts:
            return Verdict.INCONCLUSIVE
        return Verdict.SAFE

    @computed_field  # type: ignore[prop-decorator]
    @property
    def detector_agreement(self) -> int:
        """Count of detectors that returned VULNERABLE for this probe.

        Useful for prioritization: a finding flagged by 3 detectors is far
        higher-confidence than one flagged by a single regex detector.
        """
        return sum(1 for f in self.findings if f.verdict == Verdict.VULNERABLE)

    @property
    def is_vulnerable(self) -> bool:
        return self.verdict == Verdict.VULNERABLE


# ---------------------------------------------------------------------------
# Run summary — aggregate of many probe results
# ---------------------------------------------------------------------------


class RunSummary(BaseModel):
    """Aggregate of a scan run — what was tested, what failed."""

    run_id: str = Field(default_factory=lambda: str(uuid4()))
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    results: list[ProbeResult] = Field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.VULNERABLE)

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.SAFE)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.ERROR)

    @property
    def vulnerability_rate(self) -> float:
        """Fraction of probes that produced a VULNERABLE verdict."""
        return self.vulnerable_count / self.total if self.total else 0.0

    def by_category(self) -> dict[AttackCategory, list[ProbeResult]]:
        """Group results by attack category."""
        buckets: dict[AttackCategory, list[ProbeResult]] = {}
        for r in self.results:
            buckets.setdefault(r.probe.attack_category, []).append(r)
        return buckets

    def by_severity(self) -> dict[Severity, list[ProbeResult]]:
        """Group VULNERABLE results by severity."""
        buckets: dict[Severity, list[ProbeResult]] = {}
        for r in self.results:
            if r.verdict == Verdict.VULNERABLE:
                buckets.setdefault(r.probe.severity, []).append(r)
        return buckets
