# Contributing to Vex

Thanks for considering a contribution. Vex is a small, opinionated project; this guide explains how to get a useful PR merged with minimum friction.

## Where to start

- **Bug reports**: open an issue with a minimal reproduction. If you have an HTML/JSON report from a failed scan, attach it.
- **New attacks**: open an issue first so we can confirm the attack fits the agent-first scope. Then PR per the recipe in [`docs/plugin_guide.md`](docs/plugin_guide.md).
- **New providers**: similar — open an issue first to confirm scope and avoid duplicate work.
- **Detector improvements**: especially welcome if backed by real-model response examples. The v0.2 calibration release was driven entirely by captured baseline responses; that pattern scales well.

Good first issues are labeled [`good first issue`](https://github.com/desledishant10/vex/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). The current shortlist is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Development setup

```bash
git clone https://github.com/desledishant10/vex.git
cd vex
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,all]"
```

## Pre-PR checklist

The CI pipeline runs all four of these on every push. Run them locally first to avoid red builds:

```bash
ruff check src tests           # lint
ruff format --check src tests  # formatting
mypy src                       # type-check (strict)
pytest                         # tests
```

Or all at once:

```bash
ruff check src tests && ruff format --check src tests && mypy src && pytest
```

## PR style

- One logical change per PR. If you find an adjacent bug, file a separate issue or open a follow-up PR.
- New behavior gets a test. If the behavior is detector calibration, the test should use an actual captured response string (see `tests/test_calibration.py` for the pattern).
- New public API surface gets a docstring with at least an `Example` section.
- New CLI surface gets a line in the README quickstart.
- Add a `CHANGELOG.md` entry under `## [Unreleased]`.

## Adding an attack

The minimum viable attack is ~30 lines. See the [plugin guide](docs/plugin_guide.md) for the recipe. Some specific guidance for built-in attacks:

- **Use a canary, not actual harmful content.** Bundled attacks should not produce harmful output if successful. The default canaries (`PWNED-BY-VEX`, `VEX-EXFIL-CANARY`, `rainbow42`) are designed so successful attacks produce a benign signal a detector can find.
- **Document the threat model.** Each attack module should have a docstring explaining the assumed attacker capability, the model behavior being tested, and references to prior art.
- **Register in `src/vex/attacks/__init__.py`** so `vex list` finds it.

## Adding a detector

Detectors must be fast (target <100ms per probe) and side-effect-free (LLM-judge is the exception — explicit). The base contract is one method: `async def evaluate(self, probe, response) -> DetectorFinding`.

Calibration evidence is welcome. If you're adjusting refusal patterns or context-classification rules, link the responses that motivated the change.

## Adding a provider

A new provider is ~50 lines. Gate any SDK imports behind a try/except so users without the optional dependency see a helpful error. Add an extra to `pyproject.toml` under `[project.optional-dependencies]`. Add the provider to `vex.cli._build_provider`. Tests should use the SDK's mock interface when one exists.

## Responsible disclosure

If you find a real-world vulnerability in a deployed AI product using Vex:

1. **Do not** disclose it publicly first.
2. Report it through the vendor's bug bounty / security disclosure program (Anthropic, OpenAI, Google, Microsoft, etc.).
3. Once the vendor has acknowledged and fixed (or formally declined), you're welcome to add a canary-payload version of the attack to Vex via PR.

See [`SECURITY.md`](SECURITY.md) for Vex's own vulnerability disclosure policy.

## Code of conduct

Be excellent to each other. We follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) implicitly; if a written CoC becomes necessary, we'll adopt it formally.
