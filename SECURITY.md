# Security Policy

## Supported versions

Vex is in early development. Security fixes target the current major release:

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅        |
| 0.1.x   | ❌ (please upgrade — v0.2 fixes known detector calibration issues) |

## Reporting a vulnerability in Vex itself

If you find a security issue **in Vex** (e.g. SSRF in a provider, deserialization in report parsing, credential leakage in logs), report it privately:

- **Preferred**: GitHub Security Advisories — https://github.com/desledishant10/vex/security/advisories/new
- **Alternative**: open a GitHub issue *without sensitive details*, then DM the maintainer for a private channel.

You should expect an acknowledgement within 5 business days and a triage within 14 days.

Please **do not** publicly disclose security issues until they have been fixed and a release has been published.

## Reporting findings *discovered with* Vex

If you use Vex to discover a vulnerability in a third-party product (a deployed AI assistant, an MCP server, a hosted agent), report the finding to **that vendor's** security disclosure channel:

- Anthropic: HackerOne / safety@anthropic.com
- OpenAI: Bugcrowd / security@openai.com
- Google AI / Gemini: https://bughunters.google.com
- Microsoft Copilot: MSRC
- Hugging Face: https://huggingface.co/security
- For self-hosted / smaller vendors: follow their `SECURITY.md` or `security.txt`.

Vex maintainers are not a clearinghouse for third-party vulnerabilities. We can offer informal technical review but cannot coordinate disclosure on your behalf.

## Vex's threat model

Vex itself is a **defensive testing tool** that:

- Sends scripted adversarial inputs to model endpoints
- Reads model responses and writes them to disk (logs, JSON, HTML reports)
- Calls user-configured providers using credentials sourced from environment

Out of scope for our security policy:

- The fact that adversarial prompts *exist* in the source tree. Bundled probes use benign canaries (`PWNED-BY-VEX`, `VEX-EXFIL-CANARY`, `rainbow42`) and are designed for testing, not harm. Treat the source tree like any other security-tooling repo.
- Model-side vulnerabilities surfaced *by* Vex — those belong to the model vendor's security program.

In scope:

- Code execution, credential leakage, SSRF, deserialization, or injection bugs **in Vex's own code**.
- Vulnerabilities in Vex's report rendering (e.g. XSS in HTML reports — they're meant to be opened locally but should still be safe).
- Supply-chain risks in Vex's dependencies.

## Cryptography & secrets

Vex does not perform cryptographic operations beyond what the underlying provider SDKs do. API keys are sourced from environment variables and never written to logs or persisted reports. If you find a path where credentials leak into output, that's a high-severity report.
