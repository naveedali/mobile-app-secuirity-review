# Contributing

Start with a reproducible problem and a bounded detection claim. New checks need synthetic positive and negative fixtures, documented false-positive conditions, stable IDs, and meaningful regression tests. Never submit production tokens, private app artifacts, or personal data.

Run `python3 -m unittest discover -s tests -v` and `git diff --check` before submitting. Python 3.10+ is supported; there are no runtime dependencies. Keep the skill self-contained under `skills/mobile-security-review/`.

Distinguish configuration observations from verified vulnerabilities. Avoid adding rules that call every exported component, public API key, or missing defense-in-depth mechanism vulnerable. Platform-specific assertions should link to current Android or OWASP documentation.

For potential security defects in this tool, see SECURITY.md.
