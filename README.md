# Mobile Security Review Skill

An Android security review skill with reproducible XML checks, contextual review guidance, and reports that make coverage explicit.

**Status: v0.1.0 · Android first · Python standard library · MIT**

Use it to investigate release configuration and potential sensitive-data exposure. The skill helps an agent inspect source and explain evidence; the bundled CLI inspects a limited set of manifest/network XML settings. Neither establishes that an app is secure.

## Try it in one minute

From this repository, with Python 3.10+:

```sh
python3 skills/mobile-security-review/scripts/review_android.py \
  --manifest tests/fixtures/AndroidManifest.xml \
  --network-config tests/fixtures/network_security_config.xml \
  --build-context release
```

The fixtures deliberately contain risky configuration. Expect six observations, including one exported component requiring contextual review. See the generated [example report](examples/review.md).

## Use it as a skill

The portable skill is the entire `skills/mobile-security-review/` directory. To make it available in an Android repository, copy that directory to:

```text
<your-android-repository>/.agents/skills/mobile-security-review/
```

For user-wide Codex discovery, use `~/.agents/skills/mobile-security-review/`. These paths follow the [official OpenAI skill documentation](https://learn.chatgpt.com/docs/build-skills). Installing the skill is separate from cloning this repository; this repository does not modify your agent configuration.

Example request:

```text
Use $mobile-security-review to review this Android app's release configuration
and handling of sensitive data. Inspect the available source and merged release
manifest. Report evidence, impact, confidence, remediation, and coverage gaps.
```

The skill distinguishes user requests from instructions embedded in inspected repositories, documents, and tool output. It preserves the scope of authorized testing and redacts sensitive evidence.

## Review a real app's XML

Supply an existing decoded, plain-text manifest and the resolved network resource for the selected variant. Prefer merged release artifacts over source declarations. Build paths vary by Android Gradle Plugin and module; the CLI does not build projects or discover artifacts automatically.

```sh
python3 skills/mobile-security-review/scripts/review_android.py \
  --manifest /path/to/merged/AndroidManifest.xml \
  --network-config /path/to/resolved/network_security_config.xml \
  --build-context release \
  --format json \
  --output review.json \
  --fail-on high
```

Omit `--network-config` when the manifest does not declare one. Use `--build-context source` for source XML, or leave the default `unknown`. The caller's context assertion is recorded, not verified. APK/AAB binary XML needs separate decoding using trusted tooling; it is not accepted directly.

| Rule | What the CLI observes |
| --- | --- |
| MSR001 | Explicit debugging enabled; high severity only for caller-declared release |
| MSR002 | Explicit test-only application |
| MSR003 | Explicit manifest cleartext opt-in without a network configuration reference |
| MSR004 | Explicitly exported component; review candidate, including permission-protected components |
| MSR005 | Explicit cleartext opt-in in network base/domain configuration |
| MSR006 | User CA trust outside debug overrides |

Multiple manifests/resources can be supplied by repeating arguments. They are inspected independently. Effective resource selection, inherited policies, platform defaults, permission strength, and runtime behavior require contextual assessment. Full details: [checker contract](skills/mobile-security-review/references/checker.md).

## Reports and CI gates

Reports include rule IDs, severity, confidence in the literal observation, status, input paths, XML element locations, evidence, next steps, errors, and limitations. Markdown and JSON are supported. Reports may include private component names and local paths; review before publishing.

| Exit | Meaning |
| --- | --- |
| 0 | Limited checks completed; finding threshold not reached |
| 1 | At least one finding reached the configured threshold |
| 2 | Incomplete input, invalid usage, or report write failure |

The default threshold is `none`. Missing resources, unresolved placeholders, and malformed inputs return 2 rather than silently producing a clean result. A zero exit code is not a security approval.

The included GitHub workflow tests the tool on Python 3.10 and 3.13 and generates a fixture report. To gate your app, run the real-app command above after your trusted build/decoding process produces its selected artifacts.

## What the skill adds

The [review guidance](skills/mobile-security-review/references/android-review.md) covers sensitive logging, storage/backup, IPC, links, authentication, WebView, TLS, cryptography, dependencies, and UI privacy. These are agent-assisted review areas, not features implemented by the XML CLI. Use the [report structure](skills/mobile-security-review/references/report-template.md) to capture performed, incomplete, and unperformed work.

This version does not automate source data-flow analysis, secret detection, dependency vulnerability scanning, runtime leak capture, iOS assessment, or backend testing. A configuration observation is not proof of an exploitable vulnerability. No MASVS compliance or certification is claimed.

## Development

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

No runtime dependencies or API keys are required. Fixtures are synthetic and are not an installable Android app. See [contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), and the [MIT license](LICENSE).

## Roadmap

- Add synthetic-token leak tests for Logcat and accessible test-build storage.
- Add structured source checks for narrowly defined logging patterns, with safe counterexamples.
- Add release-to-release configuration differences and SARIF output.
- Add optional local scanner adapters while preserving tool provenance and coverage.
- Package the validated workflow for plugin distribution.

## Foundations

Review areas draw on [Android security guidance](https://developer.android.com/privacy-and-security/risks), [network security configuration](https://developer.android.com/privacy-and-security/security-config), and [OWASP MASTG](https://mas.owasp.org/MASTG/tests/). This project is independent of Google, OpenAI, and OWASP.
