# Checker contract — v0.1.0

Python 3.10+; standard library only. The checker reads explicit local XML files and writes a report. It does not execute Gradle, install APKs, contact services, or inspect source code. XML locations are element paths, not fabricated line numbers.

| ID | Observation | Default severity |
| --- | --- | --- |
| MSR001 | Explicit debuggable=true | High for caller-declared release; low otherwise |
| MSR002 | Explicit testOnly=true | Low |
| MSR003 | Explicit manifest usesCleartextTraffic=true without networkSecurityConfig | Medium |
| MSR004 | Explicit exported=true component, including permission-protected components | Low; needs review |
| MSR005 | Explicit cleartextTrafficPermitted=true in base/domain config | Medium |
| MSR006 | Explicit user CA trust outside debug-overrides | Low |

Observations identify configuration, not exploitability. Exported launcher activities are expected and still listed as review candidates. Permission names do not establish effective protection; provider read/write/path permissions and activity-alias inheritance are not evaluated. Omitted exported attributes and platform-dependent defaults are not checked.

Network resources are supplied manually. Each is inspected independently, including resources that might not be used by a release. The checker neither merges nested policies nor determines effective trust/cleartext policy by destination. Debug overrides are excluded from network findings. With networkSecurityConfig present, manifest cleartext is not flagged: Android 7+ ignores that attribute in this case. Older devices and client-specific enforcement still need review.

Unresolved placeholders/boolean resources, unreadable or malformed XML, wrong roots, missing application, and a referenced but unsupplied network resource mark coverage incomplete. DTD/entity declarations are rejected. This is not full Android schema validation. Supply decoded UTF-8 XML without custom entities. APK/AAB binary XML is unsupported.

JSON includes schema/tool version, caller-provided context, inputs, findings, errors, limitations, completion, and counts by severity. Findings include stable rule IDs, severity, confidence, status, path, XML location, evidence, and remediation. Preserve these distinctions when aggregating reports. Do not infer an app-wide score.

## CLI

Repeat `--manifest` and `--network-config` as needed. At least one manifest is required. Choose `--format json|markdown`; Markdown is the default. `--output` writes a file instead of stdout. The output directory must exist. Paths are local and may contain spaces when shell quoted.

`--fail-on none|low|medium|high` controls a severity gate. Default `none` still returns nonzero for incomplete input.

- 0: limited checks completed, configured finding threshold not reached.
- 1: limited checks completed, at least one finding meets/exceeds the threshold.
- 2: incomplete input, report write failure, or invalid CLI usage; takes priority over findings.

An exit code of 0 does not indicate the app is secure. Confidence is high for literal XML observations; confidence in security impact must be established by the reviewer. Evidence can contain app/component identifiers, so review reports before sharing them.
