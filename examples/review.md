# Mobile Security Review

Completion: completed-limited-checks
Build context (caller supplied): release

No findings means no observations from these limited checks; it does not establish app security.

## Inputs

- tests/fixtures/AndroidManifest.xml (manifest)
- tests/fixtures/network_security_config.xml (network-config)

## Findings

### MSR001 — Debugging explicitly enabled

- Severity: high; confidence in observation: high; status: configuration-observed
- File: tests/fixtures/AndroidManifest.xml
- XML location: /manifest/application
- Evidence: android:debuggable=true
- Next step: Disable debugging in the release variant and verify the packaged manifest.

### MSR002 — Test-only application

- Severity: low; confidence in observation: high; status: configuration-observed
- File: tests/fixtures/AndroidManifest.xml
- XML location: /manifest/application
- Evidence: android:testOnly=true
- Next step: Verify this is the intended artifact; produce a non-test release for distribution.

### MSR003 — Manifest explicitly permits cleartext traffic

- Severity: medium; confidence in observation: high; status: configuration-observed
- File: tests/fixtures/AndroidManifest.xml
- XML location: /manifest/application
- Evidence: android:usesCleartextTraffic=true
- Next step: Require HTTPS; review target SDK, supported devices, and actual network clients.

### MSR004 — Exported component requires access review

- Severity: low; confidence in observation: high; status: needs-review
- File: tests/fixtures/AndroidManifest.xml
- XML location: /manifest/application/activity&#91;1&#93;
- Evidence: component=.PublicActivity; exported=true; permission=(none declared)
- Next step: Verify callers, input validation, authentication, and intended public behavior. Exported does not itself mean vulnerable.

### MSR005 — Network configuration explicitly permits cleartext

- Severity: medium; confidence in observation: high; status: configuration-observed
- File: tests/fixtures/network_security_config.xml
- XML location: /network-security-config/base-config&#91;1&#93;
- Evidence: cleartextTrafficPermitted=true
- Next step: Remove unnecessary exceptions and test affected hosts with the actual client.

### MSR006 — User-installed certificate authorities trusted outside debug overrides

- Severity: low; confidence in observation: high; status: configuration-observed
- File: tests/fixtures/network_security_config.xml
- XML location: /network-security-config/base-config&#91;1&#93;/trust-anchors&#91;1&#93;/certificates&#91;1&#93;
- Evidence: certificates src=user
- Next step: Confirm this trust is intentional for the selected variant and threat model.

## Input errors / incomplete coverage

None recorded.

## Limitations

- Static XML observations only; no runtime testing or exploit verification.
- Build context is supplied by the caller, not independently verified.
- Source manifests may differ from merged and packaged release artifacts.
- No Gradle resource/variant resolution, manifest merging, or target/device default evaluation.
- Supplied network configurations are inspected independently; manifest linkage is not verified.
- No source data-flow, secrets, backup contents, authentication, dependencies, or backend assessment.
