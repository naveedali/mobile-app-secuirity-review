# Android review areas

Select relevant areas based on the app's data and threat model. For each area, record actual evidence and coverage rather than ticking a compliance box.

| Area | Inspect | Follow-up evidence |
| --- | --- | --- |
| Release configuration | Merged manifest, debuggability, test flags, variant-specific resources | Compare with packaged release manifest |
| IPC and links | Exported components, permissions, URI grants, PendingIntent mutability, host/path validation | Test intended/unauthorized callers and malformed links in an authorized test app |
| Data storage | Sensitive values in preferences, databases, external storage, cache; backup/data extraction rules | Use synthetic markers, inspect accessible test storage, check restore behavior |
| Logs and telemetry | Log calls, HTTP interceptors, crash/analytics payloads, identifiers | Trace actual values; capture synthetic-data flows without printing real secrets |
| Network | Cleartext exceptions, trust managers, hostname verification, WebView TLS handlers | Verify the actual client's enforcement; declarations alone are insufficient |
| Authentication | Session lifecycle, account switching, logout cleanup, biometric fallback | Reproduce with test accounts; server authorization needs separate evidence |
| WebView | JavaScript bridges, untrusted content, file/content access, URL loading | Trace attacker-controlled input and exposed bridge methods |
| Cryptography | Key generation/storage, hardcoded secret keys, algorithm/mode/nonce use | Inspect key lifecycle; public API identifiers are not automatically secrets |
| Dependencies | Resolved versions and third-party SDK behavior | Confirm vulnerable code paths and version advisories; avoid name-only conclusions |
| UI privacy | Clipboard, notifications, screenshots/recents, accessibility exposure | Test selected sensitive flows and product requirements |

## Avoid misleading conclusions

- Internal sandbox storage is not automatically a vulnerability merely because it is unencrypted. Assess sensitivity, threat model, backup policy, and access conditions.
- No certificate pinning, root detection, or obfuscation is not by itself a vulnerability.
- Permissions and exported components can be intentional. Establish impact and reachable behavior.
- Debug variants may intentionally trust developer CAs or log extra information; determine release behavior.
- Regex matches cannot establish data flow, effective TLS behavior, or server authorization.
- Only test public endpoints, devices, or accounts within the user's authorized assessment scope.

## Primary references

Consult current guidance when making platform-specific claims. Some older MASTG tests are deprecated; use the current index.

- Android security risks: https://developer.android.com/privacy-and-security/risks
- Network configuration and API-dependent defaults: https://developer.android.com/privacy-and-security/security-config
- Log disclosure: https://developer.android.com/privacy-and-security/risks/log-info-disclosure
- Deep links: https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
- OWASP MASTG atomic tests: https://mas.owasp.org/MASTG/tests/
- OWASP MASVS usage: https://mas.owasp.org/MASVS/03-Using_the_MASVS/
