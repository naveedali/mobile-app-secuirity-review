# Security review report structure

## Scope and conclusion

Application, commit/artifact identifier if available, module, variant, SDK range, artifact type, date, requested scope, assumptions, and a bounded conclusion. State when only source or selected XML was reviewed.

## Coverage

| Area | Status: performed / incomplete / not performed | Method, evidence, and limitation |
| --- | --- | --- |

Include tool versions, commands (with sensitive arguments redacted), input paths, failures, and outputs. A scanner's findings are only one input to the assessment.

## Findings

For each finding:

- ID and concise title.
- Severity with rationale; confidence in the observation and status (configuration observed / suspected / reproduced).
- Evidence: file and verified line or XML element path, artifact context, minimal redacted excerpt.
- Impact and required conditions; distinguish hypotheses from verified behavior.
- Reproduction or investigation steps, with synthetic test data where relevant.
- Focused remediation and validation procedure.
- OWASP control group or test link when verified and applicable.

## Open questions and next checks

State what additional artifacts, manual review, or runtime tests would resolve uncertainty. A zero-finding result does not establish security, absence of leaks, or MASVS compliance.
