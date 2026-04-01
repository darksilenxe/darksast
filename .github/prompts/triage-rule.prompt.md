---
name: "Triage Scanner Rule"
description: "Diagnose a react-scanner missed finding or false positive, validate on the tests target, and apply the smallest justified rule or test fix."
argument-hint: "Rule id or file, sample path, missed finding or false positive, expected behavior, and any suspected query issue"
agent: "React Scanner Assistant"
---
Triage exactly one scanner rule behavior issue for this repository based on this request:

{{input}}

Use these repo instructions as the source of truth:

- [Rule Authoring Guidelines](../instructions/rule-authoring.instructions.md)
- [React Scanner Rule Authoring](../skills/react-scanner-rule-authoring/SKILL.md)

Required workflow:

1. Identify whether the issue is a missed finding, false positive, invalid query shape, wrong framework labeling, or missing test coverage.
2. Inspect the most similar existing rules under [rules](../../rules) and the relevant sample or coverage file under [tests](../../tests).
3. Make the smallest necessary rule or test edit that resolves the issue. Avoid unrelated refactors and do not change output formats or CLI flags.
4. Validate with:
   - powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests
5. If the issue is false-positive risk or the fix broadens matching behavior, run a repo-wide scan and summarize whether the extra findings look acceptable.
6. Review and summarize impact from:
   - [tests/findings.csv](../../tests/findings.csv)
   - [tests/findings_report.json](../../tests/findings_report.json)
   - [tests/findings_framework_summary.csv](../../tests/findings_framework_summary.csv)

Output format:

- Diagnosis: root cause and why it produced the observed behavior.
- Fix: file updated and why the change is the smallest correct fix.
- Validation: command run and result summary.
- Risk: any remaining ambiguity, false-positive risk, or follow-up check.