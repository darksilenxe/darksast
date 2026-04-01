---
name: "Add Scanner Rule"
description: "Author or refine one react-scanner YAML security rule, validate it on the tests target, and report findings impact."
argument-hint: "Vulnerability pattern, framework, new rule or refinement, expected true positives, and noise concerns"
agent: "React Scanner Assistant"
---
Author or refine exactly one scanner rule for this repository based on this request:

{{input}}

Use these repo instructions as the source of truth:

- [Rule Authoring Guidelines](../instructions/rule-authoring.instructions.md)
- [React Scanner Rule Authoring](../skills/react-scanner-rule-authoring/SKILL.md)

Required workflow:

1. Inspect the most similar existing rules under [rules](../../rules) before editing.
2. Add or refine one rule file under [rules](../../rules) with required fields:
   - id
   - severity
   - framework
   - description
   - query
3. Add or update the smallest relevant test coverage under [tests](../../tests) when needed to prove the detection.
4. Keep id uppercase with hyphen separators and keep the query precise and deterministic.
5. Validate with:
   - powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests
6. Review and summarize impact from:
   - [tests/findings.csv](../../tests/findings.csv)
   - [tests/findings_report.json](../../tests/findings_report.json)
   - [tests/findings_framework_summary.csv](../../tests/findings_framework_summary.csv)
7. If the rule appears structurally broad or the test-target results suggest likely noise, run a repo-wide scan and summarize whether the additional findings look acceptable.

Output format:

- Rule change: file updated or created, brief reasoning, and whether this was a new rule or refinement.
- Test coverage: what sample was added or adjusted, or why no test edit was needed.
- Validation: command run and the relevant result summary.
- Impact: intended detections, likely false-positive risk, and any recommended follow-up.
