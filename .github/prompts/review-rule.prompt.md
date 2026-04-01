---
name: "Review Scanner Rule"
description: "Review one react-scanner YAML rule for correctness, precision, conventions, and test coverage gaps without broad repo changes."
argument-hint: "Rule file or id, intended detections, acceptable non-matches, and any suspected weaknesses"
agent: "React Scanner Assistant"
---
Review exactly one scanner rule in this repository based on this request:

{{input}}

Use these repo instructions as the source of truth:

- [Rule Authoring Guidelines](../instructions/rule-authoring.instructions.md)
- [React Scanner Rule Authoring](../skills/react-scanner-rule-authoring/SKILL.md)

Review checklist:

1. Inspect the target rule under [rules](../../rules) and compare it with the most similar rules in the repository.
2. Check required fields, rule id format, framework casing, description quality, and whether the query is precise and deterministic.
3. Check whether existing coverage under [tests](../../tests) is sufficient to prove both intended detections and likely non-matches.
4. If validation is needed to confirm a review finding, run:
   - powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests
5. Do not make code changes unless the user explicitly asks for fixes. Default to review findings first.

Output format:

- Findings: ordered by severity, with the rule weakness and why it matters.
- Coverage gaps: missing or weak tests, if any.
- Validation: whether a scan was run and what it confirmed.
- Recommendation: the smallest next change that would improve the rule.

If there are no material findings, say that explicitly and mention any residual uncertainty.