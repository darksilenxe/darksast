---
description: "Use when creating, tightening, or debugging scanner YAML rules in rules/**/*.yaml, including Tree-sitter query tuning and false-positive reduction."
name: "Rule Authoring Guidelines"
applyTo: "rules/**/*.yaml"
---
# Rule Authoring Guidelines

- Keep each rule deterministic and minimal. Include only fields required by the scanner: id, severity, framework, description, and query.
- Keep id uppercase with hyphen separators, for example INSECURE-RANDOM-TOKEN.
- Reuse existing framework labels already present in this repo, for example JavaScript, React, Angular, Vue, Node.js, Express, Next.js.
- Prefer precise Tree-sitter patterns over broad wildcard captures.
- Tune rules against tests first before broader scans.

## Validation Workflow

1. Update or add the rule in rules/.
2. Run focused validation:
   - powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests
3. Review expected artifacts for regression/noise:
   - tests/findings.csv
   - tests/findings_report.json
   - tests/findings_framework_summary.csv
4. Only run repo-wide scan when needed for broader regression checks.

## Guardrails

- Do not change CLI flags or output file schemas while editing rules.
- If a rule is noisy, tighten identifier/name constraints before adding more AST alternatives.
- If a rule misses expected findings, verify query compilation assumptions and node shapes against test samples.

## References

- [.github/skills/react-scanner-rule-authoring/SKILL.md](../skills/react-scanner-rule-authoring/SKILL.md)
- [scripts/scan_entry.ps1](../../scripts/scan_entry.ps1)
