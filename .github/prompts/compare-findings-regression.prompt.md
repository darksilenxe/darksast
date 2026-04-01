---
name: "Compare Scanner Findings"
description: "Compare current react-scanner findings artifacts against a previous scan and highlight regressions, reductions, and likely noise changes."
argument-hint: "Baseline artifact paths or scan label, current target, and whether to emphasize regressions, fixed findings, or noisy deltas"
agent: "React Scanner Assistant"
---
Compare current scanner findings for this repository against a previous scan based on this request:

{{input}}

Default current artifacts:

- [tests/findings.csv](../../tests/findings.csv)
- [tests/findings_report.json](../../tests/findings_report.json)
- [tests/findings_framework_summary.csv](../../tests/findings_framework_summary.csv)

Instructions:

1. Use the provided baseline artifacts if the request names them. If no baseline path is provided, ask for it instead of guessing.
2. Compare rule counts, framework counts, newly introduced findings, removed findings, and any sharp shifts that suggest query noise or missed coverage.
3. Focus on meaningful deltas rather than listing every row.
4. Call out whether the change looks like a real regression, an intended rule expansion, a likely false-positive increase, or an expected cleanup.

Output format:

- Scope: current artifacts and baseline artifacts compared.
- Regressions: important new findings or count increases that need review.
- Improvements: removed findings or reduced noise that look intentional.
- Unclear deltas: changes that need manual inspection.
- Next checks: the most useful follow-up commands or file inspections.