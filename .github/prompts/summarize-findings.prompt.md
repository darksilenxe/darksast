---
name: "Summarize Scanner Findings"
description: "Turn react-scanner findings artifacts into a short reviewer-facing report with notable rules, framework spread, and follow-up risks."
argument-hint: "Scan scope, time window, priority frameworks, and whether to emphasize regressions, noise, or top findings"
agent: "React Scanner Assistant"
---
Summarize scanner output for this repository based on this request:

{{input}}

Primary inputs:

- [tests/findings.csv](../../tests/findings.csv)
- [tests/findings_report.json](../../tests/findings_report.json)
- [tests/findings_framework_summary.csv](../../tests/findings_framework_summary.csv)
- [tests/package_summary.csv](../../tests/package_summary.csv)

Instructions:

1. Use the supplied artifacts as the main evidence.
2. Focus on the most important findings, rule distribution, framework distribution, and any signs of false-positive noise or missing coverage.
3. If the request mentions a different scan target, use the corresponding generated artifacts when present.
4. Keep the report compact and reviewer-facing. Do not restate every row.

Output format:

- Scope: what artifacts were summarized.
- Highlights: the most important findings or trends.
- Risk signals: suspicious concentrations, noisy rules, or unexpected absences.
- Follow-up: the 1 to 3 most useful next checks.