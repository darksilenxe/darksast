---
name: react-scanner-rule-authoring
description: 'Author or refine react-scanner YAML security rules. Use when creating a new rule, debugging a missed finding, tightening a noisy rule, writing Tree-sitter queries, validating findings on tests, or checking repo-wide false positives.'
argument-hint: 'Describe the vulnerability pattern, framework, and whether this is a new rule or a refinement.'
user-invocable: true
disable-model-invocation: false
---

# React Scanner Rule Authoring

## What This Skill Produces

This skill helps the agent create or refine a YAML rule in `./rules/`, add or update test coverage in `./tests/`, run the scanner with this repo's Windows-friendly flow, and verify both expected detections and likely false positives.

## When to Use

- Add a new security rule for React, Angular, Vue, Node.js, Express, or JavaScript patterns.
- Fix a rule that misses a known vulnerable pattern.
- Tighten a rule that matches too broadly.
- Validate Tree-sitter query changes against the repo test corpus.
- Check whether a new rule behaves correctly on the full repository.

## Repo Facts

- Rules live in `./rules/` and are auto-loaded from `.yaml` and `.yml` files.
- Each rule needs `id`, `severity`, `framework`, `description`, and `query`.
- Common frameworks in this repo: `React`, `Angular`, `Vue`, `Node.js`, `JavaScript`, `Express`.
- On Windows, direct `go run` should use `CC=gcc`.
- Preferred scan entry point for this repo is `./scripts/scan_entry.ps1`.

## Procedure

1. Clarify the target.
Determine the vulnerability pattern, affected framework, vulnerable API or syntax shape, whether the task is a brand-new rule or a refinement, and what should count as a true positive versus an acceptable non-match.

2. Inspect nearby rule patterns.
Read the most similar files in `./rules/` to copy existing naming, severity, framework casing, and Tree-sitter query structure. Prefer existing query shapes over inventing new style.

3. Add or update test coverage first.
Place a minimal representative example in `./tests/rule_coverage.js`, `./tests/framework_rule_coverage.js`, or `./tests/advanced_rule_coverage.js` based on fit. If the pattern is framework-specific, prefer the most relevant sample file such as `./tests/sample-site/app.js` or `./tests/sample-vue/main.js`.

4. Author or refine the YAML rule.
Create or update one file in `./rules/` using a descriptive lowercase filename and a stable uppercase rule id. Keep the description concrete. Use named captures where they improve clarity. Match the repo's existing framework names exactly.

5. Validate on the tests target first.
Run `./scripts/scan_entry.ps1 -TargetKey tests` or the equivalent npm script. Check that the scanner loads the expected number of rules and that the new or changed rule appears in terminal output and generated findings files.

6. Verify the detection details.
Inspect `./tests/findings.csv` and `./tests/findings_report.json` to confirm the rule id, severity, framework, and line numbers are correct for the intended test cases.

7. Check false positives on the repo.
Run `./scripts/scan_entry.ps1 -TargetKey repo` or the workspace scanner task. Review whether the rule over-matches common benign code. Tighten the query if repo-wide findings are noisy.

8. Iterate until both checks pass.
Repeat test-target validation and repo-wide validation until the rule reliably catches the intended pattern and does not produce obvious broad noise.

## Decision Points

- New rule vs refinement:
If there is already a close rule, prefer refining it instead of creating a near-duplicate id.

- Test file choice:
Use a focused coverage file for a narrow pattern and the sample apps when framework context matters.

- Query breadth:
If the first query catches too much, narrow by function name, property name, literal values, or structural context before adding more test cases.

- Rule naming:
Use repo-style descriptive names such as vulnerability plus target API or sink.

## Completion Checks

- The YAML parses and the rule loads without reducing the total loaded rule count unexpectedly.
- The rule triggers on the intended test sample.
- Reported line numbers point to the expected code.
- The framework value uses existing repo casing.
- Repo-wide scan does not introduce obvious false-positive spam.
- Output artifacts reflect the new rule consistently in CSV and JSON findings.

## Windows Execution Notes

- Preferred commands:
  - `./scripts/scan_entry.ps1 -TargetKey tests`
  - `./scripts/scan_entry.ps1 -TargetKey repo`
- If running the Go entry point directly on Windows, set `CC=gcc` first because MSVC-based cgo builds may fail in this repo.

## Common Failure Modes

- Query syntax is invalid, so the rule is skipped at runtime.
- `framework` casing does not match repo conventions, which weakens reporting consistency.
- The rule id duplicates an existing one and makes findings hard to interpret.
- The test sample uses a file extension or syntax shape the scanner does not process as expected.
- The query is structurally too broad and explodes on repo-wide scans.

## Working Style

- Prefer the smallest rule change that explains the detection goal.
- Add or adjust tests before declaring the rule correct.
- Validate on `tests` before scanning the whole repo.
- Treat repo-wide scan results as the false-positive gate.