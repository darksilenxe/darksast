# JavaScript-Security-Scanner

JavaScript-Security-Scanner is a lightweight Go-based static scanner for application and configuration code. It supports JavaScript/TypeScript, Python, Go, Rust, Java, PHP, Ruby, C#, Bash, and YAML scanning, reports findings in JSON/CSV, and exports package inventory, framework summaries, and compromised-package intel matches.

## Features

- Multi-language SAST scanning for JavaScript/TypeScript, Python, Go, Rust, Java, PHP, Ruby, C#, Bash, and YAML (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.py`, `.go`, `.rs`, `.java`, `.php`, `.rb`, `.cs`, `.sh`, `.bash`, `.zsh`, `.yaml`, `.yml`).
- Tree-sitter-based YAML rule engine with support for:
  - Native repo rules in `rules/`.
  - Semgrep/OpenGrep `rules: [...]` bundles when each imported rule provides a Tree-sitter-compatible `query` (or `metadata.query`).
  - Optional rule language targeting, dependency-aware rule gating (`requires_dependency` + `-gate-by-dependency`), and confidence/severity reporting.
  - Optional post-match false-positive controls (literal gates, regex require/ignore filters, argument-count gates) and taint-aware matching.
- Rich findings pipeline:
  - Output formats: JSON, CSV, optional SARIF.
  - Precise spans (`line/column/end_line/end_column`) plus `snippet`, `matched_code`, and `highlighted_snippet`.
  - Rule-level `tags` in findings output to support grouping by sensitive-data and secret-related detections.
  - Framework/severity rollups via findings framework summary CSV.
  - Severity/confidence result gating via `-min-severity` and `-min-confidence`.
  - Optional category-based CI fail gating via `-fail-on-categories`.
- Dependency intelligence pipeline:
  - Package inventory extraction across manifests including `package.json`, `requirements.txt`, `go.mod`, and `Cargo.toml`.
  - npm lockfile-aware resolution from `package-lock.json` / `npm-shrinkwrap.json`.
  - Inventory outputs: text table + CSV + summary CSV.
  - Compromised package detection from local seed rules plus optional remote feed (with generated merged rules output).
  - OSS advisory matching from local bundles plus optional remote feed, including `github://npm` ingestion from GitHub Advisory Database.
  - Advisory policy suppressions with optional expiry and CI fail gating via `-fail-on-oss-vuln-severity`.
- Optional URL fetch mode (`-url`) that downloads inline and same-origin external scripts into `-fetch-out` and scans them with the same pipeline.
- Scan scope controls for test/spec and vendored/build-output files via `-include-tests` and `-include-vendored`.
- Windows-first PowerShell entry scripts plus cross-platform shell entrypoint and npm wrappers.

## Requirements

- Go 1.26+
- `gcc` available on PATH (required for cgo + Tree-sitter)
- PowerShell 5.1+ on Windows (for `.ps1` entry scripts)

## Command Line Usage

### Windows (recommended)

Scan tests target:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests
```

Scan full repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey repo
```

Other targets:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey sample-site
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey sample-vue
```

### npm wrappers

```bash
npm run scan
npm run scan:tests
npm run scan:sample-site
npm run scan:sample-vue
```

### Cross-platform shell entrypoint

```bash
./scripts/scan_entry.sh --target tests
```

### Direct Go entrypoint

```bash
CC=gcc go run ./cmd/scanner/main.go \
  -dir ./tests \
  -rules ./rules \
  -advisories ./advisories \
  -packages-out ./tests/package_versions.txt \
  -packages-csv-out ./tests/package_versions.csv \
  -packages-summary-csv-out ./tests/package_summary.csv \
  -compromised-json-out ./tests/compromised_packages.json \
  -compromised-csv-out ./tests/compromised_packages.csv \
  -findings-json-out ./tests/findings_report.json \
  -findings-framework-csv-out ./tests/findings_framework_summary.csv \
  -findings-csv-out ./tests/findings.csv
```

### Scan a live website

The scanner can also fetch JavaScript directly from a URL. When `-url` is set, it downloads inline `<script>` blocks and (by default) same-origin external `<script src="...">` files into `-fetch-out`, writes a `manifest.json` mapping each saved file back to its origin URL, and then runs the normal scan pipeline against that directory.

```bash
CC=gcc go run ./cmd/scanner/main.go \
  -url https://example.com/ \
  -fetch-out ./fetched-site \
  -rules ./rules
```

Relevant flags:

| Flag | Default | Description |
|---|---|---|
| `-url` | (empty) | When set, fetch JavaScript from this URL before scanning. |
| `-fetch-out` | `./fetched-site` | Directory to write downloaded JavaScript and `manifest.json`. |
| `-fetch-timeout` | `30s` | Per-request HTTP timeout. |
| `-fetch-user-agent` | scanner UA | `User-Agent` header sent on each request. |
| `-fetch-max-bytes` | `5242880` (5 MiB) | Maximum bytes accepted per response; larger responses are skipped. |
| `-fetch-same-origin` | `true` | When `true`, skip external scripts whose host differs from the page URL. |
| `-compromised-rules` | `./intel/compromised_packages.yaml` | Local YAML seed rules for compromised package intelligence. |
| `-compromised-feed-url` | (empty) | Optional remote JSON feed for compromised package rules and IoCs. |
| `-compromised-generated-rules-out` | (empty) | Optional YAML path to write the merged compromised package ruleset. |
| `-compromised-json-out` | `./compromised_packages.json` | JSON report for compromised package matches. |
| `-compromised-csv-out` | `./compromised_packages.csv` | CSV report for compromised package matches. |
| `-advisory-rules` | `./intel/advisories.yaml` | Local YAML/JSON advisory bundle for OSS dependency vulnerability matching. |
| `-advisory-feed-url` | (empty) | Optional remote JSON feed for OSS dependency advisories. Use `github://npm` to ingest all npm advisories from GitHub Advisory Database. |
| `-advisory-generated-rules-out` | (empty) | Optional YAML path to write the merged advisory ruleset. |
| `-advisory-policy` | (empty) | Optional YAML policy file with `ignores:` entries keyed by advisory ID, package, and optional expiry. |
| `-oss-vulns-json-out` | `./oss_vulnerabilities.json` | JSON report for OSS dependency vulnerability matches. |
| `-oss-vulns-csv-out` | `./oss_vulnerabilities.csv` | CSV report for OSS dependency vulnerability matches. |
| `-oss-vulns-summary-csv-out` | `./oss_vulnerabilities_summary.csv` | Summary CSV for OSS dependency vulnerability matches. |
| `-fail-on-oss-vuln-severity` | (empty) | Exit non-zero when OSS dependency findings at or above the selected severity remain after policy filtering. |
| `-fail-on-categories` | (empty) | Comma-separated finding categories that fail the scan when present (case-insensitive). |
| `-findings-sarif-out` | (empty) | Optional SARIF output path for findings. |

Notes and limitations:

- Only the single page at `-url` is fetched; the scanner does not crawl additional pages.
- JavaScript injected at runtime by other scripts (for example via `document.write` or SPA hydration) is not captured because no headless browser is used.
- Same-origin filtering is on by default to avoid persisting third-party CDN code; pass `-fetch-same-origin=false` to include it.
- The default User-Agent identifies the scanner so site operators can see what is hitting them.
- For full JavaScript (npm) advisory coverage from GitHub Advisory Database, set `-advisory-feed-url github://npm`. For higher API limits on large pulls, set `GITHUB_TOKEN` (or `GH_TOKEN`) in the environment.

## Outputs

- Package inventory text: `package_versions.txt`
- Package inventory CSV: `package_versions.csv`
- Package summary CSV: `package_summary.csv`
- Compromised package JSON: `compromised_packages.json`
- Compromised package CSV: `compromised_packages.csv`
- OSS dependency vulnerability JSON: `oss_vulnerabilities.json`
- OSS dependency vulnerability CSV: `oss_vulnerabilities.csv`
- OSS dependency vulnerability summary CSV: `oss_vulnerabilities_summary.csv`
- Findings JSON: `findings_report.json`
- Findings SARIF (optional): user-specified via `-findings-sarif-out`
- Findings CSV: `findings.csv`
- Findings framework summary CSV: `findings_framework_summary.csv`
- Fetched JavaScript manifest (only when `-url` is set): `<fetch-out>/manifest.json`

### Dependency-aware inventory and findings

- Package inventory now records declared versions, resolved versions, and the lockfile source when available.
- Findings output distinguishes `code` findings from `dependency` findings.
- Enriched rule metadata such as category, taxonomy, CWE, OWASP, references, remediation, and confidence rationale is surfaced in JSON and CSV findings output when present.

### Finding location fields

Every finding now includes precise source location information:

| Field      | Description                                                |
|------------|------------------------------------------------------------|
| `file`     | Path to the source file containing the vulnerability       |
| `line`     | 1-based line number within the file                        |
| `column`   | 1-based column (character offset) on that line             |
| `snippet`  | Trimmed text of the source line (capped at 120 characters) |
| `matched_code` | Exact AST-matched code fragment that triggered the rule |
| `highlighted_snippet` | Snippet with `[[DANGEROUS]]...[[/DANGEROUS]]` markers around the matched fragment |

**Console output** prints `file:line:col` followed by highlighted dangerous code on the next line:

```
[!] HIGH     | JavaScript   | JS-EVAL-EXEC                 | src/app.js:14:1
    [[DANGEROUS]]eval(userInput)[[/DANGEROUS]];
```

**JSON findings** include these location/context fields per entry:

```json
{
  "file": "src/app.js",
  "line": 14,
  "column": 1,
  "rule_id": "JS-EVAL-EXEC",
  "severity": "HIGH",
  "framework": "JavaScript",
  "snippet": "eval(userInput);",
  "matched_code": "eval(userInput)",
  "highlighted_snippet": "[[DANGEROUS]]eval(userInput)[[/DANGEROUS]];"
}
```

**CSV findings** (`findings.csv`) include `snippet`, `matched_code`, and `highlighted_snippet` columns for faster triage.

## Disclaimer

This project is provided for educational and defensive security purposes only. You are solely responsible for how you use this software. The author and contributors are not liable for any misuse, damages, or legal consequences resulting from use of this project.

## License

This project is licensed under the MIT License. See `LICENSE`.
