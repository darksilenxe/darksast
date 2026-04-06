# JavaScript-Security-Scanner

JavaScript-Security-Scanner is a lightweight Go-based static scanner for JavaScript and framework projects. It detects risky patterns through Tree-sitter AST queries, reports findings in JSON/CSV, and also exports package inventory and framework summaries.

## Features

- Scans JavaScript/TypeScript source files (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`).
- Loads security signatures from YAML rule files in `rules/`.
- Produces findings in JSON and CSV formats.
- Produces package inventory outputs (table text + CSV + summary CSV).
- Supports Windows-first scripts and cross-platform shell scripts.

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
  -packages-out ./tests/package_versions.txt \
  -packages-csv-out ./tests/package_versions.csv \
  -packages-summary-csv-out ./tests/package_summary.csv \
  -findings-json-out ./tests/findings_report.json \
  -findings-framework-csv-out ./tests/findings_framework_summary.csv \
  -findings-csv-out ./tests/findings.csv
```

## Outputs

- Package inventory text: `package_versions.txt`
- Package inventory CSV: `package_versions.csv`
- Package summary CSV: `package_summary.csv`
- Findings JSON: `findings_report.json`
- Findings CSV: `findings.csv`
- Findings framework summary CSV: `findings_framework_summary.csv`

### Finding location fields

Every finding now includes precise source location information:

| Field      | Description                                                |
|------------|------------------------------------------------------------|
| `file`     | Path to the source file containing the vulnerability       |
| `line`     | 1-based line number within the file                        |
| `column`   | 1-based column (character offset) on that line             |
| `snippet`  | Trimmed text of the source line (capped at 120 characters) |

**Console output** prints `file:line:col` followed by the snippet on the next line:

```
[!] HIGH     | JavaScript   | JS-EVAL-EXEC                 | src/app.js:14:1
    eval(userInput);
```

**JSON findings** include all four location fields per entry:

```json
{
  "file": "src/app.js",
  "line": 14,
  "column": 1,
  "rule_id": "JS-EVAL-EXEC",
  "severity": "HIGH",
  "framework": "JavaScript",
  "snippet": "eval(userInput);"
}
```

**CSV findings** (`findings.csv`) columns: `file`, `line`, `column`, `rule_id`, `severity`, `framework`, `snippet`.

## Disclaimer

This project is provided for educational and defensive security purposes only. You are solely responsible for how you use this software. The author and contributors are not liable for any misuse, damages, or legal consequences resulting from use of this project.

## License

This project is licensed under the MIT License. See `LICENSE`.
