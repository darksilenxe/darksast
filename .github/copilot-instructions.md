# Project Guidelines

## Code Style
- Prefer small, targeted changes that preserve existing CLI flags, output file formats, and rule IDs.
- Follow existing Go patterns in this repo: early returns, explicit error checks, and `log.Printf` for non-fatal issues / `log.Fatalf` for fatal startup errors.
- Keep YAML security rules in `rules/` minimal and deterministic: each rule must include `id`, `severity`, `framework`, `description`, and `query`.
- Avoid broad refactors unless explicitly requested; prioritize scanner correctness and stable output compatibility.

## Architecture
- CLI orchestration lives in `cmd/scanner/main.go`.
- Scanning engine and AST matching live in `internal/engine/engine.go` and `internal/engine/rules.go`.
- Dependency/framework detection and package inventory logic live in `internal/deps/dependency.go`.
- Report writers (JSON/CSV outputs) live in `internal/reporter/reporter.go`.
- Security signatures are YAML files under `rules/`.
- Test corpus and expected scan artifacts live under `tests/` (including `tests/sample-site/` and `tests/sample-vue/`).

## Build and Test
- Preferred local run on Windows:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey tests`
- Other common targets:
  - `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey repo`
  - `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey sample-site`
  - `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/scan_entry.ps1 -TargetKey sample-vue`
- npm wrappers (Windows-first workflow):
  - `npm run scan`
  - `npm run scan:tests`
  - `npm run scan:sample-site`
  - `npm run scan:sample-vue`
- Cross-platform shell entrypoint:
  - `./scripts/scan_entry.sh --target tests`

## Conventions
- Treat scanner outputs as contract-like artifacts. Keep these flags/outputs stable unless asked to change them:
  - package inventory text/csv, package summary csv, findings json/csv, framework summary csv.
- When adding or updating rules in `rules/`:
  - Keep `id` uppercase with hyphen separators (for example: `INSECURE-RANDOM-TOKEN`).
  - Use framework labels already used in the repo (for example: `JavaScript`, `React`, `Angular`, `Vue`, `Node.js`, `Express`, `Next.js`).
  - Prefer precise Tree-sitter patterns over overly broad query matches.
- Keep scans focused during validation:
  - Use `-TargetKey tests` for quick rule iteration.
  - Use repo-wide scan only when needed for regression checks.
- Windows gotcha:
  - This scanner depends on cgo + Tree-sitter and requires `gcc` on PATH. If direct `go run` fails on Windows, use `CC=gcc`.

## References
- Rule authoring workflow and examples: `.github/skills/react-scanner-rule-authoring/SKILL.md`
- Repo-specific agent modes: `.github/agents/react-scanner.agent.md`
- Additional scanner task entrypoints: `.vscode/tasks.json`, `scripts/scan_entry.ps1`, `scripts/run_scanner.ps1`