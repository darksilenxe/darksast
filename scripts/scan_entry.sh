#!/usr/bin/env bash
set -euo pipefail

TARGET_KEY="repo"
PREFER_NPM=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_KEY="$2"
      shift 2
      ;;
    --prefer-npm)
      PREFER_NPM=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$TARGET_KEY" in
  repo|tests|sample-site|sample-vue) ;;
  *)
    echo "Invalid --target '$TARGET_KEY'. Valid: repo, tests, sample-site, sample-vue" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

case "$TARGET_KEY" in
  repo)
    DIR="."
    RULES="./rules"
    PACKAGES_OUT="./package_versions.txt"
    PACKAGES_CSV_OUT="./package_versions.csv"
    PACKAGES_SUMMARY_CSV_OUT="./package_summary.csv"
    FINDINGS_JSON_OUT="./findings_report.json"
    FINDINGS_FRAMEWORK_CSV_OUT="./findings_framework_summary.csv"
    FINDINGS_CSV_OUT="./findings.csv"
    COMPROMISED_JSON_OUT="./compromised_packages.json"
    COMPROMISED_CSV_OUT="./compromised_packages.csv"
    ;;
  tests)
    DIR="./tests"
    RULES="./rules"
    PACKAGES_OUT="./tests/package_versions.txt"
    PACKAGES_CSV_OUT="./tests/package_versions.csv"
    PACKAGES_SUMMARY_CSV_OUT="./tests/package_summary.csv"
    FINDINGS_JSON_OUT="./tests/findings_report.json"
    FINDINGS_FRAMEWORK_CSV_OUT="./tests/findings_framework_summary.csv"
    FINDINGS_CSV_OUT="./tests/findings.csv"
    COMPROMISED_JSON_OUT="./tests/compromised_packages.json"
    COMPROMISED_CSV_OUT="./tests/compromised_packages.csv"
    ;;
  sample-site)
    DIR="./tests/sample-site"
    RULES="./rules"
    PACKAGES_OUT="./tests/sample-site/package_versions.txt"
    PACKAGES_CSV_OUT="./tests/sample-site/package_versions.csv"
    PACKAGES_SUMMARY_CSV_OUT="./tests/sample-site/package_summary.csv"
    FINDINGS_JSON_OUT="./tests/sample-site/findings_report.json"
    FINDINGS_FRAMEWORK_CSV_OUT="./tests/sample-site/findings_framework_summary.csv"
    FINDINGS_CSV_OUT="./tests/sample-site/findings.csv"
    COMPROMISED_JSON_OUT="./tests/sample-site/compromised_packages.json"
    COMPROMISED_CSV_OUT="./tests/sample-site/compromised_packages.csv"
    ;;
  sample-vue)
    DIR="./tests/sample-vue"
    RULES="./rules"
    PACKAGES_OUT="./tests/sample-vue/package_versions.txt"
    PACKAGES_CSV_OUT="./tests/sample-vue/package_versions.csv"
    PACKAGES_SUMMARY_CSV_OUT="./tests/sample-vue/package_summary.csv"
    FINDINGS_JSON_OUT="./tests/sample-vue/findings_report.json"
    FINDINGS_FRAMEWORK_CSV_OUT="./tests/sample-vue/findings_framework_summary.csv"
    FINDINGS_CSV_OUT="./tests/sample-vue/findings.csv"
    COMPROMISED_JSON_OUT="./tests/sample-vue/compromised_packages.json"
    COMPROMISED_CSV_OUT="./tests/sample-vue/compromised_packages.csv"
    ;;
esac

if [[ "$PREFER_NPM" == true ]] && command -v npm >/dev/null 2>&1; then
  echo "[*] npm detected, delegating to npm run for target '${TARGET_KEY}'."
  NPM_SCRIPT="scan"
  if [[ "$TARGET_KEY" != "repo" ]]; then
    NPM_SCRIPT="scan:${TARGET_KEY}"
  fi
  npm run "$NPM_SCRIPT"
  exit $?
fi

if [[ "$PREFER_NPM" == true ]] && ! command -v npm >/dev/null 2>&1; then
  echo "[i] npm not found, running direct scanner fallback."
fi

"${SCRIPT_DIR}/run_scanner.sh" \
  --dir "$DIR" \
  --rules "$RULES" \
  --packages-out "$PACKAGES_OUT" \
  --packages-csv-out "$PACKAGES_CSV_OUT" \
  --packages-summary-csv-out "$PACKAGES_SUMMARY_CSV_OUT" \
  --findings-json-out "$FINDINGS_JSON_OUT" \
  --findings-framework-csv-out "$FINDINGS_FRAMEWORK_CSV_OUT" \
  --findings-csv-out "$FINDINGS_CSV_OUT" \
  --compromised-json-out "$COMPROMISED_JSON_OUT" \
  --compromised-csv-out "$COMPROMISED_CSV_OUT"
