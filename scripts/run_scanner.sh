#!/usr/bin/env bash
set -euo pipefail

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      DIR="$2"
      shift 2
      ;;
    --rules)
      RULES="$2"
      shift 2
      ;;
    --packages-out)
      PACKAGES_OUT="$2"
      shift 2
      ;;
    --packages-csv-out)
      PACKAGES_CSV_OUT="$2"
      shift 2
      ;;
    --packages-summary-csv-out)
      PACKAGES_SUMMARY_CSV_OUT="$2"
      shift 2
      ;;
    --findings-json-out)
      FINDINGS_JSON_OUT="$2"
      shift 2
      ;;
    --findings-framework-csv-out)
      FINDINGS_FRAMEWORK_CSV_OUT="$2"
      shift 2
      ;;
    --findings-csv-out)
      FINDINGS_CSV_OUT="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v go >/dev/null 2>&1; then
  echo "go was not found in PATH" >&2
  exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc was not found in PATH. Install build-essential or add gcc to PATH." >&2
  exit 1
fi

export CC=gcc

echo "[*] Running scanner"
echo "    dir: ${DIR}"
echo "    rules: ${RULES}"
echo "    packages-out: ${PACKAGES_OUT}"
echo "    packages-csv-out: ${PACKAGES_CSV_OUT}"
echo "    packages-summary-csv-out: ${PACKAGES_SUMMARY_CSV_OUT}"
echo "    findings-json-out: ${FINDINGS_JSON_OUT}"
echo "    findings-framework-csv-out: ${FINDINGS_FRAMEWORK_CSV_OUT}"
echo "    findings-csv-out: ${FINDINGS_CSV_OUT}"

go run ./cmd/scanner/main.go \
  -dir "${DIR}" \
  -rules "${RULES}" \
  -packages-out "${PACKAGES_OUT}" \
  -packages-csv-out "${PACKAGES_CSV_OUT}" \
  -packages-summary-csv-out "${PACKAGES_SUMMARY_CSV_OUT}" \
  -findings-json-out "${FINDINGS_JSON_OUT}" \
  -findings-framework-csv-out "${FINDINGS_FRAMEWORK_CSV_OUT}" \
  -findings-csv-out "${FINDINGS_CSV_OUT}" \
  -compromised-json-out "${COMPROMISED_JSON_OUT}" \
  -compromised-csv-out "${COMPROMISED_CSV_OUT}"
