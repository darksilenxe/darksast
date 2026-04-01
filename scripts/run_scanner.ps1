param(
    [string]$Dir = ".",
    [string]$Rules = "./rules",
    [string]$PackagesOut = "./package_versions.txt",
    [string]$PackagesCSVOut = "./package_versions.csv",
    [string]$PackagesSummaryCSVOut = "./package_summary.csv",
    [string]$FindingsJSONOut = "./findings_report.json",
    [string]$FindingsFrameworkCSVOut = "./findings_framework_summary.csv",
    [string]$FindingsCSVOut = "./findings.csv"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go was not found in PATH."
}

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    throw "gcc was not found in PATH. Install MinGW or add gcc to PATH."
}

$env:CC = "gcc"

Write-Host "[*] Running scanner"
Write-Host "    dir: $Dir"
Write-Host "    rules: $Rules"
Write-Host "    packages-out: $PackagesOut"
Write-Host "    packages-csv-out: $PackagesCSVOut"
Write-Host "    packages-summary-csv-out: $PackagesSummaryCSVOut"
Write-Host "    findings-json-out: $FindingsJSONOut"
Write-Host "    findings-framework-csv-out: $FindingsFrameworkCSVOut"
Write-Host "    findings-csv-out: $FindingsCSVOut"

go run ./cmd/scanner/main.go -dir $Dir -rules $Rules -packages-out $PackagesOut -packages-csv-out $PackagesCSVOut -packages-summary-csv-out $PackagesSummaryCSVOut -findings-json-out $FindingsJSONOut -findings-framework-csv-out $FindingsFrameworkCSVOut -findings-csv-out $FindingsCSVOut
