$ErrorActionPreference = "Stop"

$TargetKey = "repo"
$PreferNpm = $false

for ($i = 0; $i -lt $args.Count; $i++) {
    $arg = $args[$i]
    if ($arg -ieq "-TargetKey") {
        if ($i + 1 -lt $args.Count) {
            $TargetKey = $args[$i + 1]
            $i++
        }
        continue
    }

    if ($arg -ieq "-PreferNpm") {
        $PreferNpm = $true
        continue
    }
}

$validTargets = @("repo", "tests", "sample-site", "sample-vue")
if ($validTargets -notcontains $TargetKey) {
    throw "Invalid -TargetKey '$TargetKey'. Valid values: repo, tests, sample-site, sample-vue"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Set-Location $repoRoot

$targetArgs = @{}

switch ($TargetKey) {
    "repo" {
        $targetArgs = @{
            Dir = "."
            Rules = "./rules"
            PackagesOut = "./package_versions.txt"
            PackagesCSVOut = "./package_versions.csv"
            PackagesSummaryCSVOut = "./package_summary.csv"
            FindingsJSONOut = "./findings_report.json"
            FindingsFrameworkCSVOut = "./findings_framework_summary.csv"
            FindingsCSVOut = "./findings.csv"
        }
    }
    "tests" {
        $targetArgs = @{
            Dir = "./tests"
            Rules = "./rules"
            PackagesOut = "./tests/package_versions.txt"
            PackagesCSVOut = "./tests/package_versions.csv"
            PackagesSummaryCSVOut = "./tests/package_summary.csv"
            FindingsJSONOut = "./tests/findings_report.json"
            FindingsFrameworkCSVOut = "./tests/findings_framework_summary.csv"
            FindingsCSVOut = "./tests/findings.csv"
        }
    }
    "sample-site" {
        $targetArgs = @{
            Dir = "./tests/sample-site"
            Rules = "./rules"
            PackagesOut = "./tests/sample-site/package_versions.txt"
            PackagesCSVOut = "./tests/sample-site/package_versions.csv"
            PackagesSummaryCSVOut = "./tests/sample-site/package_summary.csv"
            FindingsJSONOut = "./tests/sample-site/findings_report.json"
            FindingsFrameworkCSVOut = "./tests/sample-site/findings_framework_summary.csv"
            FindingsCSVOut = "./tests/sample-site/findings.csv"
        }
    }
    "sample-vue" {
        $targetArgs = @{
            Dir = "./tests/sample-vue"
            Rules = "./rules"
            PackagesOut = "./tests/sample-vue/package_versions.txt"
            PackagesCSVOut = "./tests/sample-vue/package_versions.csv"
            PackagesSummaryCSVOut = "./tests/sample-vue/package_summary.csv"
            FindingsJSONOut = "./tests/sample-vue/findings_report.json"
            FindingsFrameworkCSVOut = "./tests/sample-vue/findings_framework_summary.csv"
            FindingsCSVOut = "./tests/sample-vue/findings.csv"
        }
    }
}

$npmCommand = Get-Command npm -ErrorAction SilentlyContinue
if ($PreferNpm -and $npmCommand) {
    Write-Host "[*] npm detected, delegating to npm run scan target '$TargetKey'."
    $npmScript = "scan"
    if ($TargetKey -ne "repo") {
        $npmScript = "scan:$TargetKey"
    }
    npm run $npmScript
    exit $LASTEXITCODE
}

if ($PreferNpm -and -not $npmCommand) {
    Write-Host "[i] npm not found, running direct scanner fallback."
}

$runner = Join-Path $scriptDir "run_scanner.ps1"
& $runner `
    -Dir $targetArgs.Dir `
    -Rules $targetArgs.Rules `
    -PackagesOut $targetArgs.PackagesOut `
    -PackagesCSVOut $targetArgs.PackagesCSVOut `
    -PackagesSummaryCSVOut $targetArgs.PackagesSummaryCSVOut `
    -FindingsJSONOut $targetArgs.FindingsJSONOut `
    -FindingsFrameworkCSVOut $targetArgs.FindingsFrameworkCSVOut `
    -FindingsCSVOut $targetArgs.FindingsCSVOut

exit $LASTEXITCODE
