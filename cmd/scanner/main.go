package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	// Adjust this import path based on your actual go.mod module name
	"javascript-security-scanner/internal/deps"
	"javascript-security-scanner/internal/engine"
	"javascript-security-scanner/internal/reporter"
)

// severityRank ranks severity strings so the --min-severity gate can
// compare findings consistently. Unknown values get the lowest rank
// so they are never filtered out by accident.
var severityRank = map[string]int{
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

// confidenceRank does the same for the --min-confidence gate.
var confidenceRank = map[string]int{
	"LOW":    1,
	"MEDIUM": 2,
	"HIGH":   3,
}

func main() {
	targetDir := flag.String("dir", ".", "Directory to scan")
	rulesDir := flag.String("rules", "./rules", "Directory containing YAML rule files")
	packagesOut := flag.String("packages-out", "./package_versions.txt", "Output text file for package/version table")
	packagesCSVOut := flag.String("packages-csv-out", "./package_versions.csv", "Output CSV file for package/version table")
	packagesSummaryCSVOut := flag.String("packages-summary-csv-out", "./package_summary.csv", "Output summary CSV file for CI dashboards")
	findingsJSONOut := flag.String("findings-json-out", "./findings_report.json", "Output JSON file for SAST findings")
	findingsFrameworkCSVOut := flag.String("findings-framework-csv-out", "./findings_framework_summary.csv", "Output CSV file for framework/severity finding counts")
	findingsCSVOut := flag.String("findings-csv-out", "./findings.csv", "Output CSV file with one row per finding")
	includeTests := flag.Bool("include-tests", false, "Include test/spec files (*.test.*, *.spec.*, __tests__, cypress, e2e, playwright) in scans")
	includeVendored := flag.Bool("include-vendored", false, "Include vendored / build-output files (node_modules, dist, build, out, coverage, .next, vendor, *.min.js, *.d.ts) in scans")
	gateByDependency := flag.Bool("gate-by-dependency", false, "Suppress framework-specific rules whose `requires_dependency` list does not match the scanned project's package.json (e.g. skip Angular rules when @angular/core is absent)")
	minSeverity := flag.String("min-severity", "LOW", "Minimum finding severity to report: LOW, MEDIUM, HIGH, CRITICAL")
	minConfidence := flag.String("min-confidence", "LOW", "Minimum finding confidence to report: LOW, MEDIUM, HIGH")
	flag.Parse()

	fmt.Printf("[*] Target Directory: %s\n", *targetDir)

	// 1. Run the dependency check
	deps.CheckDependencies(*targetDir)

	// 1b. Build a package/version inventory table across discovered JS projects
	packageRecords, err := deps.CollectPackageRecords(*targetDir)
	if err != nil {
		log.Printf("[!] Failed to collect package inventory: %v\n", err)
	} else {
		frameworks := deps.DetectFrameworks(packageRecords)
		if writeErr := deps.WritePackageTable(packageRecords, frameworks, *packagesOut); writeErr != nil {
			log.Printf("[!] Failed to write package inventory table: %v\n", writeErr)
		} else {
			fmt.Printf("[+] Package inventory written to %s (%d packages).\n", *packagesOut, len(packageRecords))
			if csvErr := deps.WritePackageCSV(packageRecords, *packagesCSVOut); csvErr != nil {
				log.Printf("[!] Failed to write package inventory CSV: %v\n", csvErr)
			} else {
				fmt.Printf("[+] Package CSV written to %s (%d packages).\n", *packagesCSVOut, len(packageRecords))
			}
			summary := deps.BuildSummaryStats(packageRecords, frameworks)
			if summaryErr := deps.WriteSummaryCSV(summary, *packagesSummaryCSVOut); summaryErr != nil {
				log.Printf("[!] Failed to write package summary CSV: %v\n", summaryErr)
			} else {
				fmt.Printf("[+] Package summary CSV written to %s.\n", *packagesSummaryCSVOut)
			}
			if len(frameworks) > 0 {
				fmt.Printf("[*] Detected frameworks: %v\n", frameworks)
			} else {
				fmt.Println("[*] Detected frameworks: none")
			}
		}
		fmt.Println()
	}

	// 2. Load the external YAML rules
	fmt.Printf("[*] Loading signatures from %s...\n", *rulesDir)
	rules, err := engine.LoadRules(*rulesDir)
	if err != nil {
		log.Fatalf("[!] Fatal error loading rules: %v", err)
	}

	if len(rules) == 0 {
		log.Fatalf("[!] No valid rules found in %s. Exiting.", *rulesDir)
	}
	fmt.Printf("[+] Loaded %d rules.\n\n", len(rules))

	// 3. Initialize the scanning engine with the loaded rules
	scannerEngine := engine.New(rules)
	scannerEngine.IncludeTests = *includeTests
	scannerEngine.IncludeVendored = *includeVendored
	scannerEngine.EnableDependencyGating = *gateByDependency

	// Wire the project's package inventory into the engine so rules
	// can be gated by `requires_dependency`.
	if len(packageRecords) > 0 {
		names := make([]string, 0, len(packageRecords))
		for _, record := range packageRecords {
			names = append(names, record.Name)
		}
		scannerEngine.SetProjectDependencies(names)
	}

	findingsChan := make(chan engine.Finding, 100)
	findings := make([]engine.Finding, 0)

	// Resolve the minimum severity/confidence gates once.
	minSevRank := severityRank[strings.ToUpper(*minSeverity)]
	minConfRank := confidenceRank[strings.ToUpper(*minConfidence)]

	// 4. Execute the scan in a goroutine and consume findings in the main flow.
	scanErrChan := make(chan error, 1)
	go func() {
		scanErrChan <- scannerEngine.ScanDirectory(*targetDir, findingsChan)
	}()

	for f := range findingsChan {
		if minSevRank > 0 && severityRank[strings.ToUpper(f.Severity)] < minSevRank {
			continue
		}
		if minConfRank > 0 && confidenceRank[strings.ToUpper(f.Confidence)] < minConfRank {
			continue
		}
		findings = append(findings, f)
		fmt.Printf("[!] %-8s | %-7s | %-12s | %-28s | %s:%d:%d\n    %s\n", f.Severity, f.Confidence, f.Framework, f.RuleID, f.File, f.Line, f.Column, f.Snippet)
	}

	err = <-scanErrChan
	if err != nil {
		log.Printf("Scan encountered an error: %v\n", err)
	}

	if jsonErr := reporter.WriteJSON(findings, *targetDir, *findingsJSONOut); jsonErr != nil {
		log.Printf("[!] Failed to write findings JSON: %v\n", jsonErr)
	}
	if summaryErr := reporter.WriteFrameworkSummaryCSV(findings, *findingsFrameworkCSVOut); summaryErr != nil {
		log.Printf("[!] Failed to write findings framework summary CSV: %v\n", summaryErr)
	}
	if findingsCSVErr := reporter.WriteFindingsCSV(findings, *findingsCSVOut); findingsCSVErr != nil {
		log.Printf("[!] Failed to write findings CSV: %v\n", findingsCSVErr)
	}

	fmt.Println("[*] Scan complete.")
}
