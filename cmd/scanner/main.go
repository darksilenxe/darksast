package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	// Adjust this import path based on your actual go.mod module name
	"javascript-security-scanner/internal/deps"
	"javascript-security-scanner/internal/engine"
	"javascript-security-scanner/internal/fetcher"
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
	advisoriesDir := flag.String("advisories", "./advisories", "Directory containing dependency advisory YAML files")
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

	// Optional "fetch from URL" front end. When -url is empty the
	// scanner behaves exactly as before, so existing CLI/script
	// invocations are unaffected.
	pageURL := flag.String("url", "", "Optional URL to download JavaScript from before scanning. When set, inline <script> blocks and same-origin external scripts are saved to -fetch-out and that directory becomes the scan target.")
	fetchOut := flag.String("fetch-out", "./fetched-site", "Directory to write fetched JavaScript into when -url is set")
	fetchTimeout := flag.Duration("fetch-timeout", 30*time.Second, "Per-request HTTP timeout used when fetching JavaScript")
	fetchUserAgent := flag.String("fetch-user-agent", "", "User-Agent header used when fetching JavaScript (defaults to a clearly-identified scanner UA)")
	fetchMaxBytes := flag.Int64("fetch-max-bytes", 5*1024*1024, "Maximum bytes accepted per HTTP response when fetching JavaScript")
	fetchSameOrigin := flag.Bool("fetch-same-origin", true, "Only download external scripts whose host matches the page URL")
	flag.Parse()

	// If a URL was supplied, fetch JavaScript first and redirect the
	// rest of the pipeline at the directory we just populated.
	if strings.TrimSpace(*pageURL) != "" {
		fmt.Printf("[*] Fetching JavaScript from %s into %s ...\n", *pageURL, *fetchOut)
		manifest, err := fetcher.Fetch(*pageURL, *fetchOut, fetcher.Options{
			Timeout:        *fetchTimeout,
			UserAgent:      *fetchUserAgent,
			MaxBytes:       *fetchMaxBytes,
			SameOriginOnly: *fetchSameOrigin,
		})
		if err != nil {
			log.Fatalf("[!] Fetch failed: %v", err)
		}
		fmt.Printf("[+] Fetched %d script(s) to %s (manifest: %s/manifest.json)\n",
			manifest.SavedCount(), *fetchOut, *fetchOut)
		for _, f := range manifest.Files {
			if f.Error != "" {
				log.Printf("[!] Fetch warning for %s: %s", f.LocalFile, f.Error)
			}
		}
		*targetDir = *fetchOut
	}

	fmt.Printf("[*] Target Directory: %s\n", *targetDir)

	// 1. Build a package/version inventory table across discovered JS projects.
	packageRecords, err := deps.CollectPackageRecords(*targetDir)
	advisoryMatches := make([]deps.AdvisoryMatch, 0)
	if err != nil {
		log.Printf("[!] Failed to collect package inventory: %v\n", err)
	} else {
		frameworks := deps.DetectFrameworks(packageRecords)
		advisoryDB, advisoryErr := deps.LoadAdvisories(*advisoriesDir)
		if advisoryErr != nil {
			log.Printf("[!] Failed to load dependency advisories: %v\n", advisoryErr)
		} else {
			advisoryMatches = advisoryDB.Match(packageRecords)
		}
		if writeErr := deps.WritePackageTable(packageRecords, frameworks, *packagesOut); writeErr != nil {
			log.Printf("[!] Failed to write package inventory table: %v\n", writeErr)
		} else {
			fmt.Printf("[+] Package inventory written to %s (%d packages).\n", *packagesOut, len(packageRecords))
			if csvErr := deps.WritePackageCSV(packageRecords, *packagesCSVOut); csvErr != nil {
				log.Printf("[!] Failed to write package inventory CSV: %v\n", csvErr)
			} else {
				fmt.Printf("[+] Package CSV written to %s (%d packages).\n", *packagesCSVOut, len(packageRecords))
			}
			summary := deps.BuildSummaryStats(packageRecords, frameworks, advisoryMatches)
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
			if len(advisoryMatches) == 0 {
				fmt.Println("[*] Matched advisories: none")
			} else {
				fmt.Printf("[*] Matched advisories: %d\n", len(advisoryMatches))
				for _, match := range advisoryMatches {
					fmt.Printf("   🚨 %-8s | %-18s | %s@%s | %s\n", match.Severity, match.AdvisoryID, match.PackageName, match.MatchedVersion, match.ProjectPath)
				}
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
		printFinding(f)
	}

	err = <-scanErrChan
	if err != nil {
		log.Printf("Scan encountered an error: %v\n", err)
	}

	for _, match := range advisoryMatches {
		f := advisoryMatchToFinding(match)
		if minSevRank > 0 && severityRank[strings.ToUpper(f.Severity)] < minSevRank {
			continue
		}
		if minConfRank > 0 && confidenceRank[strings.ToUpper(f.Confidence)] < minConfRank {
			continue
		}
		findings = append(findings, f)
		printFinding(f)
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

	codeCount := 0
	dependencyCount := 0
	for _, finding := range findings {
		if finding.Kind == "dependency" {
			dependencyCount++
			continue
		}
		codeCount++
	}

	fmt.Printf("[*] Scan complete. Findings=%d (code=%d, dependency=%d)\n", len(findings), codeCount, dependencyCount)
}

func advisoryMatchToFinding(match deps.AdvisoryMatch) engine.Finding {
	return engine.Finding{
		Kind:            "dependency",
		RuleID:          match.AdvisoryID,
		Severity:        match.Severity,
		Framework:       dependencyFramework(match.PackageName),
		Confidence:      "HIGH",
		Description:     match.Description,
		Category:        "Dependency Advisory",
		References:      append([]string(nil), match.References...),
		Remediation:     dependencyRemediation(match.FixedVersions),
		PackageName:     match.PackageName,
		DeclaredVersion: match.DeclaredVersion,
		ResolvedVersion: match.ResolvedVersion,
		VersionSource:   match.VersionSource,
		FixedVersions:   append([]string(nil), match.FixedVersions...),
		ProjectPath:     match.ProjectPath,
		Snippet:         match.AdvisoryTitle,
	}
}

func dependencyFramework(packageName string) string {
	if framework, ok := map[string]string{
		"react":                     "React",
		"react-dom":                 "React",
		"next":                      "Next.js",
		"vue":                       "Vue",
		"nuxt":                      "Nuxt",
		"@angular/core":             "Angular",
		"@angular/platform-browser": "Angular",
	}[packageName]; ok {
		return framework
	}
	return "Dependency"
}

func dependencyRemediation(fixedVersions []string) string {
	if len(fixedVersions) == 0 {
		return "Upgrade the affected package to a vendor-patched release."
	}
	return "Upgrade to a fixed version such as " + strings.Join(fixedVersions, ", ") + "."
}

func printFinding(f engine.Finding) {
	if f.Kind == "dependency" {
		version := f.ResolvedVersion
		if version == "" {
			version = f.DeclaredVersion
		}
		fmt.Printf("[!] %-8s | %-7s | %-12s | %-28s | %s@%s (%s)\n    %s\n", f.Severity, f.Confidence, f.Framework, f.RuleID, f.PackageName, version, f.ProjectPath, f.Description)
		return
	}
	fmt.Printf("[!] %-8s | %-7s | %-12s | %-28s | %s:%d:%d\n    %s\n", f.Severity, f.Confidence, f.Framework, f.RuleID, f.File, f.Line, f.Column, f.Snippet)
}
