package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	// Replace with your actual module name from go.mod
	"javascript-security-scanner/internal/engine"
)

// ScanReport represents the final output structure of the tool
type ScanReport struct {
	Timestamp              string           `json:"timestamp"`
	TargetDir              string           `json:"target_directory"`
	TotalFindings          int              `json:"total_findings"`
	CodeFindings           int              `json:"code_findings"`
	DependencyFindings     int              `json:"dependency_findings"`
	FrameworkSummary       map[string]int   `json:"framework_summary,omitempty"`
	FindingCategorySummary map[string]int   `json:"finding_category_summary,omitempty"`
	Findings               []engine.Finding `json:"findings"`
}

// WriteJSON takes a slice of findings and writes them to a formatted JSON file.
func WriteJSON(findings []engine.Finding, targetDir string, outputPath string) error {
	report := ScanReport{
		Timestamp:              time.Now().Format(time.RFC3339),
		TargetDir:              targetDir,
		TotalFindings:          len(findings),
		CodeFindings:           countFindingsByKind(findings, "code"),
		DependencyFindings:     countFindingsByKind(findings, "dependency"),
		FrameworkSummary:       summarizeByFramework(findings),
		FindingCategorySummary: summarizeByCategory(findings),
		Findings:               findings,
	}

	// MarshalIndent creates beautifully formatted, human-readable JSON
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report data: %w", err)
	}

	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report to file: %w", err)
	}

	fmt.Printf("[+] Successfully wrote JSON report to: %s\n", outputPath)
	return nil
}

// WriteFrameworkSummaryCSV writes a framework-severity breakdown for CI/reporting pipelines.
func WriteFrameworkSummaryCSV(findings []engine.Finding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create framework summary CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"kind", "framework", "severity", "count", "confidence"}); err != nil {
		return fmt.Errorf("failed to write framework summary CSV header: %w", err)
	}

	counts := make(map[string]map[string]map[string]map[string]int)
	for _, finding := range findings {
		kind := finding.Kind
		if kind == "" {
			kind = "code"
		}
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}
		confidence := finding.Confidence
		if confidence == "" {
			confidence = "MEDIUM"
		}

		if _, ok := counts[kind]; !ok {
			counts[kind] = make(map[string]map[string]map[string]int)
		}
		if _, ok := counts[kind][framework]; !ok {
			counts[kind][framework] = make(map[string]map[string]int)
		}
		if _, ok := counts[kind][framework][finding.Severity]; !ok {
			counts[kind][framework][finding.Severity] = make(map[string]int)
		}
		counts[kind][framework][finding.Severity][confidence]++
	}

	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	for _, kind := range kinds {
		frameworks := make([]string, 0, len(counts[kind]))
		for framework := range counts[kind] {
			frameworks = append(frameworks, framework)
		}
		sort.Strings(frameworks)

		for _, framework := range frameworks {
			severities := make([]string, 0, len(counts[kind][framework]))
			for severity := range counts[kind][framework] {
				severities = append(severities, severity)
			}
			sort.Strings(severities)

			for _, severity := range severities {
				confidences := make([]string, 0, len(counts[kind][framework][severity]))
				for confidence := range counts[kind][framework][severity] {
					confidences = append(confidences, confidence)
				}
				sort.Strings(confidences)
				for _, confidence := range confidences {
					row := []string{kind, framework, severity, fmt.Sprintf("%d", counts[kind][framework][severity][confidence]), confidence}
					if err := writer.Write(row); err != nil {
						return fmt.Errorf("failed to write framework summary CSV row: %w", err)
					}
				}
			}
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize framework summary CSV write: %w", err)
	}

	fmt.Printf("[+] Successfully wrote framework summary CSV to: %s\n", outputPath)
	return nil
}

// WriteFindingsCSV writes one CSV row per finding for BI/SQL ingestion.
func WriteFindingsCSV(findings []engine.Finding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create findings CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"kind", "file", "line", "column", "rule_id", "severity", "framework", "snippet", "confidence", "description", "category", "taxonomy", "cwe", "owasp", "package_name", "declared_version", "resolved_version", "version_source", "fixed_versions", "references", "remediation", "confidence_rationale", "project_path"}); err != nil {
		return fmt.Errorf("failed to write findings CSV header: %w", err)
	}

	for _, finding := range findings {
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}

		confidence := finding.Confidence
		if confidence == "" {
			confidence = "MEDIUM"
		}

		row := []string{
			normalizeKind(finding.Kind),
			finding.File,
			fmt.Sprintf("%d", finding.Line),
			fmt.Sprintf("%d", finding.Column),
			finding.RuleID,
			finding.Severity,
			framework,
			finding.Snippet,
			confidence,
			finding.Description,
			finding.Category,
			strings.Join(finding.Taxonomy, ";"),
			strings.Join(finding.CWE, ";"),
			strings.Join(finding.OWASP, ";"),
			finding.PackageName,
			finding.DeclaredVersion,
			finding.ResolvedVersion,
			finding.VersionSource,
			strings.Join(finding.FixedVersions, ";"),
			strings.Join(finding.References, ";"),
			finding.Remediation,
			finding.ConfidenceRationale,
			finding.ProjectPath,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write findings CSV row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize findings CSV write: %w", err)
	}

	fmt.Printf("[+] Successfully wrote findings CSV to: %s\n", outputPath)
	return nil
}

func countFindingsByKind(findings []engine.Finding, kind string) int {
	count := 0
	for _, finding := range findings {
		if normalizeKind(finding.Kind) == kind {
			count++
		}
	}
	return count
}

func summarizeByFramework(findings []engine.Finding) map[string]int {
	out := make(map[string]int)
	for _, finding := range findings {
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}
		out[framework]++
	}
	return out
}

func summarizeByCategory(findings []engine.Finding) map[string]int {
	out := make(map[string]int)
	for _, finding := range findings {
		category := finding.Category
		if category == "" {
			category = normalizeKind(finding.Kind)
		}
		out[category]++
	}
	return out
}

func normalizeKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "code"
	}
	return kind
}
