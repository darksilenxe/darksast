package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"javascript-security-scanner/internal/deps"
)

type AdvisoryReport struct {
	Timestamp     string                 `json:"timestamp"`
	TargetDir     string                 `json:"target_directory"`
	TotalFindings int                    `json:"total_findings"`
	Findings      []deps.AdvisoryFinding `json:"findings"`
}

func WriteAdvisoryJSON(findings []deps.AdvisoryFinding, targetDir string, outputPath string) error {
	report := AdvisoryReport{
		Timestamp:     time.Now().Format(time.RFC3339),
		TargetDir:     targetDir,
		TotalFindings: len(findings),
		Findings:      findings,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal advisory report: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write advisory report: %w", err)
	}
	fmt.Printf("[+] Successfully wrote OSS vulnerability JSON report to: %s\n", outputPath)
	return nil
}

func WriteAdvisoryCSV(findings []deps.AdvisoryFinding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create advisory CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"ecosystem", "package", "version", "fixed_version", "relationship", "dependency_path", "project_path", "manifest_path", "scope", "advisory_id", "aliases", "severity", "title", "description", "source", "cvss", "references", "remediation", "reachability"}); err != nil {
		return fmt.Errorf("failed to write advisory CSV header: %w", err)
	}

	for _, finding := range findings {
		row := []string{
			finding.Ecosystem,
			finding.Package,
			finding.Version,
			finding.FixedVersion,
			finding.Relationship,
			finding.DependencyPath,
			finding.ProjectPath,
			finding.ManifestPath,
			finding.Scope,
			finding.AdvisoryID,
			deps.FormatIdentifiers(finding.AdvisoryID, finding.Aliases),
			finding.Severity,
			finding.Title,
			finding.Description,
			finding.Source,
			finding.CVSS,
			strings.Join(finding.References, ";"),
			finding.Remediation,
			finding.Reachability,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write advisory CSV row: %w", err)
		}
	}
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize advisory CSV write: %w", err)
	}
	fmt.Printf("[+] Successfully wrote OSS vulnerability CSV to: %s\n", outputPath)
	return nil
}

func WriteAdvisorySummaryCSV(findings []deps.AdvisoryFinding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create advisory summary CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"category", "metric", "value"}); err != nil {
		return fmt.Errorf("failed to write advisory summary CSV header: %w", err)
	}

	rows := [][]string{{"oss_vulnerabilities", "total_findings", fmt.Sprintf("%d", len(findings))}}

	bySeverity := make(map[string]int)
	byRelationship := make(map[string]int)
	for _, finding := range findings {
		bySeverity[finding.Severity]++
		byRelationship[finding.Relationship]++
	}

	for _, key := range sortedKeys(bySeverity) {
		rows = append(rows, []string{"oss_vulnerabilities", "severity_" + key, fmt.Sprintf("%d", bySeverity[key])})
	}
	for _, key := range sortedKeys(byRelationship) {
		rows = append(rows, []string{"oss_vulnerabilities", "relationship_" + key, fmt.Sprintf("%d", byRelationship[key])})
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write advisory summary CSV row: %w", err)
		}
	}
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize advisory summary CSV write: %w", err)
	}
	fmt.Printf("[+] Successfully wrote OSS vulnerability summary CSV to: %s\n", outputPath)
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
