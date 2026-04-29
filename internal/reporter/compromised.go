package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"javascript-security-scanner/internal/deps"
)

type CompromisedPackageReport struct {
	Timestamp     string                    `json:"timestamp"`
	TargetDir     string                    `json:"target_directory"`
	TotalFindings int                       `json:"total_findings"`
	Findings      []deps.CompromisedFinding `json:"findings"`
}

func WriteCompromisedJSON(findings []deps.CompromisedFinding, targetDir string, outputPath string) error {
	report := CompromisedPackageReport{
		Timestamp:     time.Now().Format(time.RFC3339),
		TargetDir:     targetDir,
		TotalFindings: len(findings),
		Findings:      findings,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal compromised package report: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write compromised package report: %w", err)
	}
	fmt.Printf("[+] Successfully wrote compromised package JSON report to: %s\n", outputPath)
	return nil
}

func WriteCompromisedCSV(findings []deps.CompromisedFinding, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create compromised package CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"ecosystem", "package", "version", "project_path", "manifest_path", "scope", "rule_id", "severity", "description", "iocs", "source"}); err != nil {
		return fmt.Errorf("failed to write compromised package CSV header: %w", err)
	}

	for _, finding := range findings {
		row := []string{
			finding.Ecosystem,
			finding.Package,
			finding.Version,
			finding.ProjectPath,
			finding.ManifestPath,
			finding.Scope,
			finding.RuleID,
			finding.Severity,
			finding.Description,
			deps.FormatIOCs(finding.IOCs),
			finding.Source,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write compromised package CSV row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize compromised package CSV write: %w", err)
	}
	fmt.Printf("[+] Successfully wrote compromised package CSV to: %s\n", outputPath)
	return nil
}
