package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	// Replace with your actual module name from go.mod
	"javascript-security-scanner/internal/engine"
)

// ScanReport represents the final output structure of the tool
type ScanReport struct {
	Timestamp     string           `json:"timestamp"`
	TargetDir     string           `json:"target_directory"`
	TotalFindings int              `json:"total_findings"`
	Findings      []engine.Finding `json:"findings"`
}

// WriteJSON takes a slice of findings and writes them to a formatted JSON file.
func WriteJSON(findings []engine.Finding, targetDir string, outputPath string) error {
	report := ScanReport{
		Timestamp:     time.Now().Format(time.RFC3339),
		TargetDir:     targetDir,
		TotalFindings: len(findings),
		Findings:      findings,
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

	if err := writer.Write([]string{"framework", "severity", "count"}); err != nil {
		return fmt.Errorf("failed to write framework summary CSV header: %w", err)
	}

	counts := make(map[string]map[string]int)
	for _, finding := range findings {
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}

		if _, ok := counts[framework]; !ok {
			counts[framework] = make(map[string]int)
		}
		counts[framework][finding.Severity]++
	}

	frameworks := make([]string, 0, len(counts))
	for framework := range counts {
		frameworks = append(frameworks, framework)
	}
	sort.Strings(frameworks)

	for _, framework := range frameworks {
		severities := make([]string, 0, len(counts[framework]))
		for severity := range counts[framework] {
			severities = append(severities, severity)
		}
		sort.Strings(severities)

		for _, severity := range severities {
			row := []string{framework, severity, fmt.Sprintf("%d", counts[framework][severity])}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write framework summary CSV row: %w", err)
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

	if err := writer.Write([]string{"file", "line", "rule_id", "severity", "framework"}); err != nil {
		return fmt.Errorf("failed to write findings CSV header: %w", err)
	}

	for _, finding := range findings {
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}

		row := []string{
			finding.File,
			fmt.Sprintf("%d", finding.Line),
			finding.RuleID,
			finding.Severity,
			framework,
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
