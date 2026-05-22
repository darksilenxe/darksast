package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription *sarifMessage      `json:"shortDescription,omitempty"`
	FullDescription  *sarifMessage      `json:"fullDescription,omitempty"`
	Help             *sarifMessage      `json:"help,omitempty"`
	Properties       *sarifRuleProperty `json:"properties,omitempty"`
}

type sarifRuleProperty struct {
	Tags             []string `json:"tags,omitempty"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Framework        string   `json:"framework,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	CWE              []string `json:"cwe,omitempty"`
	OWASP            []string `json:"owasp,omitempty"`
	References       []string `json:"references,omitempty"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level,omitempty"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations,omitempty"`
	Properties *sarifResultProp `json:"properties,omitempty"`
}

type sarifResultProp struct {
	Framework  string   `json:"framework,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	OWASP      []string `json:"owasp,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   uint32        `json:"startLine"`
	StartColumn uint32        `json:"startColumn,omitempty"`
	EndLine     uint32        `json:"endLine,omitempty"`
	EndColumn   uint32        `json:"endColumn,omitempty"`
	Snippet     *sarifMessage `json:"snippet,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
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

// WriteSARIF writes findings in SARIF 2.1.0 format using rule metadata when available.
func WriteSARIF(findings []engine.Finding, rules []engine.Rule, targetDir string, outputPath string) error {
	ruleIndex := make(map[string]engine.Rule, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.ID) == "" {
			continue
		}
		ruleIndex[rule.ID] = rule
	}

	ruleIDs := make([]string, 0, len(ruleIndex))
	for id := range ruleIndex {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)

	sarifRules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rule := ruleIndex[id]
		description := rule.EffectiveDescription()
		helpText := description
		if strings.TrimSpace(rule.Remediation) != "" {
			helpText = description + "\n\nRemediation: " + strings.TrimSpace(rule.Remediation)
		}
		sarifRules = append(sarifRules, sarifRule{
			ID:               id,
			Name:             description,
			ShortDescription: &sarifMessage{Text: description},
			FullDescription:  &sarifMessage{Text: description},
			Help:             &sarifMessage{Text: helpText},
			Properties: &sarifRuleProperty{
				Tags:             normalizeStringSlice(rule.Tags),
				Precision:        sarifPrecision(rule.EffectiveConfidence()),
				SecuritySeverity: sarifSecuritySeverity(rule.Severity),
				Framework:        defaultFramework(rule.Framework),
				Confidence:       rule.EffectiveConfidence(),
				CWE:              normalizeStringSlice(rule.CWE),
				OWASP:            normalizeStringSlice(rule.OWASP),
				References:       normalizeStringSlice(rule.References),
			},
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		rule, ok := ruleIndex[finding.RuleID]
		messageText := finding.Snippet
		if ok && strings.TrimSpace(rule.EffectiveDescription()) != "" {
			messageText = rule.EffectiveDescription()
		}
		if strings.TrimSpace(messageText) == "" {
			messageText = finding.RuleID
		}
		location := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(targetDir, finding.File)},
				Region: sarifRegion{
					StartLine:   finding.Line,
					StartColumn: finding.Column,
					EndLine:     finding.EndLine,
					EndColumn:   finding.EndColumn,
				},
			},
		}
		if strings.TrimSpace(finding.Snippet) != "" {
			location.PhysicalLocation.Region.Snippet = &sarifMessage{Text: finding.Snippet}
		}

		props := &sarifResultProp{
			Framework:  defaultFramework(finding.Framework),
			Severity:   strings.ToUpper(strings.TrimSpace(finding.Severity)),
			Confidence: defaultConfidence(finding.Confidence),
		}
		if ok {
			props.Tags = normalizeStringSlice(rule.Tags)
			props.CWE = normalizeStringSlice(rule.CWE)
			props.OWASP = normalizeStringSlice(rule.OWASP)
		}

		results = append(results, sarifResult{
			RuleID:     finding.RuleID,
			Level:      sarifLevel(finding.Severity),
			Message:    sarifMessage{Text: messageText},
			Locations:  []sarifLocation{location},
			Properties: props,
		})
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "JavaScript-Security-Scanner",
						InformationURI: "https://github.com/darksilenxe/JavaScript-Scanner",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report data: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write SARIF report to file: %w", err)
	}

	fmt.Printf("[+] Successfully wrote SARIF report to: %s\n", outputPath)
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

	if err := writer.Write([]string{"kind", "file", "line", "column", "end_line", "end_column", "rule_id", "severity", "framework", "snippet", "matched_code", "highlighted_snippet", "confidence", "tags", "description", "category", "taxonomy", "cwe", "owasp", "package_name", "declared_version", "resolved_version", "version_source", "fixed_versions", "references", "remediation", "confidence_rationale", "project_path"}); err != nil {
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
			fmt.Sprintf("%d", finding.EndLine),
			fmt.Sprintf("%d", finding.EndColumn),
			finding.RuleID,
			finding.Severity,
			framework,
			finding.Snippet,
			finding.MatchedCode,
			finding.HighlightedSnippet,
			confidence,
			strings.Join(finding.Tags, ";"),
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

func sarifArtifactURI(targetDir string, findingPath string) string {
	if rel, err := filepath.Rel(targetDir, findingPath); err == nil && rel != "" && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(findingPath)
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func sarifPrecision(confidence string) string {
	switch defaultConfidence(confidence) {
	case "HIGH":
		return "high"
	case "LOW":
		return "low"
	default:
		return "medium"
	}
}

func sarifSecuritySeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "9.0"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.0"
	default:
		return "3.0"
	}
}

func normalizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func defaultFramework(framework string) string {
	if strings.TrimSpace(framework) == "" {
		return "JavaScript"
	}
	return framework
}

func defaultConfidence(confidence string) string {
	if strings.TrimSpace(confidence) == "" {
		return "MEDIUM"
	}
	return strings.ToUpper(strings.TrimSpace(confidence))
}

func normalizeKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "code"
	}
	return strings.ToLower(kind)
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
	summary := make(map[string]int)
	for _, finding := range findings {
		framework := finding.Framework
		if framework == "" {
			framework = "JavaScript"
		}
		summary[framework]++
	}
	if len(summary) == 0 {
		return nil
	}
	return summary
}

func summarizeByCategory(findings []engine.Finding) map[string]int {
	summary := make(map[string]int)
	for _, finding := range findings {
		category := strings.TrimSpace(finding.Category)
		if category == "" {
			continue
		}
		summary[category]++
	}
	if len(summary) == 0 {
		return nil
	}
	return summary
}
