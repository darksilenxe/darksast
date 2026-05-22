package reporter

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"javascript-security-scanner/internal/engine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSARIFIncludesRuleMetadataAndRelativeLocations(t *testing.T) {
	targetDir := t.TempDir()
	sourceFile := filepath.Join(targetDir, "src", "app.js")
	require.NoError(t, os.MkdirAll(filepath.Dir(sourceFile), 0o755))
	require.NoError(t, os.WriteFile(sourceFile, []byte("eval(userInput);\n"), 0o644))

	outputPath := filepath.Join(targetDir, "findings.sarif")
	findings := []engine.Finding{
		{
			File:       sourceFile,
			Line:       1,
			Column:     1,
			EndLine:    1,
			EndColumn:  16,
			RuleID:     "JS-EVAL-EXEC",
			Severity:   "HIGH",
			Framework:  "JavaScript",
			Snippet:    "eval(userInput);",
			Confidence: "HIGH",
		},
	}
	rules := []engine.Rule{
		{
			ID:          "JS-EVAL-EXEC",
			Severity:    "HIGH",
			Framework:   "JavaScript",
			Description: "Detect eval usage",
			Message:     "Avoid eval with attacker-controlled input.",
			Confidence:  "HIGH",
			Tags:        engine.StringList{"injection", "javascript"},
			References:  engine.StringList{"https://example.com/rules/js-eval"},
			CWE:         engine.StringList{"CWE-95"},
			OWASP:       engine.StringList{"A03:2021-Injection"},
			Remediation: "Replace eval with safer parsing or dispatch logic.",
		},
	}

	require.NoError(t, WriteSARIF(findings, rules, targetDir, outputPath))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var report sarifReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Tool.Driver.Rules, 1)
	require.Len(t, report.Runs[0].Results, 1)

	rule := report.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "JS-EVAL-EXEC", rule.ID)
	require.NotNil(t, rule.ShortDescription)
	assert.Equal(t, "Detect eval usage", rule.ShortDescription.Text)
	require.NotNil(t, rule.Help)
	assert.Contains(t, rule.Help.Text, "Remediation:")
	require.NotNil(t, rule.Properties)
	assert.Equal(t, []string{"injection", "javascript"}, rule.Properties.Tags)
	assert.Equal(t, []string{"CWE-95"}, rule.Properties.CWE)
	assert.Equal(t, []string{"A03:2021-Injection"}, rule.Properties.OWASP)
	assert.Equal(t, []string{"https://example.com/rules/js-eval"}, rule.Properties.References)
	assert.Equal(t, "8.0", rule.Properties.SecuritySeverity)
	assert.Equal(t, "high", rule.Properties.Precision)

	result := report.Runs[0].Results[0]
	assert.Equal(t, "JS-EVAL-EXEC", result.RuleID)
	assert.Equal(t, "error", result.Level)
	assert.Equal(t, "Detect eval usage", result.Message.Text)
	require.Len(t, result.Locations, 1)
	assert.Equal(t, "src/app.js", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, uint32(1), result.Locations[0].PhysicalLocation.Region.StartLine)
	assert.Equal(t, uint32(1), result.Locations[0].PhysicalLocation.Region.StartColumn)
	assert.Equal(t, uint32(1), result.Locations[0].PhysicalLocation.Region.EndLine)
	assert.Equal(t, uint32(16), result.Locations[0].PhysicalLocation.Region.EndColumn)
	require.NotNil(t, result.Locations[0].PhysicalLocation.Region.Snippet)
	assert.Equal(t, "eval(userInput);", result.Locations[0].PhysicalLocation.Region.Snippet.Text)
	require.NotNil(t, result.Properties)
	assert.Equal(t, "JavaScript", result.Properties.Framework)
	assert.Equal(t, "HIGH", result.Properties.Confidence)
	assert.Equal(t, []string{"injection", "javascript"}, result.Properties.Tags)
}

func TestWriteFindingsCSVIncludesTagsColumn(t *testing.T) {
	targetDir := t.TempDir()
	outputPath := filepath.Join(targetDir, "findings.csv")
	findings := []engine.Finding{
		{
			Kind:        "code",
			File:        "tests/advanced_rule_coverage.js",
			Line:        12,
			Column:      1,
			EndLine:     12,
			EndColumn:   15,
			RuleID:      "HARDCODED-BEARER-AUTH",
			Severity:    "HIGH",
			Framework:   "Node.js",
			Confidence:  "HIGH",
			Tags:        []string{"secrets", "sensitive-data"},
			Description: "Detects hardcoded Authorization Bearer headers.",
		},
	}

	require.NoError(t, WriteFindingsCSV(findings, outputPath))

	f, err := os.Open(outputPath)
	require.NoError(t, err)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "tags", rows[0][13])
	assert.Equal(t, "secrets;sensitive-data", rows[1][13])
}
