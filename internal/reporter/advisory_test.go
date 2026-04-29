package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"javascript-security-scanner/internal/deps"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAdvisoryReports(t *testing.T) {
	targetDir := t.TempDir()
	jsonPath := filepath.Join(targetDir, "oss_vulnerabilities.json")
	csvPath := filepath.Join(targetDir, "oss_vulnerabilities.csv")
	summaryPath := filepath.Join(targetDir, "oss_vulnerabilities_summary.csv")

	findings := []deps.AdvisoryFinding{{
		AdvisoryID:     "OSS-NPM-LODASH",
		Aliases:        []string{"CVE-2021-23337"},
		Ecosystem:      "npm",
		Package:        "lodash",
		Version:        "4.17.20",
		FixedVersion:   "4.17.21",
		ProjectPath:    targetDir,
		ManifestPath:   filepath.Join(targetDir, "package-lock.json"),
		Scope:          "dependencies",
		Relationship:   "direct",
		DependencyPath: "lodash",
		Severity:       "HIGH",
		Title:          "Prototype Pollution in lodash",
		Description:    "lodash versions before 4.17.21 are affected.",
		References:     []string{"https://example.com/advisory"},
		Source:         "test",
		Remediation:    "Upgrade lodash to 4.17.21 or later.",
		Reachability:   "unknown",
	}}

	require.NoError(t, WriteAdvisoryJSON(findings, targetDir, jsonPath))
	require.NoError(t, WriteAdvisoryCSV(findings, csvPath))
	require.NoError(t, WriteAdvisorySummaryCSV(findings, summaryPath))

	data, err := os.ReadFile(jsonPath)
	require.NoError(t, err)
	var report AdvisoryReport
	require.NoError(t, json.Unmarshal(data, &report))
	require.Len(t, report.Findings, 1)
	assert.Equal(t, "OSS-NPM-LODASH", report.Findings[0].AdvisoryID)

	csvData, err := os.ReadFile(csvPath)
	require.NoError(t, err)
	assert.Contains(t, string(csvData), "fixed_version")
	assert.Contains(t, string(csvData), "Upgrade lodash to 4.17.21 or later.")

	summaryData, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	assert.Contains(t, string(summaryData), "total_findings,1")
	assert.Contains(t, string(summaryData), "relationship_direct,1")
}
