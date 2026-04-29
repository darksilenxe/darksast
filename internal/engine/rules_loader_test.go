package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRulesSemgrepFormat(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "semgrep.yaml")
	content := `rules:
  - id: SEMGREP-EVAL
    message: Detect eval usage from Semgrep rule format
    severity: ERROR
    languages: [javascript, typescript]
    query: |
      (call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")
      ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "SEMGREP-EVAL", rules[0].ID)
	assert.Equal(t, "HIGH", rules[0].Severity)
	assert.Equal(t, "JavaScript", rules[0].Framework)
	assert.Equal(t, "Detect eval usage from Semgrep rule format", rules[0].Description)
	assert.Contains(t, rules[0].Query, "(call_expression")
}

func TestLoadRulesMetadataFields(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "opengrep.yaml")
	content := `rules:
  - id: OPENGREP-INNERHTML
    message: Detect innerHTML assignment from OpenGrep-style bundle
    severity: WARNING
    languages: [javascript]
    metadata:
      framework: React
      confidence: HIGH
      requires_dependency:
        - react
      category: Cross-Site Scripting
      taxonomy:
        - code-pattern/framework
      cwe:
        - CWE-79
      owasp:
        - A03:2021
      references:
        - https://example.com/react-xss
      remediation: Sanitize before rendering.
      confidence_rationale: React sink.
      # query is intentionally in metadata to validate OpenGrep/Semgrep bundle mapping.
      query: |
        (assignment_expression
          left: (member_expression
            property: (property_identifier) @prop (#eq? @prop "innerHTML")
          )
        ) @finding
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	assert.Equal(t, "OPENGREP-INNERHTML", rules[0].ID)
	assert.Equal(t, "MEDIUM", rules[0].Severity)
	assert.Equal(t, "React", rules[0].Framework)
	assert.Equal(t, "HIGH", rules[0].Confidence)
	assert.Equal(t, []string{"react"}, rules[0].RequiresDependency)
	assert.Equal(t, "Cross-Site Scripting", rules[0].Metadata.Category)
	assert.Equal(t, []string{"code-pattern/framework"}, rules[0].Metadata.Taxonomy)
	assert.Equal(t, []string{"CWE-79"}, rules[0].Metadata.CWE)
	assert.Equal(t, []string{"A03:2021"}, rules[0].Metadata.OWASP)
	assert.Equal(t, []string{"https://example.com/react-xss"}, rules[0].Metadata.References)
	assert.Equal(t, "Sanitize before rendering.", rules[0].Metadata.Remediation)
	assert.Equal(t, "React sink.", rules[0].Metadata.ConfidenceRationale)
	assert.Contains(t, rules[0].Query, "innerHTML")
}

func TestLoadRulesSkipsSemgrepPatternOnlyRules(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "pattern_only.yaml")
	content := `rules:
  - id: SEMGREP-PATTERN-ONLY
    severity: ERROR
    message: Pattern is semgrep syntax, not tree-sitter query
    pattern: eval($X)
`
	require.NoError(t, os.WriteFile(ruleFile, []byte(content), 0o644))

	rules, err := LoadRules(dir)
	require.NoError(t, err)
	assert.Len(t, rules, 0)
}
