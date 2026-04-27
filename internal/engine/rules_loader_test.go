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
