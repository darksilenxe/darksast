package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRule builds a Rule with the given id/severity/query and returns it with
// the compiled query pre-warmed so tests don't need the rules directory.
func testRule(id, severity, query string) Rule {
	r := Rule{ID: id, Severity: severity, Query: query}
	if err := r.compile(); err != nil {
		panic("test rule failed to compile: " + err.Error())
	}
	return r
}

var evalRule = testRule(
	"JS-EVAL-EXEC", "HIGH",
	`(call_expression
    function: (identifier) @fn
    (#eq? @fn "eval")
  )`,
)

var innerHTMLRule = testRule(
	"DOM-XSS-INNERHTML-ASSIGN", "HIGH",
	`(assignment_expression
    left: (member_expression
      property: (property_identifier) @prop (#eq? @prop "innerHTML")
    ) @innerhtml_sink
  )`,
)

// writeTemp writes content to a temporary .js file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.js")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

// scanFile is a convenience wrapper that scans a single file and collects findings.
func scanFile(t *testing.T, path string, rules []Rule) []Finding {
	t.Helper()
	e := New(rules)

	// Use ScanDirectory on the parent dir and collect all findings.
	findings := make(chan Finding, 64)
	go func() {
		e.ScanDirectory(filepath.Dir(path), findings)
	}()

	var result []Finding
	for f := range findings {
		result = append(result, f)
	}
	return result
}

// TestEvalLineColumnSnippet verifies that a JS-EVAL-EXEC finding carries the
// correct line number, column, and snippet.
func TestEvalLineColumnSnippet(t *testing.T) {
	// Line 1: blank, Line 2: comment, Line 3: eval call
	src := "\n// evaluate user input\neval(userInput);\n"
	path := writeTemp(t, src)

	findings := scanFile(t, path, []Rule{evalRule})

	require.Len(t, findings, 1, "expected exactly one JS-EVAL-EXEC finding")
	f := findings[0]

	assert.Equal(t, "JS-EVAL-EXEC", f.RuleID)
	assert.EqualValues(t, 3, f.Line, "line number should be 3 (1-based)")
	assert.Greater(t, f.Column, uint32(0), "column should be > 0")
	assert.Contains(t, f.Snippet, "eval(userInput)", "snippet should contain the eval call")
	assert.Equal(t, "eval(userInput)", f.MatchedCode, "matched code should contain exact AST content for the finding")
	assert.Contains(t, f.HighlightedSnippet, "[[DANGEROUS]]eval(userInput)[[/DANGEROUS]]", "highlighted snippet should mark dangerous code")
}

// TestInnerHTMLLineColumnSnippet verifies that a DOM-XSS-INNERHTML-ASSIGN finding
// carries the correct line number, column, and snippet.
func TestInnerHTMLLineColumnSnippet(t *testing.T) {
	// Two lines; innerHTML assignment on line 2.
	src := "var x = document.getElementById('out');\ndocument.body.innerHTML = userInput;\n"
	path := writeTemp(t, src)

	findings := scanFile(t, path, []Rule{innerHTMLRule})

	require.Len(t, findings, 1, "expected exactly one DOM-XSS-INNERHTML-ASSIGN finding")
	f := findings[0]

	assert.Equal(t, "DOM-XSS-INNERHTML-ASSIGN", f.RuleID)
	assert.EqualValues(t, 2, f.Line, "line number should be 2 (1-based)")
	assert.Greater(t, f.Column, uint32(0), "column should be > 0")
	assert.Contains(t, f.Snippet, "innerHTML", "snippet should contain innerHTML")
	assert.Contains(t, f.MatchedCode, "innerHTML", "matched code should include the sink expression")
	assert.Contains(t, f.HighlightedSnippet, "[[DANGEROUS]]", "highlighted snippet should mark dangerous code")
}

// TestExtractSnippet unit-tests the snippet extraction helper directly.
func TestExtractSnippet(t *testing.T) {
	src := []byte("line one\n  line two with leading spaces  \nline three")

	assert.Equal(t, "line one", extractSnippet(src, 0))
	assert.Equal(t, "line two with leading spaces", extractSnippet(src, 1), "leading/trailing whitespace trimmed")
	assert.Equal(t, "line three", extractSnippet(src, 2))
	assert.Equal(t, "", extractSnippet(src, 99), "out-of-range row returns empty string")
}

// TestExtractSnippetTruncation ensures very long lines are capped at 120 chars.
func TestExtractSnippetTruncation(t *testing.T) {
	longLine := make([]byte, 200)
	for i := range longLine {
		longLine[i] = 'a'
	}
	src := longLine

	snippet := extractSnippet(src, 0)
	assert.Len(t, snippet, 123, "120 chars + '...' suffix = 123 total")
	assert.True(t, len(snippet) <= 123)
}

func TestPythonRuleScansPyFiles(t *testing.T) {
	rule := Rule{
		ID:       "PYTHON-EVAL",
		Severity: "HIGH",
		Language: "Python",
		Query: `(call
    function: (identifier) @fn
    (#eq? @fn "eval")
  ) @finding`,
	}
	require.NoError(t, rule.compile())

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.py")
	require.NoError(t, os.WriteFile(path, []byte("eval(user_input)\n"), 0o644))

	findings := scanFile(t, path, []Rule{rule})
	require.Len(t, findings, 1)
	assert.Equal(t, "PYTHON-EVAL", findings[0].RuleID)
}

func TestGoRuleScansGoFiles(t *testing.T) {
	rule := Rule{
		ID:       "GO-EXEC",
		Severity: "HIGH",
		Language: "Go",
		Query: `(call_expression
    function: (selector_expression
      operand: (identifier) @pkg (#eq? @pkg "exec")
      field: (field_identifier) @fn (#eq? @fn "Command")
    )
  ) @finding`,
	}
	require.NoError(t, rule.compile())

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.go")
	require.NoError(t, os.WriteFile(path, []byte("package main\nimport \"os/exec\"\nfunc main(){exec.Command(\"sh\", \"-c\", \"echo hi\")}\n"), 0o644))

	findings := scanFile(t, path, []Rule{rule})
	require.Len(t, findings, 1)
	assert.Equal(t, "GO-EXEC", findings[0].RuleID)
}

func TestRustRuleScansRustFiles(t *testing.T) {
	rule := Rule{
		ID:       "RUST-MD5",
		Severity: "MEDIUM",
		Language: "Rust",
		Query: `(call_expression
    function: (scoped_identifier
      path: (identifier) @mod (#eq? @mod "md5")
      name: (identifier) @fn (#eq? @fn "compute")
    )
  ) @finding`,
	}
	require.NoError(t, rule.compile())

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.rs")
	require.NoError(t, os.WriteFile(path, []byte("fn main(){ let _ = md5::compute(data); }\n"), 0o644))

	findings := scanFile(t, path, []Rule{rule})
	require.Len(t, findings, 1)
	assert.Equal(t, "RUST-MD5", findings[0].RuleID)
}
