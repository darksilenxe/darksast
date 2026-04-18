// Package integration exercises the fetcher → engine pipeline end to end:
// it stands up an httptest server returning HTML with a vulnerable inline
// script, runs the fetcher, then runs the scan engine over the saved
// directory and asserts the expected rule fires.
package integration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"javascript-security-scanner/internal/engine"
	"javascript-security-scanner/internal/fetcher"
)

const evalRuleYAML = `id: "JS-EVAL-EXEC"
severity: "HIGH"
confidence: "HIGH"
framework: "JavaScript"
description: "Detects direct use of eval()."
query: |
  (call_expression
    function: (identifier) @fn
    (#eq? @fn "eval")
    arguments: (arguments
      (_) @arg
    )
  ) @finding
`

func TestFetchThenScanFindsInlineEval(t *testing.T) {
	html := `<!doctype html><html><head>
<script>var risky = eval(userInput);</script>
</head></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(html))
	}))
	defer srv.Close()

	out := t.TempDir()
	manifest, err := fetcher.Fetch(srv.URL+"/", out, fetcher.Options{SameOriginOnly: true})
	require.NoError(t, err)
	require.GreaterOrEqual(t, manifest.SavedCount(), 1)

	// Materialize a one-rule rules dir for the engine.
	rulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "eval.yaml"), []byte(evalRuleYAML), 0o644))

	rules, err := engine.LoadRules(rulesDir)
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	e := engine.New(rules)
	ch := make(chan engine.Finding, 16)
	go func() { _ = e.ScanDirectory(out, ch) }()

	var findings []engine.Finding
	for f := range ch {
		findings = append(findings, f)
	}

	require.NotEmpty(t, findings, "expected eval() finding from fetched inline script")
	matched := false
	for _, f := range findings {
		if f.RuleID == "JS-EVAL-EXEC" {
			matched = true
			assert.Contains(t, f.File, "inline_1.js")
		}
	}
	assert.True(t, matched, "expected JS-EVAL-EXEC rule to fire")
}
