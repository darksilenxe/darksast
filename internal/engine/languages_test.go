package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdditionalLanguagesScanFiles(t *testing.T) {
	tests := []struct {
		name   string
		lang   string
		file   string
		src    string
		query  string
		ruleID string
	}{
		{name: "java", lang: "Java", file: "sample.java", src: `class T { void x() { Runtime.getRuntime().exec(cmd); } }`, query: `(method_invocation
  object: (method_invocation
    object: (identifier) @runtime (#eq? @runtime "Runtime")
    name: (identifier) @getter (#eq? @getter "getRuntime")
    arguments: (argument_list)
  )
  name: (identifier) @exec (#eq? @exec "exec")
  arguments: (argument_list)
) @finding`, ruleID: "JAVA-TEST"},
		{name: "php", lang: "PHP", file: "sample.php", src: `<?php eval($input);`, query: `(function_call_expression
  function: (name) @fn (#eq? @fn "eval")
) @finding`, ruleID: "PHP-TEST"},
		{name: "ruby", lang: "Ruby", file: "sample.rb", src: `system(user_input)`, query: `(call
  method: (identifier) @fn (#eq? @fn "system")
) @finding`, ruleID: "RUBY-TEST"},
		{name: "csharp", lang: "C#", file: "sample.cs", src: `class T { void X() { Process.Start(cmd); } }`, query: `(invocation_expression
  function: (member_access_expression
    expression: (identifier) @obj (#eq? @obj "Process")
    name: (identifier) @name (#eq? @name "Start")
  )
) @finding`, ruleID: "CS-TEST"},
		{name: "bash", lang: "Bash", file: "sample.sh", src: `curl -k https://example.com`, query: `(command
  name: (command_name (word) @cmd (#eq? @cmd "curl"))
  argument: (word) @flag (#eq? @flag "-k")
) @finding`, ruleID: "BASH-TEST"},
		{name: "yaml", lang: "YAML", file: "sample.yaml", src: "verify: false\n", query: `(block_mapping_pair
  key: (flow_node (plain_scalar (string_scalar) @key (#eq? @key "verify")))
  value: (flow_node (plain_scalar (boolean_scalar) @value (#eq? @value "false")))
) @finding`, ruleID: "YAML-TEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{ID: tt.ruleID, Severity: "HIGH", Language: tt.lang, Query: tt.query}
			require.NoError(t, rule.compile())

			dir := t.TempDir()
			path := filepath.Join(dir, tt.file)
			require.NoError(t, os.WriteFile(path, []byte(tt.src), 0o644))

			findings := make(chan Finding, 16)
			e := New([]Rule{rule})
			go func() { _ = e.ScanDirectory(dir, findings) }()

			var result []Finding
			for f := range findings {
				result = append(result, f)
			}

			require.Len(t, result, 1)
			assert.Equal(t, tt.ruleID, result[0].RuleID)
		})
	}
}

func TestEngineExcludesConfiguredPaths(t *testing.T) {
	dir := t.TempDir()
	excludedDir := filepath.Join(dir, "rules")
	require.NoError(t, os.MkdirAll(excludedDir, 0o755))
	excludedFile := filepath.Join(excludedDir, "sample.yaml")
	require.NoError(t, os.WriteFile(excludedFile, []byte("verify: false\n"), 0o644))

	rule := Rule{ID: "YAML-TEST", Severity: "HIGH", Language: "YAML", Query: `(block_mapping_pair
  key: (flow_node (plain_scalar (string_scalar) @key (#eq? @key "verify")))
  value: (flow_node (plain_scalar (boolean_scalar) @value (#eq? @value "false")))
) @finding`}
	require.NoError(t, rule.compile())

	e := New([]Rule{rule})
	e.SetExcludedPaths([]string{excludedDir})
	findings := make(chan Finding, 4)
	go func() { _ = e.ScanDirectory(dir, findings) }()

	count := 0
	for range findings {
		count++
	}
	assert.Equal(t, 0, count)
}
