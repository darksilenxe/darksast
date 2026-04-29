package deps

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectPackageRecordsIncludesMultipleEcosystems(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "dependencies": {"axios": "^1.14.1"},
  "devDependencies": {"chalk": "5.6.1"}
}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.32.0\nflask>=3.0.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module sample\n\nrequire github.com/example/lib v1.2.3\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte("[dependencies]\nserde = \"1.0.210\"\n[dev-dependencies]\ntokio = { version = \"1.40.0\" }\n"), 0o644))

	records, err := CollectPackageRecords(root)
	require.NoError(t, err)
	require.Len(t, records, 7)

	seen := map[string]bool{}
	for _, record := range records {
		seen[record.Ecosystem+":"+record.Name] = true
	}
	assert.True(t, seen["npm:axios"])
	assert.True(t, seen["npm:chalk"])
	assert.True(t, seen["pip:requests"])
	assert.True(t, seen["go:github.com/example/lib"])
	assert.True(t, seen["cargo:serde"])
	assert.True(t, seen["cargo:tokio"])
}

func TestLoadAndMatchCompromisedRules(t *testing.T) {
	root := t.TempDir()
	rulesPath := filepath.Join(root, "compromised.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(`rules:
  - id: TEST-NPM
    ecosystem: npm
    package: axios
    versions: [1.14.1]
    severity: critical
    description: test npm compromise
    iocs:
      - type: domain
        value: example.invalid
  - id: TEST-PIP
    ecosystem: pip
    package: requests
    versions: [2.32.0]
    severity: high
    description: test pip compromise
`), 0o644))

	rules, err := LoadCompromisedRules(rulesPath)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	records := []PackageRecord{
		{Ecosystem: "npm", Name: "axios", Version: "^1.14.1", ProjectPath: "/repo", ManifestPath: "/repo/package.json", Scope: "dependencies"},
		{Ecosystem: "pip", Name: "requests", Version: "==2.32.0", ProjectPath: "/repo", ManifestPath: "/repo/requirements.txt", Scope: "dependencies"},
	}

	findings := MatchCompromisedPackages(records, rules)
	require.Len(t, findings, 2)
	assert.Equal(t, "TEST-NPM", findings[0].RuleID)
	assert.Equal(t, "domain:example.invalid", FormatIOCs(findings[0].IOCs))
	assert.Equal(t, "TEST-PIP", findings[1].RuleID)
}

func TestFetchCompromisedRulesFromJSONFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rules":[{"id":"TEST-GO","ecosystem":"go","package":"github.com/example/lib","versions":["1.2.3"],"severity":"high","description":"go compromise"}]}`))
	}))
	defer srv.Close()

	rules, err := FetchCompromisedRules(srv.URL, CompromisedFeedOptions{})
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "go", rules[0].Ecosystem)
	assert.Equal(t, "HIGH", rules[0].Severity)
}

func TestWriteCompromisedRulesYAML(t *testing.T) {
	out := filepath.Join(t.TempDir(), "generated.yaml")
	err := WriteCompromisedRulesYAML(out, []CompromisedPackageRule{{
		ID:          "TEST-CARGO",
		Ecosystem:   "cargo",
		Package:     "serde",
		Versions:    []string{"1.0.210"},
		Severity:    "critical",
		Description: "cargo compromise",
	}})
	require.NoError(t, err)
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), "TEST-CARGO")
	assert.Contains(t, string(data), "serde")
}
