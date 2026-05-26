package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"javascript-security-scanner/internal/engine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "baseline.json")

	findings := []engine.Finding{
		{RuleID: "A", Fingerprint: "aaaa"},
		{RuleID: "B", Fingerprint: "bbbb"},
		{RuleID: "C", Fingerprint: "aaaa"}, // duplicate, should be deduped
		{RuleID: "D"},                       // no fingerprint, skipped
	}
	require.NoError(t, Write(out, findings))

	loaded, err := Load(out)
	require.NoError(t, err)
	assert.Contains(t, loaded, "aaaa")
	assert.Contains(t, loaded, "bbbb")
	assert.Len(t, loaded, 2, "duplicate fingerprints should not be written twice; empty fingerprints should be skipped")
}

func TestLoadMissingPathReturnsEmpty(t *testing.T) {
	loaded, err := Load("")
	require.NoError(t, err)
	assert.Empty(t, loaded)

	loaded, err = Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	require.NoError(t, err)
	assert.Empty(t, loaded)
}

func TestLoadAcceptsBareArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bare.json")
	require.NoError(t, os.WriteFile(path, []byte(`["aaaa","bbbb"]`), 0o644))

	loaded, err := Load(path)
	require.NoError(t, err)
	assert.Contains(t, loaded, "aaaa")
	assert.Contains(t, loaded, "bbbb")
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`not json at all`), 0o644))
	_, err := Load(path)
	assert.Error(t, err)
}

func TestFilterRemovesKnownFingerprints(t *testing.T) {
	findings := []engine.Finding{
		{RuleID: "A", Fingerprint: "aaaa"},
		{RuleID: "B", Fingerprint: "bbbb"},
		{RuleID: "C", Fingerprint: "cccc"},
		{RuleID: "D"}, // no fingerprint — must be kept (safer default)
	}
	baseline := map[string]struct{}{"aaaa": {}, "cccc": {}}

	kept, matched := Filter(findings, baseline)
	require.Len(t, kept, 2)
	require.Len(t, matched, 2)
	keptIDs := []string{kept[0].RuleID, kept[1].RuleID}
	assert.Contains(t, keptIDs, "B")
	assert.Contains(t, keptIDs, "D")
	matchedIDs := []string{matched[0].RuleID, matched[1].RuleID}
	assert.Contains(t, matchedIDs, "A")
	assert.Contains(t, matchedIDs, "C")
}

func TestFilterEmptyBaselineReturnsAll(t *testing.T) {
	findings := []engine.Finding{{RuleID: "A", Fingerprint: "x"}}
	kept, matched := Filter(findings, nil)
	assert.Equal(t, findings, kept)
	assert.Empty(t, matched)
}

func TestWritePopulatesVersion(t *testing.T) {
	out := filepath.Join(t.TempDir(), "baseline.json")
	require.NoError(t, Write(out, []engine.Finding{{Fingerprint: "abc"}}))
	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var file File
	require.NoError(t, json.Unmarshal(data, &file))
	assert.Equal(t, 1, file.Version)
	assert.Equal(t, []string{"abc"}, file.Fingerprints)
	assert.NotEmpty(t, file.GeneratedAt)
}
