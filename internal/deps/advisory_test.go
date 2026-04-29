package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAdvisoriesAndMatchResolvedVersions(t *testing.T) {
	dir := t.TempDir()
	advisoryPath := filepath.Join(dir, "react.yaml")
	content := `id: "CVE-2025-55182"
title: "React issue"
severity: "CRITICAL"
packages:
  - react
affected_ranges:
  - introduced: "19.0.0"
    fixed: "19.2.1"
fixed_versions:
  - "19.2.1"
description: "test advisory"
references:
  - "https://example.com/advisory"
`
	require.NoError(t, os.WriteFile(advisoryPath, []byte(content), 0o644))

	db, err := LoadAdvisories(dir)
	require.NoError(t, err)
	require.Len(t, db.Advisories, 1)

	matches := db.Match([]PackageRecord{{
		ProjectPath:     "tests/sample-site",
		Scope:           "dependencies",
		Name:            "react",
		Version:         "^19.1.0",
		ResolvedVersion: "19.1.0",
		VersionSource:   "package-lock.json",
	}})
	require.Len(t, matches, 1)
	assert.Equal(t, "CVE-2025-55182", matches[0].AdvisoryID)
	assert.Equal(t, "19.1.0", matches[0].MatchedVersion)
	assert.Equal(t, []string{"19.2.1"}, matches[0].FixedVersions)
}

func TestAdvisoryRangeVersionComparison(t *testing.T) {
	rng := AdvisoryRange{Introduced: "15.0.0", Fixed: "15.6.0"}
	assert.True(t, rng.matches("15.5.15"))
	assert.False(t, rng.matches("15.6.0"))
	assert.False(t, rng.matches("14.9.0"))
}
