package deps

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectPackageRecordsPrefersResolvedNPMLockfileAndCapturesTransitives(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "dependencies": {"lodash": "^4.17.20"},
  "devDependencies": {"semver": "^7.5.0"}
}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{
  "name": "sample",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {"lodash": "^4.17.20"},
      "devDependencies": {"semver": "^7.5.0"}
    },
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/semver": {"version": "7.5.0", "dev": true},
    "node_modules/lodash/node_modules/minimist": {"version": "1.2.5"}
  }
}`), 0o644))

	records, err := CollectPackageRecords(root)
	require.NoError(t, err)
	require.Len(t, records, 3)

	byPackage := make(map[string]PackageRecord)
	for _, record := range records {
		byPackage[record.Name] = record
	}

	assert.Equal(t, "4.17.20", byPackage["lodash"].Version)
	assert.True(t, byPackage["lodash"].Resolved)
	assert.Equal(t, "direct", byPackage["lodash"].Relationship)
	assert.Equal(t, "dependencies", byPackage["lodash"].Scope)

	assert.Equal(t, "7.5.0", byPackage["semver"].Version)
	assert.True(t, byPackage["semver"].Resolved)
	assert.Equal(t, "devDependencies", byPackage["semver"].Scope)

	assert.Equal(t, "transitive", byPackage["minimist"].Relationship)
	assert.Equal(t, "lodash > minimist", byPackage["minimist"].DependencyPath)
}

func TestMatchAdvisoriesAndPolicyIgnores(t *testing.T) {
	advisories := []Advisory{
		{
			ID:               "OSS-NPM-LODASH",
			Ecosystem:        "npm",
			Package:          "lodash",
			Severity:         "high",
			Description:      "lodash vulnerability",
			AffectedVersions: []string{"<4.17.21"},
			FixedVersion:     "4.17.21",
			Aliases:          []string{"CVE-2021-23337"},
		},
		{
			ID:               "OSS-NPM-MINIMIST",
			Ecosystem:        "npm",
			Package:          "minimist",
			Severity:         "high",
			Description:      "minimist vulnerability",
			AffectedVersions: []string{">=1.0.0 <1.2.6"},
			FixedVersion:     "1.2.6",
		},
	}
	records := []PackageRecord{
		{
			ProjectPath:    "/repo",
			ManifestPath:   "/repo/package-lock.json",
			Scope:          "dependencies",
			Ecosystem:      "npm",
			Name:           "lodash",
			Version:        "4.17.20",
			Relationship:   "direct",
			DependencyPath: "lodash",
			Resolved:       true,
		},
		{
			ProjectPath:    "/repo",
			ManifestPath:   "/repo/package-lock.json",
			Scope:          "dependencies",
			Ecosystem:      "npm",
			Name:           "minimist",
			Version:        "1.2.5",
			Relationship:   "transitive",
			DependencyPath: "lodash > minimist",
			Resolved:       true,
		},
	}

	findings := MatchAdvisories(records, advisories)
	require.Len(t, findings, 2)
	assert.Equal(t, "Upgrade lodash to 4.17.21 or later.", findings[0].Remediation)
	assert.Contains(t, findings[1].Remediation, "minimist resolves to 1.2.6 or later")

	policy := AdvisoryPolicy{
		Ignores: []AdvisoryIgnore{{
			ID:          "OSS-NPM-MINIMIST",
			Package:     "minimist",
			ProjectPath: "/repo",
			Reason:      "accepted temporarily",
			Expires:     time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		}},
	}
	filtered, ignored := ApplyAdvisoryPolicy(findings, policy, time.Now().UTC())
	require.Len(t, filtered, 1)
	assert.Equal(t, 1, ignored)
	assert.Equal(t, "OSS-NPM-LODASH", filtered[0].AdvisoryID)
}

func TestMatchesVersionConstraintSupportsCommonRangeSyntax(t *testing.T) {
	assert.True(t, matchesVersionConstraint(">=1.0.0 <1.2.6", "1.2.5"))
	assert.False(t, matchesVersionConstraint(">=1.0.0 <1.2.6", "1.2.6"))
	assert.True(t, matchesVersionConstraint("<4.17.21", "4.17.20"))
	assert.True(t, matchesVersionConstraint("^1.2.3", "1.9.0"))
	assert.False(t, matchesVersionConstraint("^1.2.3", "2.0.0"))
	assert.True(t, matchesVersionConstraint("1.2.x", "1.2.9"))
}

func TestConvertGitHubNPMAdvisories(t *testing.T) {
	payload := []githubSecurityAdvisory{
		{
			GHSAID:      "GHSA-35jh-r3h4-6jhm",
			Summary:     "Command Injection in lodash",
			Description: "lodash command injection advisory",
			Severity:    "high",
			Identifiers: []githubAdvisoryIdentifier{
				{Type: "GHSA", Value: "GHSA-35jh-r3h4-6jhm"},
				{Type: "CVE", Value: "CVE-2021-23337"},
			},
			References: []githubAdvisoryReference{
				{URL: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},
			},
			CWEs: []githubAdvisoryCWE{{CWEID: "CWE-77"}},
			CVSS: githubAdvisoryCVSS{Score: 7.2},
			Vulnerabilities: []githubAdvisoryVulnerability{
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "npm", Name: "lodash"},
					VulnerableVersionRange: "< 4.17.21 || >=5.0.0 <5.0.3",
					FirstPatchedVersion: struct {
						Identifier string `json:"identifier"`
					}{Identifier: "4.17.21"},
				},
			},
		},
	}

	advisories := convertGitHubNPMAdvisories(payload)
	require.Len(t, advisories, 1)
	assert.Equal(t, "OSS-NPM-LODASH-GHSA-35JH-R3H4-6JHM", advisories[0].ID)
	assert.Equal(t, "npm", advisories[0].Ecosystem)
	assert.Equal(t, "lodash", advisories[0].Package)
	assert.Equal(t, "HIGH", advisories[0].Severity)
	assert.Equal(t, "4.17.21", advisories[0].FixedVersion)
	assert.Equal(t, []string{"< 4.17.21", ">=5.0.0 <5.0.3"}, advisories[0].AffectedVersions)
	assert.Equal(t, []string{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"}, advisories[0].Aliases)
	assert.Equal(t, []string{"CWE-77"}, advisories[0].CWE)
	assert.Equal(t, "7.2", advisories[0].CVSS)
	assert.Equal(t, "github-advisory-database", advisories[0].Source)
}

func TestHasNextPageLink(t *testing.T) {
	assert.True(t, hasNextPageLink(`<https://api.github.com/advisories?ecosystem=npm&page=2>; rel="next", <https://api.github.com/advisories?ecosystem=npm&page=20>; rel="last"`))
	assert.False(t, hasNextPageLink(`<https://api.github.com/advisories?ecosystem=npm&page=1>; rel="first", <https://api.github.com/advisories?ecosystem=npm&page=20>; rel="last"`))
}
