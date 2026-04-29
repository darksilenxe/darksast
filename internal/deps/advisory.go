package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type AdvisoryRange struct {
	Introduced string `yaml:"introduced"`
	Fixed      string `yaml:"fixed"`
	Min        string `yaml:"min"`
	Max        string `yaml:"max"`
}

type Advisory struct {
	ID             string          `yaml:"id"`
	Title          string          `yaml:"title"`
	Severity       string          `yaml:"severity"`
	Packages       []string        `yaml:"packages"`
	AffectedRanges []AdvisoryRange `yaml:"affected_ranges"`
	FixedVersions  []string        `yaml:"fixed_versions"`
	Description    string          `yaml:"description"`
	References     []string        `yaml:"references"`
}

type advisoryDocument struct {
	Advisories []Advisory `yaml:"advisories"`
}

type AdvisoryDatabase struct {
	Advisories   []Advisory
	packageIndex map[string][]Advisory
}

type AdvisoryMatch struct {
	AdvisoryID      string
	AdvisoryTitle   string
	Severity        string
	Description     string
	PackageName     string
	ProjectPath     string
	Scope           string
	DeclaredVersion string
	ResolvedVersion string
	MatchedVersion  string
	VersionSource   string
	FixedVersions   []string
	References      []string
}

func LoadAdvisories(advisoriesDir string) (*AdvisoryDatabase, error) {
	db := &AdvisoryDatabase{packageIndex: make(map[string][]Advisory)}

	info, err := os.Stat(advisoriesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, fmt.Errorf("failed to stat advisories dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("advisories path is not a directory: %s", advisoriesDir)
	}

	err = filepath.WalkDir(advisoriesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("failed to read advisory file %s: %w", path, readErr)
		}

		var single Advisory
		if unmarshalErr := yaml.Unmarshal(data, &single); unmarshalErr != nil {
			return fmt.Errorf("failed to parse advisory YAML %s: %w", path, unmarshalErr)
		}
		if strings.TrimSpace(single.ID) != "" {
			db.addAdvisory(single)
			return nil
		}

		var doc advisoryDocument
		if unmarshalErr := yaml.Unmarshal(data, &doc); unmarshalErr != nil {
			return fmt.Errorf("failed to parse advisory bundle YAML %s: %w", path, unmarshalErr)
		}
		for _, advisory := range doc.Advisories {
			db.addAdvisory(advisory)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(db.Advisories, func(i, j int) bool {
		if severityOrder(db.Advisories[i].Severity) != severityOrder(db.Advisories[j].Severity) {
			return severityOrder(db.Advisories[i].Severity) > severityOrder(db.Advisories[j].Severity)
		}
		return db.Advisories[i].ID < db.Advisories[j].ID
	})
	return db, nil
}

func (db *AdvisoryDatabase) addAdvisory(advisory Advisory) {
	advisory.ID = strings.TrimSpace(advisory.ID)
	advisory.Title = strings.TrimSpace(advisory.Title)
	advisory.Description = strings.TrimSpace(advisory.Description)
	advisory.Severity = normalizeSeverity(advisory.Severity)
	for idx := range advisory.Packages {
		advisory.Packages[idx] = strings.TrimSpace(advisory.Packages[idx])
	}
	for idx := range advisory.FixedVersions {
		advisory.FixedVersions[idx] = normalizeVersion(advisory.FixedVersions[idx])
	}
	db.Advisories = append(db.Advisories, advisory)
	for _, pkg := range advisory.Packages {
		if pkg == "" {
			continue
		}
		db.packageIndex[pkg] = append(db.packageIndex[pkg], advisory)
	}
}

func (db *AdvisoryDatabase) Match(records []PackageRecord) []AdvisoryMatch {
	if db == nil || len(db.packageIndex) == 0 || len(records) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	matches := make([]AdvisoryMatch, 0)
	for _, record := range records {
		advisories := db.packageIndex[record.Name]
		if len(advisories) == 0 {
			continue
		}
		matchedVersion := record.EffectiveVersion()
		if matchedVersion == "" {
			continue
		}
		for _, advisory := range advisories {
			if !advisory.matchesVersion(matchedVersion) {
				continue
			}
			key := strings.Join([]string{advisory.ID, record.ProjectPath, record.Scope, record.Name, matchedVersion}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, AdvisoryMatch{
				AdvisoryID:      advisory.ID,
				AdvisoryTitle:   advisory.Title,
				Severity:        advisory.Severity,
				Description:     advisory.Description,
				PackageName:     record.Name,
				ProjectPath:     record.ProjectPath,
				Scope:           record.Scope,
				DeclaredVersion: record.Version,
				ResolvedVersion: record.ResolvedVersion,
				MatchedVersion:  matchedVersion,
				VersionSource:   record.VersionSource,
				FixedVersions:   append([]string(nil), advisory.FixedVersions...),
				References:      append([]string(nil), advisory.References...),
			})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if severityOrder(matches[i].Severity) != severityOrder(matches[j].Severity) {
			return severityOrder(matches[i].Severity) > severityOrder(matches[j].Severity)
		}
		if matches[i].AdvisoryID != matches[j].AdvisoryID {
			return matches[i].AdvisoryID < matches[j].AdvisoryID
		}
		if matches[i].ProjectPath != matches[j].ProjectPath {
			return matches[i].ProjectPath < matches[j].ProjectPath
		}
		if matches[i].PackageName != matches[j].PackageName {
			return matches[i].PackageName < matches[j].PackageName
		}
		return matches[i].MatchedVersion < matches[j].MatchedVersion
	})

	return matches
}

func (a Advisory) matchesVersion(version string) bool {
	version = normalizeVersion(version)
	if version == "" {
		return false
	}
	if len(a.AffectedRanges) == 0 {
		return false
	}
	for _, rng := range a.AffectedRanges {
		if rng.matches(version) {
			return true
		}
	}
	return false
}

func (r AdvisoryRange) matches(version string) bool {
	if version == "" {
		return false
	}
	if introduced := normalizeVersion(r.Introduced); introduced != "" && compareVersions(version, introduced) < 0 {
		return false
	}
	if min := normalizeVersion(r.Min); min != "" && compareVersions(version, min) < 0 {
		return false
	}
	if fixed := normalizeVersion(r.Fixed); fixed != "" && compareVersions(version, fixed) >= 0 {
		return false
	}
	if max := normalizeVersion(r.Max); max != "" && compareVersions(version, max) > 0 {
		return false
	}
	return true
}

var versionPattern = regexp.MustCompile(`\d+(?:\.\d+){0,3}`)

func normalizeVersion(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "||") {
		raw = strings.Split(raw, "||")[0]
	}
	if idx := strings.Index(raw, " "); idx >= 0 {
		raw = raw[:idx]
	}
	raw = strings.TrimLeft(raw, "^~<>=v")
	match := versionPattern.FindString(raw)
	if match == "" {
		return ""
	}
	parts := strings.Split(match, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, ".")
}

func compareVersions(left, right string) int {
	left = normalizeVersion(left)
	right = normalizeVersion(right)
	if left == right {
		return 0
	}
	lp := strings.Split(left, ".")
	rp := strings.Split(right, ".")
	for len(lp) < 3 {
		lp = append(lp, "0")
	}
	for len(rp) < 3 {
		rp = append(rp, "0")
	}
	for idx := 0; idx < 3; idx++ {
		li, _ := strconv.Atoi(lp[idx])
		ri, _ := strconv.Atoi(rp[idx])
		if li < ri {
			return -1
		}
		if li > ri {
			return 1
		}
	}
	return 0
}

func normalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return strings.ToUpper(strings.TrimSpace(severity))
	default:
		return "MEDIUM"
	}
}

func severityOrder(severity string) int {
	switch normalizeSeverity(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
