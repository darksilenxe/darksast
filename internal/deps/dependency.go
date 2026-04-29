package deps

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PackageJSON defines the fields we want to extract from the file.
type PackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageRecord represents one dependency entry from a discovered project.
type PackageRecord struct {
	ProjectPath     string
	Scope           string
	Name            string
	Version         string
	ResolvedVersion string
	VersionSource   string
}

func (p PackageRecord) EffectiveVersion() string {
	if p.ResolvedVersion != "" {
		return p.ResolvedVersion
	}
	return normalizeVersion(p.Version)
}

// SummaryStats captures high-level metrics for CI-friendly reporting.
type SummaryStats struct {
	TotalProjects          int
	TotalPackages          int
	DependencyCount        int
	DevDependencyCount     int
	TransitiveCount        int
	ResolvedVersionCount   int
	DetectedFrameworks     []string
	FrameworkPackageCounts map[string]int
	AdvisoryMatches        []AdvisoryMatch
	AdvisoryCounts         map[string]int
	AdvisorySeverities     map[string]int
}

var frameworkIndicators = map[string]string{
	"react":                     "React",
	"react-dom":                 "React",
	"next":                      "Next.js",
	"vue":                       "Vue",
	"nuxt":                      "Nuxt",
	"@angular/core":             "Angular",
	"@angular/platform-browser": "Angular",
	"svelte":                    "Svelte",
	"@sveltejs/kit":             "SvelteKit",
	"solid-js":                  "SolidJS",
	"preact":                    "Preact",
	"ember-source":              "Ember",
	"gatsby":                    "Gatsby",
	"@remix-run/react":          "Remix",
	"express":                   "Express",
	"koa":                       "Node.js",
	"fastify":                   "Node.js",
	"astro":                     "Astro",
	"@astrojs/react":            "Astro",
	"lit":                       "Lit",
	"lit-html":                  "Lit",
	"alpinejs":                  "Alpine.js",
	"@hotwired/stimulus":        "Stimulus",
	"htmx.org":                  "HTMX",
	"backbone":                  "Backbone",
	"mithril":                   "Mithril",
	"@builder.io/qwik":          "Qwik",
	"qwik":                      "Qwik",
	"pinia":                     "Vue",
}

// CollectPackageRecords scans for package.json files and returns direct and resolved dependencies.
func CollectPackageRecords(targetDir string) ([]PackageRecord, error) {
	records := make([]PackageRecord, 0)

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == ".git" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Name() != "package.json" {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		var pkg PackageJSON
		if unmarshalErr := json.Unmarshal(data, &pkg); unmarshalErr != nil {
			return nil
		}

		projectPath := filepath.Dir(path)
		lockfileInventory, lockfileErr := loadProjectLockfile(projectPath)
		if lockfileErr != nil {
			fmt.Printf("[-] Warning: failed to parse lockfile in %s: %v\n", projectPath, lockfileErr)
		}

		directNames := make(map[string]struct{})
		appendRecords := func(scope string, deps map[string]string) {
			for name, version := range deps {
				record := PackageRecord{
					ProjectPath: projectPath,
					Scope:       scope,
					Name:        name,
					Version:     version,
				}
				if lockfileInventory != nil {
					if resolved := lockfileInventory.DirectVersions[name]; resolved != "" {
						record.ResolvedVersion = resolved
						record.VersionSource = lockfileInventory.Source
					} else if versions := lockfileInventory.AllVersions[name]; len(versions) == 1 {
						record.ResolvedVersion = versions[0]
						record.VersionSource = lockfileInventory.Source
					}
				}
				records = append(records, record)
				directNames[name] = struct{}{}
			}
		}

		appendRecords("dependencies", pkg.Dependencies)
		appendRecords("devDependencies", pkg.DevDependencies)

		if lockfileInventory != nil {
			for name, versions := range lockfileInventory.AllVersions {
				if _, ok := directNames[name]; ok {
					continue
				}
				for _, version := range versions {
					records = append(records, PackageRecord{
						ProjectPath:     projectPath,
						Scope:           "transitiveDependencies",
						Name:            name,
						ResolvedVersion: version,
						VersionSource:   lockfileInventory.Source,
					})
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].ProjectPath != records[j].ProjectPath {
			return records[i].ProjectPath < records[j].ProjectPath
		}
		if records[i].Scope != records[j].Scope {
			return records[i].Scope < records[j].Scope
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].ResolvedVersion != records[j].ResolvedVersion {
			return records[i].ResolvedVersion < records[j].ResolvedVersion
		}
		return records[i].Version < records[j].Version
	})

	return records, nil
}

// DetectFrameworks returns unique framework names found from dependency indicators.
func DetectFrameworks(records []PackageRecord) []string {
	found := make(map[string]struct{})
	for _, record := range records {
		if record.Scope == "transitiveDependencies" {
			continue
		}
		if fw, ok := frameworkIndicators[record.Name]; ok {
			found[fw] = struct{}{}
		}
	}

	frameworks := make([]string, 0, len(found))
	for name := range found {
		frameworks = append(frameworks, name)
	}
	sort.Strings(frameworks)
	return frameworks
}

// WritePackageTable writes a markdown-style table to a text file.
func WritePackageTable(records []PackageRecord, frameworks []string, outputPath string) error {
	var b strings.Builder
	b.WriteString("JavaScript Framework and Package Inventory\n")
	b.WriteString("========================================\n\n")

	if len(frameworks) == 0 {
		b.WriteString("Detected frameworks: none\n\n")
	} else {
		b.WriteString("Detected frameworks: ")
		b.WriteString(strings.Join(frameworks, ", "))
		b.WriteString("\n\n")
	}

	b.WriteString("| Project Path | Scope | Package | Declared Version | Resolved Version | Version Source |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, record := range records {
		b.WriteString("| ")
		b.WriteString(strings.ReplaceAll(record.ProjectPath, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(record.Scope)
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Name, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Version, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.ResolvedVersion, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.VersionSource, "|", "\\|"))
		b.WriteString(" |\n")
	}

	if err := os.WriteFile(outputPath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("failed to write package table: %w", err)
	}

	return nil
}

// WritePackageCSV writes package inventory records in CSV format.
func WritePackageCSV(records []PackageRecord, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create package CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"project_path", "scope", "package", "declared_version", "resolved_version", "version_source"}); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, record := range records {
		if err := writer.Write([]string{record.ProjectPath, record.Scope, record.Name, record.Version, record.ResolvedVersion, record.VersionSource}); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize CSV write: %w", err)
	}

	return nil
}

// BuildSummaryStats derives aggregate metrics from discovered packages.
func BuildSummaryStats(records []PackageRecord, frameworks []string, advisoryMatches []AdvisoryMatch) SummaryStats {
	projectSet := make(map[string]struct{})
	dependencyCount := 0
	devDependencyCount := 0
	transitiveCount := 0
	resolvedCount := 0
	frameworkPackageCounts := make(map[string]int)
	advisoryCounts := make(map[string]int)
	advisorySeverities := make(map[string]int)

	for _, record := range records {
		projectSet[record.ProjectPath] = struct{}{}
		switch record.Scope {
		case "dependencies":
			dependencyCount++
		case "devDependencies":
			devDependencyCount++
		case "transitiveDependencies":
			transitiveCount++
		}
		if record.ResolvedVersion != "" {
			resolvedCount++
		}
		if record.Scope != "transitiveDependencies" {
			if frameworkName, ok := frameworkIndicators[record.Name]; ok {
				frameworkPackageCounts[frameworkName]++
			}
		}
	}

	for _, match := range advisoryMatches {
		advisoryCounts[match.AdvisoryID]++
		advisorySeverities[normalizeSeverity(match.Severity)]++
	}

	return SummaryStats{
		TotalProjects:          len(projectSet),
		TotalPackages:          len(records),
		DependencyCount:        dependencyCount,
		DevDependencyCount:     devDependencyCount,
		TransitiveCount:        transitiveCount,
		ResolvedVersionCount:   resolvedCount,
		DetectedFrameworks:     frameworks,
		FrameworkPackageCounts: frameworkPackageCounts,
		AdvisoryMatches:        advisoryMatches,
		AdvisoryCounts:         advisoryCounts,
		AdvisorySeverities:     advisorySeverities,
	}
}

// WriteSummaryCSV writes flattened summary metrics for CI dashboards.
func WriteSummaryCSV(summary SummaryStats, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create summary CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"category", "metric", "value"}); err != nil {
		return fmt.Errorf("failed to write summary CSV header: %w", err)
	}

	rows := [][]string{
		{"inventory", "total_projects", fmt.Sprintf("%d", summary.TotalProjects)},
		{"inventory", "total_packages", fmt.Sprintf("%d", summary.TotalPackages)},
		{"inventory", "dependencies", fmt.Sprintf("%d", summary.DependencyCount)},
		{"inventory", "dev_dependencies", fmt.Sprintf("%d", summary.DevDependencyCount)},
		{"inventory", "transitive_dependencies", fmt.Sprintf("%d", summary.TransitiveCount)},
		{"inventory", "resolved_versions", fmt.Sprintf("%d", summary.ResolvedVersionCount)},
		{"frameworks", "count", fmt.Sprintf("%d", len(summary.DetectedFrameworks))},
		{"frameworks", "names", strings.Join(summary.DetectedFrameworks, ";")},
		{"advisories", "match_count", fmt.Sprintf("%d", len(summary.AdvisoryMatches))},
	}

	severityKeys := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, severity := range severityKeys {
		rows = append(rows, []string{"advisories", "severity_" + strings.ToLower(severity), fmt.Sprintf("%d", summary.AdvisorySeverities[severity])})
	}

	for _, frameworkName := range summary.DetectedFrameworks {
		rows = append(rows, []string{
			"frameworks",
			"package_count_" + frameworkMetricName(frameworkName),
			fmt.Sprintf("%d", summary.FrameworkPackageCounts[frameworkName]),
		})
	}

	if len(summary.AdvisoryMatches) > 0 {
		entries := make([]string, 0, len(summary.AdvisoryMatches))
		for _, match := range summary.AdvisoryMatches {
			entries = append(entries, fmt.Sprintf("%s:%s@%s (%s)", match.AdvisoryID, match.PackageName, match.MatchedVersion, match.ProjectPath))
		}
		rows = append(rows, []string{"advisories", "entries", strings.Join(entries, ";")})
	}

	for advisoryID, count := range summary.AdvisoryCounts {
		rows = append(rows, []string{"advisories", "count_" + frameworkMetricName(advisoryID), fmt.Sprintf("%d", count)})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0] < rows[j][0]
		}
		return rows[i][1] < rows[j][1]
	})

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write summary CSV row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize summary CSV write: %w", err)
	}

	return nil
}

func frameworkMetricName(name string) string {
	metric := strings.ToLower(name)
	metric = strings.ReplaceAll(metric, ".", "")
	metric = strings.ReplaceAll(metric, "-", "_")
	metric = strings.ReplaceAll(metric, " ", "_")
	metric = strings.ReplaceAll(metric, "/", "_")
	return metric
}
