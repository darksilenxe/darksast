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

// PackageJSON defines the fields we want to extract from the file
type PackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageRecord represents one dependency entry from a discovered package.json file.
type PackageRecord struct {
	ProjectPath string
	Scope       string
	Name        string
	Version     string
}

// SummaryStats captures high-level metrics for CI-friendly reporting.
type SummaryStats struct {
	TotalProjects                int
	TotalPackages                int
	DependencyCount              int
	DevDependencyCount           int
	DetectedFrameworks           []string
	FrameworkPackageCounts       map[string]int
	PotentiallyVulnerableCount   int
	PotentiallyVulnerableEntries []string
}

var react2ShellTargetPackages = map[string]struct{}{
	"react":                      {},
	"react-dom":                  {},
	"next":                       {},
	"react-server-dom-webpack":   {},
	"react-server-dom-turbopack": {},
	"react-server-dom-parcel":    {},
}

var frameworkIndicators = map[string]string{
	"react":            "React",
	"react-dom":        "React",
	"next":             "Next.js",
	"vue":              "Vue",
	"nuxt":             "Nuxt",
	"@angular/core":    "Angular",
	"svelte":           "Svelte",
	"@sveltejs/kit":    "SvelteKit",
	"solid-js":         "SolidJS",
	"preact":           "Preact",
	"ember-source":     "Ember",
	"gatsby":           "Gatsby",
	"@remix-run/react": "Remix",
}

// CheckDependencies parses package.json and flags vulnerable packages
func CheckDependencies(targetDir string) {
	pkgPath := filepath.Join(targetDir, "package.json")

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		fmt.Printf("[-] No package.json found in %s. Skipping dependency audit.\n\n", targetDir)
		return
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		fmt.Printf("[!] Error parsing package.json: %v\n\n", err)
		return
	}

	// Combine dependencies and devDependencies into one map for easy scanning
	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	fmt.Println("[*] Auditing package.json for React2Shell (CVE-2025-55182) targets...")

	// The specific packages compromised in the React2Shell exploit path
	targetPackages := []string{
		"react",
		"react-dom",
		"next",
		"react-server-dom-webpack",
		"react-server-dom-turbopack",
		"react-server-dom-parcel",
	}

	foundVulnerability := false

	for _, pkgName := range targetPackages {
		if version, exists := allDeps[pkgName]; exists {
			// A simplified check for the known vulnerable React 19.x and Next 15.x versions
			if isVulnerableVersion(version) {
				fmt.Printf("   🚨 CRITICAL: %s (%s) is highly vulnerable to remote code execution!\n", pkgName, version)
				foundVulnerability = true
			} else {
				fmt.Printf("   [i] Found %s (%s) - Version appears to be outside the primary CVE range, but verify patches.\n", pkgName, version)
			}
		}
	}

	if !foundVulnerability {
		fmt.Println("   [+] No critical React2Shell dependency versions detected.")
	}
	fmt.Println()
}

// CollectPackageRecords scans for package.json files and returns all dependencies and devDependencies.
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
		for name, version := range pkg.Dependencies {
			records = append(records, PackageRecord{
				ProjectPath: projectPath,
				Scope:       "dependencies",
				Name:        name,
				Version:     version,
			})
		}

		for name, version := range pkg.DevDependencies {
			records = append(records, PackageRecord{
				ProjectPath: projectPath,
				Scope:       "devDependencies",
				Name:        name,
				Version:     version,
			})
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
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Scope < records[j].Scope
	})

	return records, nil
}

// DetectFrameworks returns unique framework names found from dependency indicators.
func DetectFrameworks(records []PackageRecord) []string {
	found := make(map[string]struct{})
	for _, record := range records {
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

	b.WriteString("| Project Path | Scope | Package | Version |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, record := range records {
		b.WriteString("| ")
		b.WriteString(strings.ReplaceAll(record.ProjectPath, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(record.Scope)
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Name, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Version, "|", "\\|"))
		b.WriteString(" |\n")
	}

	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
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

	if err := writer.Write([]string{"project_path", "scope", "package", "version"}); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, record := range records {
		if err := writer.Write([]string{record.ProjectPath, record.Scope, record.Name, record.Version}); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize CSV write: %w", err)
	}

	return nil
}

// BuildSummaryStats derives aggregate metrics from discovered packages.
func BuildSummaryStats(records []PackageRecord, frameworks []string) SummaryStats {
	projectSet := make(map[string]struct{})
	vulnerableEntries := make([]string, 0)
	dependencyCount := 0
	devDependencyCount := 0
	frameworkPackageCounts := make(map[string]int)

	for _, record := range records {
		projectSet[record.ProjectPath] = struct{}{}
		if record.Scope == "dependencies" {
			dependencyCount++
		}
		if record.Scope == "devDependencies" {
			devDependencyCount++
		}

		if frameworkName, ok := frameworkIndicators[record.Name]; ok {
			frameworkPackageCounts[frameworkName]++
		}

		if _, tracked := react2ShellTargetPackages[record.Name]; tracked && isVulnerableVersion(record.Version) {
			vulnerableEntries = append(vulnerableEntries, fmt.Sprintf("%s@%s (%s)", record.Name, record.Version, record.ProjectPath))
		}
	}

	sort.Strings(vulnerableEntries)

	return SummaryStats{
		TotalProjects:                len(projectSet),
		TotalPackages:                len(records),
		DependencyCount:              dependencyCount,
		DevDependencyCount:           devDependencyCount,
		DetectedFrameworks:           frameworks,
		FrameworkPackageCounts:       frameworkPackageCounts,
		PotentiallyVulnerableCount:   len(vulnerableEntries),
		PotentiallyVulnerableEntries: vulnerableEntries,
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
		{"frameworks", "count", fmt.Sprintf("%d", len(summary.DetectedFrameworks))},
		{"frameworks", "names", strings.Join(summary.DetectedFrameworks, ";")},
		{"vulnerability", "react2shell_potential_count", fmt.Sprintf("%d", summary.PotentiallyVulnerableCount)},
		{"vulnerability", "react2shell_potential_entries", strings.Join(summary.PotentiallyVulnerableEntries, ";")},
	}

	for _, frameworkName := range summary.DetectedFrameworks {
		rows = append(rows, []string{
			"frameworks",
			"package_count_" + frameworkMetricName(frameworkName),
			fmt.Sprintf("%d", summary.FrameworkPackageCounts[frameworkName]),
		})
	}

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

// isVulnerableVersion performs basic string matching against known bad versions.
// (Note: In a production tool, replace this with a library like github.com/Masterminds/semver)
func isVulnerableVersion(version string) bool {
	// React 19.0.0, 19.1.0, 19.1.1, 19.2.0 are vulnerable
	if strings.Contains(version, "19.0.0") || strings.Contains(version, "19.1.0") ||
		strings.Contains(version, "19.1.1") || strings.Contains(version, "19.2.0") {
		return true
	}
	// Next.js 15.x and 16.x are vulnerable prior to their specific patch releases
	if strings.Contains(version, "15.") || strings.Contains(version, "16.0.") {
		return true
	}
	return false
}
