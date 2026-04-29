package deps

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// PackageJSON defines the fields we want to extract from the file.
type PackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// PackageRecord represents one dependency entry from a discovered manifest.
type PackageRecord struct {
	ProjectPath  string
	ManifestPath string
	Scope        string
	Ecosystem    string
	Name         string
	Version      string
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

var (
	requirementsLineRE = regexp.MustCompile(`^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*([^;\s]+)?`)
	cargoKVRE          = regexp.MustCompile(`^([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"`)
	cargoVersionRE     = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
)

// CheckDependencies prints the legacy React2Shell audit summary across discovered npm manifests.
func CheckDependencies(targetDir string) {
	records, err := CollectPackageRecords(targetDir)
	if err != nil {
		fmt.Printf("[!] Failed to collect manifests for dependency audit: %v\n\n", err)
		return
	}

	npmRecords := make([]PackageRecord, 0)
	for _, record := range records {
		if record.Ecosystem == "npm" {
			npmRecords = append(npmRecords, record)
		}
	}

	if len(npmRecords) == 0 {
		fmt.Printf("[-] No npm package manifests found in %s. Skipping legacy dependency audit.\n\n", targetDir)
		return
	}

	fmt.Println("[*] Auditing discovered npm manifests for React2Shell (CVE-2025-55182) targets...")
	foundVulnerability := false
	for _, record := range npmRecords {
		if _, exists := react2ShellTargetPackages[record.Name]; !exists {
			continue
		}
		if isVulnerableVersion(record.Version) {
			fmt.Printf("   🚨 CRITICAL: %s (%s) in %s is highly vulnerable to remote code execution!\n", record.Name, record.Version, record.ManifestPath)
			foundVulnerability = true
			continue
		}
		fmt.Printf("   [i] Found %s (%s) in %s - Version appears to be outside the primary CVE range, but verify patches.\n", record.Name, record.Version, record.ManifestPath)
	}
	if !foundVulnerability {
		fmt.Println("   [+] No critical React2Shell dependency versions detected.")
	}
	fmt.Println()
}

// CollectPackageRecords scans for supported dependency manifests and returns all discovered records.
func CollectPackageRecords(targetDir string) ([]PackageRecord, error) {
	records := make([]PackageRecord, 0)

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			switch name {
			case "node_modules", ".git", "dist", "build", "vendor", "target", ".next", "coverage":
				return filepath.SkipDir
			}
			return nil
		}

		var parsed []PackageRecord
		switch d.Name() {
		case "package.json":
			parsed = parseNPMManifest(path)
		case "requirements.txt":
			parsed = parseRequirementsManifest(path)
		case "go.mod":
			parsed = parseGoModManifest(path)
		case "Cargo.toml":
			parsed = parseCargoManifest(path)
		default:
			return nil
		}

		records = append(records, parsed...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].ProjectPath != records[j].ProjectPath {
			return records[i].ProjectPath < records[j].ProjectPath
		}
		if records[i].Ecosystem != records[j].Ecosystem {
			return records[i].Ecosystem < records[j].Ecosystem
		}
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Scope != records[j].Scope {
			return records[i].Scope < records[j].Scope
		}
		return records[i].Version < records[j].Version
	})

	return records, nil
}

func parseNPMManifest(path string) []PackageRecord {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil
	}

	var pkg PackageJSON
	if unmarshalErr := json.Unmarshal(data, &pkg); unmarshalErr != nil {
		return nil
	}

	projectPath := filepath.Dir(path)
	records := make([]PackageRecord, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name, version := range pkg.Dependencies {
		records = append(records, PackageRecord{
			ProjectPath:  projectPath,
			ManifestPath: path,
			Scope:        "dependencies",
			Ecosystem:    "npm",
			Name:         name,
			Version:      version,
		})
	}
	for name, version := range pkg.DevDependencies {
		records = append(records, PackageRecord{
			ProjectPath:  projectPath,
			ManifestPath: path,
			Scope:        "devDependencies",
			Ecosystem:    "npm",
			Name:         name,
			Version:      version,
		})
	}
	return records
}

func parseRequirementsManifest(path string) []PackageRecord {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	records := make([]PackageRecord, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		matches := requirementsLineRE.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}
		name := strings.TrimSpace(matches[1])
		version := ""
		if len(matches) > 2 {
			version = strings.TrimSpace(matches[2])
		}
		if name == "" {
			continue
		}
		records = append(records, PackageRecord{
			ProjectPath:  filepath.Dir(path),
			ManifestPath: path,
			Scope:        "dependencies",
			Ecosystem:    "pip",
			Name:         name,
			Version:      version,
		})
	}
	return records
}

func parseGoModManifest(path string) []PackageRecord {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	records := make([]PackageRecord, 0)
	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		entry := line
		if strings.HasPrefix(line, "require ") {
			entry = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inRequireBlock {
			continue
		}
		if idx := strings.Index(entry, "//"); idx >= 0 {
			entry = strings.TrimSpace(entry[:idx])
		}
		fields := strings.Fields(entry)
		if len(fields) < 2 {
			continue
		}
		records = append(records, PackageRecord{
			ProjectPath:  filepath.Dir(path),
			ManifestPath: path,
			Scope:        "dependencies",
			Ecosystem:    "go",
			Name:         fields[0],
			Version:      fields[1],
		})
	}
	return records
}

func parseCargoManifest(path string) []PackageRecord {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	records := make([]PackageRecord, 0)
	scanner := bufio.NewScanner(file)
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}

		scope := ""
		switch section {
		case "dependencies", "workspace.dependencies":
			scope = "dependencies"
		case "dev-dependencies":
			scope = "devDependencies"
		default:
			continue
		}

		if matches := cargoKVRE.FindStringSubmatch(line); len(matches) == 3 {
			records = append(records, PackageRecord{
				ProjectPath:  filepath.Dir(path),
				ManifestPath: path,
				Scope:        scope,
				Ecosystem:    "cargo",
				Name:         strings.TrimSpace(matches[1]),
				Version:      strings.TrimSpace(matches[2]),
			})
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || strings.EqualFold(value, "{ workspace = true }") {
			continue
		}
		matches := cargoVersionRE.FindStringSubmatch(value)
		if len(matches) != 2 {
			continue
		}
		records = append(records, PackageRecord{
			ProjectPath:  filepath.Dir(path),
			ManifestPath: path,
			Scope:        scope,
			Ecosystem:    "cargo",
			Name:         name,
			Version:      strings.TrimSpace(matches[1]),
		})
	}
	return records
}

// DetectFrameworks returns unique framework names found from dependency indicators.
func DetectFrameworks(records []PackageRecord) []string {
	found := make(map[string]struct{})
	for _, record := range records {
		if record.Ecosystem != "npm" {
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

	b.WriteString("| Project Path | Scope | Package | Version |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, record := range records {
		scope := record.Scope
		if record.Ecosystem != "npm" {
			scope = record.Ecosystem + ":" + scope
		}
		b.WriteString("| ")
		b.WriteString(strings.ReplaceAll(record.ProjectPath, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(scope)
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Name, "|", "\\|"))
		b.WriteString(" | ")
		b.WriteString(strings.ReplaceAll(record.Version, "|", "\\|"))
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

	if err := writer.Write([]string{"project_path", "scope", "package", "version"}); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, record := range records {
		scope := record.Scope
		if record.Ecosystem != "npm" {
			scope = record.Ecosystem + ":" + scope
		}
		if err := writer.Write([]string{record.ProjectPath, scope, record.Name, record.Version}); err != nil {
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
		switch record.Scope {
		case "dependencies":
			dependencyCount++
		case "devDependencies":
			devDependencyCount++
		}

		if record.Ecosystem == "npm" {
			if frameworkName, ok := frameworkIndicators[record.Name]; ok {
				frameworkPackageCounts[frameworkName]++
			}
			if _, tracked := react2ShellTargetPackages[record.Name]; tracked && isVulnerableVersion(record.Version) {
				vulnerableEntries = append(vulnerableEntries, fmt.Sprintf("%s@%s (%s)", record.Name, record.Version, record.ProjectPath))
			}
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
	if strings.Contains(version, "19.0.0") || strings.Contains(version, "19.1.0") ||
		strings.Contains(version, "19.1.1") || strings.Contains(version, "19.2.0") {
		return true
	}
	if strings.Contains(version, "15.") || strings.Contains(version, "16.0.") {
		return true
	}
	return false
}
