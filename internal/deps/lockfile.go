package deps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type lockfileInventory struct {
	Source         string
	DirectVersions map[string]string
	AllVersions    map[string][]string
}

func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, `"'`)
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		version = version[1:]
	}
	return strings.TrimSpace(version)
}

func loadProjectLockfile(projectPath string) (*lockfileInventory, error) {
	candidates := []struct {
		name   string
		loader func(string) (*lockfileInventory, error)
	}{
		{name: "package-lock.json", loader: parsePackageLockFile},
		{name: "npm-shrinkwrap.json", loader: parsePackageLockFile},
		{name: "pnpm-lock.yaml", loader: parsePnpmLockFile},
		{name: "yarn.lock", loader: parseYarnLockFile},
	}

	for _, candidate := range candidates {
		path := filepath.Join(projectPath, candidate.name)
		if _, err := os.Stat(path); err == nil {
			return candidate.loader(path)
		}
	}
	return nil, nil
}

type npmLockfile struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	Dependencies map[string]npmLockDependency `json:"dependencies"`
}

type npmLockDependency struct {
	Version      string                       `json:"version"`
	Dependencies map[string]npmLockDependency `json:"dependencies"`
}

func parsePackageLockFile(path string) (*lockfileInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse package lock %s: %w", path, err)
	}
	inv := &lockfileInventory{
		Source:         filepath.Base(path),
		DirectVersions: make(map[string]string),
		AllVersions:    make(map[string][]string),
	}
	for name, dep := range lock.Dependencies {
		if dep.Version != "" {
			inv.DirectVersions[name] = dep.Version
		}
		walkNpmDependencyTree(name, dep, inv.AllVersions)
	}
	for pkgPath, pkg := range lock.Packages {
		if pkgPath == "" || pkg.Version == "" {
			continue
		}
		name := packageNameFromNodeModulesPath(pkgPath)
		if name == "" {
			continue
		}
		appendUniqueVersion(inv.AllVersions, name, pkg.Version)
		if _, ok := inv.DirectVersions[name]; !ok && strings.Count(pkgPath, "node_modules/") == 1 {
			inv.DirectVersions[name] = pkg.Version
		}
	}
	normalizeVersionMaps(inv)
	return inv, nil
}

func walkNpmDependencyTree(name string, dep npmLockDependency, versions map[string][]string) {
	if name != "" && dep.Version != "" {
		appendUniqueVersion(versions, name, dep.Version)
	}
	for childName, child := range dep.Dependencies {
		walkNpmDependencyTree(childName, child, versions)
	}
}

type pnpmLockfile struct {
	Importers map[string]map[string]any `yaml:"importers"`
	Packages  map[string]map[string]any `yaml:"packages"`
}

func parsePnpmLockFile(path string) (*lockfileInventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse pnpm lock %s: %w", path, err)
	}
	inv := &lockfileInventory{
		Source:         filepath.Base(path),
		DirectVersions: make(map[string]string),
		AllVersions:    make(map[string][]string),
	}
	for key := range lock.Packages {
		name, version := packageFromVersionKey(key)
		if name != "" && version != "" {
			appendUniqueVersion(inv.AllVersions, name, version)
		}
	}
	for _, importer := range lock.Importers {
		for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			deps, _ := importer[section].(map[string]any)
			for name, raw := range deps {
				if version := extractPnpmVersion(raw); version != "" {
					inv.DirectVersions[name] = version
					appendUniqueVersion(inv.AllVersions, name, version)
				}
			}
		}
	}
	normalizeVersionMaps(inv)
	return inv, nil
}

func extractPnpmVersion(raw any) string {
	switch value := raw.(type) {
	case string:
		return normalizeVersion(value)
	case map[string]any:
		if version, ok := value["version"].(string); ok {
			return normalizeVersion(version)
		}
	}
	return ""
}

func parseYarnLockFile(path string) (*lockfileInventory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	inv := &lockfileInventory{
		Source:         filepath.Base(path),
		DirectVersions: make(map[string]string),
		AllVersions:    make(map[string][]string),
	}

	scanner := bufio.NewScanner(file)
	selectors := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			selectors = selectors[:0]
			for _, selector := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				selector = strings.Trim(strings.TrimSpace(selector), `"'`)
				if selector != "" {
					selectors = append(selectors, selector)
				}
			}
			continue
		}
		if strings.HasPrefix(trimmed, "version ") {
			version := normalizeVersion(strings.TrimSpace(strings.TrimPrefix(trimmed, "version ")))
			for _, selector := range selectors {
				name := packageNameFromYarnSelector(selector)
				if name != "" && version != "" {
					appendUniqueVersion(inv.AllVersions, name, version)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse yarn lock %s: %w", path, err)
	}
	normalizeVersionMaps(inv)
	return inv, nil
}

func packageNameFromNodeModulesPath(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx == -1 {
		return ""
	}
	name := path[idx+len("node_modules/"):]
	name = strings.TrimPrefix(name, "/")
	parts := strings.Split(name, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func packageNameFromYarnSelector(selector string) string {
	selector = strings.Trim(strings.TrimSpace(selector), `"'`)
	if selector == "" {
		return ""
	}
	if idx := strings.LastIndex(selector, "@npm:"); idx > 0 {
		selector = selector[:idx]
	}
	idx := strings.LastIndex(selector, "@")
	if idx <= 0 {
		return ""
	}
	return selector[:idx]
}

func packageFromVersionKey(key string) (string, string) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if key == "" {
		return "", ""
	}
	idx := strings.LastIndex(key, "@")
	if idx <= 0 {
		return "", ""
	}
	return key[:idx], normalizeVersion(key[idx+1:])
}

func appendUniqueVersion(dst map[string][]string, name, version string) {
	version = normalizeVersion(version)
	if name == "" || version == "" {
		return
	}
	for _, existing := range dst[name] {
		if existing == version {
			return
		}
	}
	dst[name] = append(dst[name], version)
}

func normalizeVersionMaps(inv *lockfileInventory) {
	for name, versions := range inv.AllVersions {
		sort.Slice(versions, func(i, j int) bool {
			return compareVersions(versions[i], versions[j]) < 0
		})
		inv.AllVersions[name] = versions
	}
	for name, version := range inv.DirectVersions {
		inv.DirectVersions[name] = normalizeVersion(version)
	}
}
