package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type npmPackageLock struct {
	Packages     map[string]npmPackageLockEntry `json:"packages"`
	Dependencies map[string]npmDependencyNode   `json:"dependencies"`
}

type npmPackageLockEntry struct {
	Version         string            `json:"version"`
	Dev             bool              `json:"dev"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type npmDependencyNode struct {
	Version      string                       `json:"version"`
	Dev          bool                         `json:"dev"`
	Dependencies map[string]npmDependencyNode `json:"dependencies"`
}

func parseNPMPackageLock(path string) []PackageRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lock npmPackageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	if len(lock.Packages) > 0 {
		return parseNPMPackageEntries(path, lock)
	}
	return parseNPMDependencyTree(path, lock.Dependencies)
}

func parseNPMPackageEntries(path string, lock npmPackageLock) []PackageRecord {
	projectPath := filepath.Dir(path)
	root := lock.Packages[""]
	directDeps := make(map[string]string, len(root.Dependencies))
	directDevDeps := make(map[string]string, len(root.DevDependencies))
	for name := range root.Dependencies {
		directDeps[name] = "dependencies"
	}
	for name := range root.DevDependencies {
		directDevDeps[name] = "devDependencies"
	}

	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	records := make([]PackageRecord, 0, len(keys))
	for _, key := range keys {
		entry := lock.Packages[key]
		name := packageNameFromLockPath(key)
		version := strings.TrimSpace(entry.Version)
		if name == "" || version == "" {
			continue
		}

		scope := "dependencies"
		relationship := "transitive"
		switch {
		case directDeps[name] != "":
			scope = "dependencies"
			relationship = "direct"
		case directDevDeps[name] != "":
			scope = "devDependencies"
			relationship = "direct"
		case entry.Dev:
			scope = "devDependencies"
		}

		dependencyPath := dependencyChainFromLockPath(key)
		if dependencyPath == "" {
			dependencyPath = name
		}

		records = append(records, PackageRecord{
			ProjectPath:    projectPath,
			ManifestPath:   path,
			Scope:          scope,
			Ecosystem:      "npm",
			Name:           name,
			Version:        version,
			Relationship:   relationship,
			DependencyPath: dependencyPath,
			Resolved:       true,
		})
	}
	return records
}

func parseNPMDependencyTree(path string, dependencies map[string]npmDependencyNode) []PackageRecord {
	projectPath := filepath.Dir(path)
	records := make([]PackageRecord, 0)
	var walk func(parent []string, name string, node npmDependencyNode, relationship string)
	walk = func(parent []string, name string, node npmDependencyNode, relationship string) {
		version := strings.TrimSpace(node.Version)
		if version == "" {
			return
		}
		scope := "dependencies"
		if node.Dev {
			scope = "devDependencies"
		}
		chain := append(append([]string(nil), parent...), name)
		records = append(records, PackageRecord{
			ProjectPath:    projectPath,
			ManifestPath:   path,
			Scope:          scope,
			Ecosystem:      "npm",
			Name:           name,
			Version:        version,
			Relationship:   relationship,
			DependencyPath: strings.Join(chain, " > "),
			Resolved:       true,
		})
		childNames := make([]string, 0, len(node.Dependencies))
		for childName := range node.Dependencies {
			childNames = append(childNames, childName)
		}
		sort.Strings(childNames)
		for _, childName := range childNames {
			walk(chain, childName, node.Dependencies[childName], "transitive")
		}
	}

	names := make([]string, 0, len(dependencies))
	for name := range dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		walk(nil, name, dependencies[name], "direct")
	}
	return records
}

func packageNameFromLockPath(path string) string {
	parts := splitNodeModulesPath(path)
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func dependencyChainFromLockPath(path string) string {
	parts := splitNodeModulesPath(path)
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " > ")
}

func splitNodeModulesPath(path string) []string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	segments := strings.Split(path, "/")
	out := make([]string, 0)
	for idx := 0; idx < len(segments); idx++ {
		if segments[idx] != "node_modules" {
			continue
		}
		if idx+1 >= len(segments) {
			break
		}
		name := segments[idx+1]
		if strings.HasPrefix(name, "@") && idx+2 < len(segments) {
			name = name + "/" + segments[idx+2]
			idx++
		}
		out = append(out, name)
	}
	return out
}
