package engine

import (
	"fmt"
	"os"
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"gopkg.in/yaml.v3"
)

// Rule represents the structure of our YAML signature files.
// The tags (yaml:"...") tell the parser how to map the YAML keys to the struct fields.
type Rule struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Framework   string `yaml:"framework"`
	Description string `yaml:"description"`
	Query       string `yaml:"query"`
	compiled    *sitter.Query
}

func (r *Rule) compile() error {
	if r.compiled != nil {
		return nil
	}

	if r.Query == "" {
		return fmt.Errorf("rule %s has an empty query", r.ID)
	}

	compiled, err := sitter.NewQuery([]byte(r.Query), javascript.GetLanguage())
	if err != nil {
		return fmt.Errorf("failed to compile query for rule %s: %w", r.ID, err)
	}

	r.compiled = compiled
	return nil
}

// LoadRules scans a directory for .yaml files and parses them into a slice of Rule structs.
func LoadRules(rulesDir string) ([]Rule, error) {
	var rules []Rule

	err := filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" {
			fileData, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read rule file %s: %w", path, err)
			}

			var rule Rule
			if err := yaml.Unmarshal(fileData, &rule); err != nil {
				return fmt.Errorf("failed to parse YAML in %s: %w", path, err)
			}

			// Basic validation to ensure the rule isn't missing critical components
			if rule.ID != "" && rule.Query != "" {
				rules = append(rules, rule)
			} else {
				fmt.Printf("[-] Warning: Skipping invalid rule file %s (missing ID or Query)\n", path)
			}
		}
		return nil
	})

	return rules, err
}
