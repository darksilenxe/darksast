package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"gopkg.in/yaml.v3"
)

// TaintConfig declares how a rule wants intra-file taint analysis applied.
type TaintConfig struct {
	// SinkCapture is the @capture name whose argument should be analyzed.
	SinkCapture string `yaml:"sink_capture"`
	// RequireTainted drops the finding when the sink is provably a
	// constant or sanitized expression (i.e. not tainted).
	RequireTainted bool `yaml:"require_tainted"`
}

// Rule represents the structure of our YAML signature files.
// The tags (yaml:"...") tell the parser how to map the YAML keys to the struct fields.
//
// Beyond the original required fields (id/severity/framework/description/query),
// rules may opt into post-match heuristics that suppress likely false
// positives. All such fields are optional and additive — rules that omit
// them keep their previous behavior.
type Rule struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Framework   string `yaml:"framework"`
	Description string `yaml:"description"`
	Query       string `yaml:"query"`

	// Confidence is reported alongside severity. Defaults to "MEDIUM".
	Confidence string `yaml:"confidence"`

	// IgnoreIfLiteral lists @capture names whose value, when a string,
	// number, regex, or non-interpolated template literal, suppresses
	// the finding (e.g. eval("use strict")).
	IgnoreIfLiteral []string `yaml:"ignore_if_literal"`

	// IgnoreIfMatches maps a @capture name to a regex; a match drops
	// the finding (e.g. URLs that start with a safe origin).
	IgnoreIfMatches map[string]string `yaml:"ignore_if_matches"`

	// RequireIfMatches maps a @capture name to a regex; the finding is
	// emitted only when the captured text matches the pattern (e.g.
	// crypto.createHash() only matters when the algorithm is md5/sha1).
	RequireIfMatches map[string]string `yaml:"require_if_matches"`

	// MinArgCount / MaxArgCount gate the rule on the number of
	// arguments passed to the matched call expression.
	MinArgCount *int `yaml:"min_arg_count"`
	MaxArgCount *int `yaml:"max_arg_count"`

	// RequiresDependency lists package names from package.json that
	// must be present for this rule to be evaluated. An empty list
	// means the rule runs on every project.
	RequiresDependency []string `yaml:"requires_dependency"`

	// Taint opts the rule into intra-file taint analysis.
	Taint *TaintConfig `yaml:"taint"`

	compiled         *sitter.Query
	ignoreMatchers   map[string]*regexp.Regexp
	requireMatchers  map[string]*regexp.Regexp
	literalCaptures  map[string]struct{}
	captureNamesInit bool
}

func (r *Rule) compile() error {
	if r.Query == "" {
		return fmt.Errorf("rule %s has an empty query", r.ID)
	}

	if r.compiled == nil {
		compiled, err := sitter.NewQuery([]byte(r.Query), javascript.GetLanguage())
		if err != nil {
			return fmt.Errorf("failed to compile query for rule %s: %w", r.ID, err)
		}
		r.compiled = compiled
	}

	// Rebuild the post-match filter caches every call. Compilation is
	// cheap and this lets tests mutate Rule fields after construction
	// without having to clear `compiled` manually.
	r.ignoreMatchers = make(map[string]*regexp.Regexp, len(r.IgnoreIfMatches))
	for capture, pattern := range r.IgnoreIfMatches {
		re, reErr := regexp.Compile(pattern)
		if reErr != nil {
			return fmt.Errorf("rule %s ignore_if_matches[%s]: %w", r.ID, capture, reErr)
		}
		r.ignoreMatchers[capture] = re
	}

	r.requireMatchers = make(map[string]*regexp.Regexp, len(r.RequireIfMatches))
	for capture, pattern := range r.RequireIfMatches {
		re, reErr := regexp.Compile(pattern)
		if reErr != nil {
			return fmt.Errorf("rule %s require_if_matches[%s]: %w", r.ID, capture, reErr)
		}
		r.requireMatchers[capture] = re
	}

	r.literalCaptures = make(map[string]struct{}, len(r.IgnoreIfLiteral))
	for _, capture := range r.IgnoreIfLiteral {
		r.literalCaptures[capture] = struct{}{}
	}

	r.captureNamesInit = true
	return nil
}

// EffectiveConfidence returns the rule's confidence, defaulting to
// "MEDIUM" when the rule does not declare one.
func (r *Rule) EffectiveConfidence() string {
	if r.Confidence == "" {
		return "MEDIUM"
	}
	return strings.ToUpper(r.Confidence)
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
