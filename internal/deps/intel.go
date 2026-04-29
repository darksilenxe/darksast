package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultCompromisedFeedUserAgent = "JavaScript-Security-Scanner/1.0 threat-intel client"

type IOC struct {
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
}

type CompromisedPackageRule struct {
	ID          string   `json:"id" yaml:"id"`
	Ecosystem   string   `json:"ecosystem" yaml:"ecosystem"`
	Package     string   `json:"package" yaml:"package"`
	Versions    []string `json:"versions,omitempty" yaml:"versions,omitempty"`
	Severity    string   `json:"severity" yaml:"severity"`
	Description string   `json:"description" yaml:"description"`
	IOCs        []IOC    `json:"iocs,omitempty" yaml:"iocs,omitempty"`
	Source      string   `json:"source,omitempty" yaml:"source,omitempty"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`
}

type CompromisedFinding struct {
	RuleID       string   `json:"rule_id"`
	Ecosystem    string   `json:"ecosystem"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	ProjectPath  string   `json:"project_path"`
	ManifestPath string   `json:"manifest_path"`
	Scope        string   `json:"scope"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	IOCs         []IOC    `json:"iocs,omitempty"`
	Source       string   `json:"source,omitempty"`
	References   []string `json:"references,omitempty"`
}

type CompromisedRulesDocument struct {
	Source    string                   `json:"source,omitempty" yaml:"source,omitempty"`
	UpdatedAt string                   `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	Rules     []CompromisedPackageRule `json:"rules" yaml:"rules"`
}

type CompromisedFeedOptions struct {
	Timeout   time.Duration
	UserAgent string
	MaxBytes  int64
}

func LoadCompromisedRules(path string) ([]CompromisedPackageRule, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load compromised rules: %w", err)
	}

	var doc CompromisedRulesDocument
	if err := yaml.Unmarshal(data, &doc); err == nil && len(doc.Rules) > 0 {
		return normalizeCompromisedRules(doc.Rules), nil
	}

	var raw []CompromisedPackageRule
	if err := yaml.Unmarshal(data, &raw); err == nil && len(raw) > 0 {
		return normalizeCompromisedRules(raw), nil
	}

	return nil, fmt.Errorf("load compromised rules: %s does not contain any rules", path)
}

func FetchCompromisedRules(feedURL string, opts CompromisedFeedOptions) ([]CompromisedPackageRule, error) {
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil, nil
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = defaultCompromisedFeedUserAgent
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2 * 1024 * 1024
	}

	client := &http.Client{Timeout: opts.Timeout}
	req, err := http.NewRequest(http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch compromised rules: %w", err)
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch compromised rules: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch compromised rules: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch compromised rules: %w", err)
	}
	if int64(len(body)) > opts.MaxBytes {
		return nil, fmt.Errorf("fetch compromised rules: response exceeded max bytes (%d)", opts.MaxBytes)
	}

	var doc CompromisedRulesDocument
	if err := json.Unmarshal(body, &doc); err == nil && len(doc.Rules) > 0 {
		return normalizeCompromisedRules(doc.Rules), nil
	}

	var raw []CompromisedPackageRule
	if err := json.Unmarshal(body, &raw); err == nil && len(raw) > 0 {
		return normalizeCompromisedRules(raw), nil
	}

	return nil, fmt.Errorf("fetch compromised rules: feed did not contain any rules")
}

func MergeCompromisedRules(groups ...[]CompromisedPackageRule) []CompromisedPackageRule {
	merged := make(map[string]CompromisedPackageRule)
	for _, group := range groups {
		for _, rule := range normalizeCompromisedRules(group) {
			key := compromisedRuleKey(rule)
			merged[key] = rule
		}
	}

	out := make([]CompromisedPackageRule, 0, len(merged))
	for _, rule := range merged {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func MatchCompromisedPackages(records []PackageRecord, rules []CompromisedPackageRule) []CompromisedFinding {
	findings := make([]CompromisedFinding, 0)
	for _, record := range records {
		for _, rule := range rules {
			if !strings.EqualFold(record.Ecosystem, rule.Ecosystem) {
				continue
			}
			if !strings.EqualFold(record.Name, rule.Package) {
				continue
			}
			if !matchesAnyVersion(rule.Versions, record.Version) {
				continue
			}
			findings = append(findings, CompromisedFinding{
				RuleID:       rule.ID,
				Ecosystem:    rule.Ecosystem,
				Package:      record.Name,
				Version:      record.Version,
				ProjectPath:  record.ProjectPath,
				ManifestPath: record.ManifestPath,
				Scope:        record.Scope,
				Severity:     rule.Severity,
				Description:  rule.Description,
				IOCs:         append([]IOC(nil), rule.IOCs...),
				Source:       rule.Source,
				References:   append([]string(nil), rule.References...),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Ecosystem != findings[j].Ecosystem {
			return findings[i].Ecosystem < findings[j].Ecosystem
		}
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		if findings[i].ManifestPath != findings[j].ManifestPath {
			return findings[i].ManifestPath < findings[j].ManifestPath
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	return findings
}

func WriteCompromisedRulesYAML(path string, rules []CompromisedPackageRule) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	doc := CompromisedRulesDocument{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:     normalizeCompromisedRules(rules),
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("write compromised rules yaml: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write compromised rules yaml: %w", err)
	}
	return nil
}

func FormatIOCs(iocs []IOC) string {
	if len(iocs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(iocs))
	for _, ioc := range iocs {
		value := strings.TrimSpace(ioc.Value)
		if value == "" {
			continue
		}
		typ := strings.TrimSpace(ioc.Type)
		if typ == "" {
			parts = append(parts, value)
			continue
		}
		parts = append(parts, typ+":"+value)
	}
	return strings.Join(parts, ";")
}

func normalizeCompromisedRules(rules []CompromisedPackageRule) []CompromisedPackageRule {
	normalized := make([]CompromisedPackageRule, 0, len(rules))
	for _, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Ecosystem = strings.ToLower(strings.TrimSpace(rule.Ecosystem))
		rule.Package = strings.TrimSpace(rule.Package)
		rule.Severity = strings.ToUpper(strings.TrimSpace(rule.Severity))
		rule.Description = strings.TrimSpace(rule.Description)
		rule.Source = strings.TrimSpace(rule.Source)
		if rule.Severity == "" {
			rule.Severity = "HIGH"
		}
		if rule.Ecosystem == "" || rule.Package == "" || rule.ID == "" || rule.Description == "" {
			continue
		}
		versions := make([]string, 0, len(rule.Versions))
		for _, version := range rule.Versions {
			version = strings.TrimSpace(version)
			if version != "" {
				versions = append(versions, version)
			}
		}
		sort.Strings(versions)
		rule.Versions = versions
		normalized = append(normalized, rule)
	}
	return normalized
}

func compromisedRuleKey(rule CompromisedPackageRule) string {
	versions := append([]string(nil), rule.Versions...)
	sort.Strings(versions)
	return strings.ToLower(strings.TrimSpace(rule.ID)) + "|" +
		strings.ToLower(strings.TrimSpace(rule.Ecosystem)) + "|" +
		strings.ToLower(strings.TrimSpace(rule.Package)) + "|" +
		strings.Join(versions, ",")
}

func matchesAnyVersion(patterns []string, rawVersion string) bool {
	if len(patterns) == 0 {
		return true
	}
	candidates := versionCandidates(rawVersion)
	for _, pattern := range patterns {
		normalizedPattern := normalizeVersionToken(pattern)
		if normalizedPattern == "" {
			continue
		}
		if strings.HasSuffix(normalizedPattern, "*") {
			prefix := strings.TrimSuffix(normalizedPattern, "*")
			for _, candidate := range candidates {
				if strings.HasPrefix(candidate, prefix) {
					return true
				}
			}
			continue
		}
		for _, candidate := range candidates {
			if candidate == normalizedPattern {
				return true
			}
		}
	}
	return false
}

func versionCandidates(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ' ', '|', ',', ';':
			return true
		default:
			return false
		}
	})
	candidates := make([]string, 0, len(parts)+1)
	seen := make(map[string]struct{})
	for _, part := range append(parts, raw) {
		normalized := normalizeVersionToken(part)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		candidates = append(candidates, normalized)
	}
	return candidates
}

func normalizeVersionToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, `"'()[]{} `)
	token = strings.TrimLeft(token, "^~<>=!v")
	token = strings.TrimSpace(token)
	if idx := strings.Index(token, "#"); idx >= 0 {
		token = strings.TrimSpace(token[:idx])
	}
	return strings.ToLower(token)
}
