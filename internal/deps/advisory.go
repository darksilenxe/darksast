package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultAdvisoryFeedUserAgent = "JavaScript-Security-Scanner/1.0 advisory client"
const githubNPMAdvisoryFeedAlias = "github://npm"

type Advisory struct {
	ID               string   `json:"id" yaml:"id"`
	Ecosystem        string   `json:"ecosystem" yaml:"ecosystem"`
	Package          string   `json:"package" yaml:"package"`
	Severity         string   `json:"severity" yaml:"severity"`
	Title            string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description      string   `json:"description" yaml:"description"`
	AffectedVersions []string `json:"affected_versions,omitempty" yaml:"affected_versions,omitempty"`
	FixedVersion     string   `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
	Aliases          []string `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	References       []string `json:"references,omitempty" yaml:"references,omitempty"`
	CWE              []string `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	CVSS             string   `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	Source           string   `json:"source,omitempty" yaml:"source,omitempty"`
}

type AdvisoryDocument struct {
	Source    string     `json:"source,omitempty" yaml:"source,omitempty"`
	UpdatedAt string     `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	Rules     []Advisory `json:"rules" yaml:"rules"`
}

type AdvisoryFeedOptions struct {
	Timeout   time.Duration
	UserAgent string
	MaxBytes  int64
}

type AdvisoryFinding struct {
	AdvisoryID     string   `json:"advisory_id"`
	Aliases        []string `json:"aliases,omitempty"`
	Ecosystem      string   `json:"ecosystem"`
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	ProjectPath    string   `json:"project_path"`
	ManifestPath   string   `json:"manifest_path"`
	Scope          string   `json:"scope"`
	Relationship   string   `json:"relationship"`
	DependencyPath string   `json:"dependency_path,omitempty"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description"`
	References     []string `json:"references,omitempty"`
	CWE            []string `json:"cwe,omitempty"`
	CVSS           string   `json:"cvss,omitempty"`
	Source         string   `json:"source,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	Reachability   string   `json:"reachability,omitempty"`
}

type AdvisoryPolicy struct {
	Ignores []AdvisoryIgnore `json:"ignores,omitempty" yaml:"ignores,omitempty"`
}

type AdvisoryIgnore struct {
	ID          string `json:"id" yaml:"id"`
	Package     string `json:"package,omitempty" yaml:"package,omitempty"`
	ProjectPath string `json:"project_path,omitempty" yaml:"project_path,omitempty"`
	Reason      string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Expires     string `json:"expires,omitempty" yaml:"expires,omitempty"`
}

func LoadAdvisories(path string) ([]Advisory, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("load advisories: %w", err)
	}
	return parseAdvisoryBytes(path, data)
}

func FetchAdvisories(feedURL string, opts AdvisoryFeedOptions) ([]Advisory, error) {
	feedURL = strings.TrimSpace(feedURL)
	if feedURL == "" {
		return nil, nil
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if strings.TrimSpace(opts.UserAgent) == "" {
		opts.UserAgent = defaultAdvisoryFeedUserAgent
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2 * 1024 * 1024
	}
	if strings.EqualFold(feedURL, githubNPMAdvisoryFeedAlias) {
		return fetchGitHubNPMAdvisories(opts)
	}

	client := &http.Client{Timeout: opts.Timeout}
	req, err := http.NewRequest(http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch advisories: %w", err)
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch advisories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch advisories: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch advisories: %w", err)
	}
	if int64(len(body)) > opts.MaxBytes {
		return nil, fmt.Errorf("fetch advisories: response exceeded max bytes (%d)", opts.MaxBytes)
	}

	return parseAdvisoryBytes(feedURL, body)
}

type githubAdvisoryIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type githubAdvisoryReference struct {
	URL string `json:"url"`
}

type githubAdvisoryCWE struct {
	CWEID string `json:"cwe_id"`
}

type githubAdvisoryCVSS struct {
	Score float64 `json:"score"`
}

type githubAdvisoryVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	FirstPatchedVersion    struct {
		Identifier string `json:"identifier"`
	} `json:"first_patched_version"`
}

type githubSecurityAdvisory struct {
	GHSAID          string                        `json:"ghsa_id"`
	Summary         string                        `json:"summary"`
	Description     string                        `json:"description"`
	Severity        string                        `json:"severity"`
	Identifiers     []githubAdvisoryIdentifier    `json:"identifiers"`
	References      []githubAdvisoryReference     `json:"references"`
	CWEs            []githubAdvisoryCWE           `json:"cwes"`
	CVSS            githubAdvisoryCVSS            `json:"cvss"`
	Vulnerabilities []githubAdvisoryVulnerability `json:"vulnerabilities"`
}

func fetchGitHubNPMAdvisories(opts AdvisoryFeedOptions) ([]Advisory, error) {
	client := &http.Client{Timeout: opts.Timeout}
	page := 1
	out := make([]Advisory, 0)
	for {
		pageURL := fmt.Sprintf("https://api.github.com/advisories?ecosystem=npm&per_page=100&page=%d", page)
		req, err := http.NewRequest(http.MethodGet, pageURL, nil)
		if err != nil {
			return nil, fmt.Errorf("fetch advisories: %w", err)
		}
		req.Header.Set("User-Agent", opts.UserAgent)
		req.Header.Set("Accept", "application/vnd.github+json")
		if token := strings.TrimSpace(githubAdvisoryToken()); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch advisories: %w", err)
		}
		body, bodyErr := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes+1))
		resp.Body.Close()
		if bodyErr != nil {
			return nil, fmt.Errorf("fetch advisories: %w", bodyErr)
		}
		if int64(len(body)) > opts.MaxBytes {
			return nil, fmt.Errorf("fetch advisories: response exceeded max bytes (%d)", opts.MaxBytes)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("fetch advisories: HTTP %d", resp.StatusCode)
		}
		var payload []githubSecurityAdvisory
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("fetch advisories: %w", err)
		}
		out = append(out, convertGitHubNPMAdvisories(payload)...)
		if !hasNextPageLink(resp.Header.Get("Link")) {
			break
		}
		page++
	}
	return normalizeAdvisories(out), nil
}

func githubAdvisoryToken() string {
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token
	}
	return strings.TrimSpace(os.Getenv("GH_TOKEN"))
}

var advisoryIDSanitizerRE = regexp.MustCompile(`[^A-Za-z0-9]+`)

func advisoryIDSegment(value string) string {
	value = strings.TrimSpace(value)
	value = advisoryIDSanitizerRE.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(value)
}

func splitGitHubVersionRange(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, ",", " ")
	parts := strings.Split(raw, "||")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func convertGitHubNPMAdvisories(payload []githubSecurityAdvisory) []Advisory {
	out := make([]Advisory, 0)
	for _, entry := range payload {
		aliases := make([]string, 0, len(entry.Identifiers)+1)
		if ghsa := strings.TrimSpace(entry.GHSAID); ghsa != "" {
			aliases = append(aliases, ghsa)
		}
		for _, ident := range entry.Identifiers {
			if strings.EqualFold(strings.TrimSpace(ident.Type), "GHSA") {
				continue
			}
			if v := strings.TrimSpace(ident.Value); v != "" {
				aliases = append(aliases, v)
			}
		}
		refs := make([]string, 0, len(entry.References))
		for _, ref := range entry.References {
			if url := strings.TrimSpace(ref.URL); url != "" {
				refs = append(refs, url)
			}
		}
		cwes := make([]string, 0, len(entry.CWEs))
		for _, cwe := range entry.CWEs {
			if id := strings.TrimSpace(cwe.CWEID); id != "" {
				cwes = append(cwes, id)
			}
		}
		cvss := ""
		if entry.CVSS.Score > 0 {
			cvss = fmt.Sprintf("%.1f", entry.CVSS.Score)
		}
		for _, vuln := range entry.Vulnerabilities {
			if !strings.EqualFold(vuln.Package.Ecosystem, "npm") {
				continue
			}
			pkg := strings.TrimSpace(vuln.Package.Name)
			if pkg == "" {
				continue
			}
			title := strings.TrimSpace(entry.Summary)
			if title == "" {
				title = strings.TrimSpace(entry.GHSAID)
			}
			description := strings.TrimSpace(entry.Description)
			if description == "" {
				description = title
			}
			ranges := splitGitHubVersionRange(vuln.VulnerableVersionRange)
			out = append(out, Advisory{
				ID:               "OSS-NPM-" + advisoryIDSegment(pkg) + "-" + advisoryIDSegment(entry.GHSAID),
				Ecosystem:        "npm",
				Package:          pkg,
				Severity:         strings.ToUpper(strings.TrimSpace(entry.Severity)),
				Title:            title,
				Description:      description,
				AffectedVersions: ranges,
				FixedVersion:     strings.TrimSpace(vuln.FirstPatchedVersion.Identifier),
				Aliases:          append([]string(nil), aliases...),
				References:       append([]string(nil), refs...),
				CWE:              append([]string(nil), cwes...),
				CVSS:             cvss,
				Source:           "github-advisory-database",
			})
		}
	}
	return out
}

func hasNextPageLink(linkHeader string) bool {
	for _, part := range strings.Split(linkHeader, ",") {
		if strings.Contains(part, `rel="next"`) {
			return true
		}
	}
	return false
}

func MergeAdvisories(groups ...[]Advisory) []Advisory {
	merged := make(map[string]Advisory)
	for _, group := range groups {
		for _, advisory := range normalizeAdvisories(group) {
			key := advisoryKey(advisory)
			merged[key] = advisory
		}
	}

	out := make([]Advisory, 0, len(merged))
	for _, advisory := range merged {
		out = append(out, advisory)
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

func WriteAdvisoriesYAML(path string, advisories []Advisory) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	doc := AdvisoryDocument{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:     normalizeAdvisories(advisories),
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("write advisories yaml: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write advisories yaml: %w", err)
	}
	return nil
}

func LoadAdvisoryPolicy(path string) (AdvisoryPolicy, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return AdvisoryPolicy{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AdvisoryPolicy{}, nil
		}
		return AdvisoryPolicy{}, fmt.Errorf("load advisory policy: %w", err)
	}
	var policy AdvisoryPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return AdvisoryPolicy{}, fmt.Errorf("load advisory policy: %w", err)
	}
	return policy, nil
}

func MatchAdvisories(records []PackageRecord, advisories []Advisory) []AdvisoryFinding {
	findings := make([]AdvisoryFinding, 0)
	for _, record := range records {
		version := strings.TrimSpace(record.Version)
		if version == "" {
			continue
		}
		for _, advisory := range advisories {
			if !strings.EqualFold(record.Ecosystem, advisory.Ecosystem) {
				continue
			}
			if !strings.EqualFold(record.Name, advisory.Package) {
				continue
			}
			if !matchesAnyVersionRange(advisory.AffectedVersions, version) {
				continue
			}
			findings = append(findings, AdvisoryFinding{
				AdvisoryID:     advisory.ID,
				Aliases:        append([]string(nil), advisory.Aliases...),
				Ecosystem:      advisory.Ecosystem,
				Package:        record.Name,
				Version:        record.Version,
				FixedVersion:   advisory.FixedVersion,
				ProjectPath:    record.ProjectPath,
				ManifestPath:   record.ManifestPath,
				Scope:          record.Scope,
				Relationship:   defaultRelationship(record.Relationship),
				DependencyPath: record.DependencyPath,
				Severity:       advisory.Severity,
				Title:          advisory.Title,
				Description:    advisory.Description,
				References:     append([]string(nil), advisory.References...),
				CWE:            append([]string(nil), advisory.CWE...),
				CVSS:           advisory.CVSS,
				Source:         advisory.Source,
				Remediation:    buildAdvisoryRemediation(record, advisory),
				Reachability:   "unknown",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Package != findings[j].Package {
			return findings[i].Package < findings[j].Package
		}
		if findings[i].ManifestPath != findings[j].ManifestPath {
			return findings[i].ManifestPath < findings[j].ManifestPath
		}
		return findings[i].AdvisoryID < findings[j].AdvisoryID
	})
	return findings
}

func ApplyAdvisoryPolicy(findings []AdvisoryFinding, policy AdvisoryPolicy, now time.Time) ([]AdvisoryFinding, int) {
	if len(policy.Ignores) == 0 {
		return findings, 0
	}
	filtered := make([]AdvisoryFinding, 0, len(findings))
	ignored := 0
	for _, finding := range findings {
		if shouldIgnoreFinding(finding, policy.Ignores, now) {
			ignored++
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered, ignored
}

func FormatIdentifiers(advisoryID string, aliases []string) string {
	parts := make([]string, 0, 1+len(aliases))
	if strings.TrimSpace(advisoryID) != "" {
		parts = append(parts, strings.TrimSpace(advisoryID))
	}
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		parts = append(parts, alias)
	}
	return strings.Join(parts, ";")
}

func parseAdvisoryBytes(source string, data []byte) ([]Advisory, error) {
	var doc AdvisoryDocument
	if err := yaml.Unmarshal(data, &doc); err == nil && len(doc.Rules) > 0 {
		return normalizeAdvisories(doc.Rules), nil
	}
	var list []Advisory
	if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
		return normalizeAdvisories(list), nil
	}
	if jsonErr := json.Unmarshal(data, &doc); jsonErr == nil && len(doc.Rules) > 0 {
		return normalizeAdvisories(doc.Rules), nil
	}
	if jsonErr := json.Unmarshal(data, &list); jsonErr == nil && len(list) > 0 {
		return normalizeAdvisories(list), nil
	}
	return nil, fmt.Errorf("load advisories: %s does not contain any advisories", source)
}

func normalizeAdvisories(advisories []Advisory) []Advisory {
	normalized := make([]Advisory, 0, len(advisories))
	for _, advisory := range advisories {
		advisory.ID = strings.TrimSpace(advisory.ID)
		advisory.Ecosystem = strings.ToLower(strings.TrimSpace(advisory.Ecosystem))
		advisory.Package = strings.TrimSpace(advisory.Package)
		advisory.Severity = strings.ToUpper(strings.TrimSpace(advisory.Severity))
		advisory.Title = strings.TrimSpace(advisory.Title)
		advisory.Description = strings.TrimSpace(advisory.Description)
		advisory.FixedVersion = normalizeAdvisoryVersionToken(advisory.FixedVersion)
		advisory.Source = strings.TrimSpace(advisory.Source)
		advisory.CVSS = strings.TrimSpace(advisory.CVSS)
		advisory.AffectedVersions = normalizeStringList(advisory.AffectedVersions)
		advisory.Aliases = normalizeStringList(advisory.Aliases)
		advisory.References = normalizeStringList(advisory.References)
		advisory.CWE = normalizeStringList(advisory.CWE)
		if advisory.Severity == "" {
			advisory.Severity = "MEDIUM"
		}
		normalized = append(normalized, advisory)
	}
	return normalized
}

func advisoryKey(advisory Advisory) string {
	if advisory.ID != "" {
		return advisory.ID
	}
	return advisory.Ecosystem + "|" + advisory.Package + "|" + strings.Join(advisory.AffectedVersions, ",")
}

func shouldIgnoreFinding(finding AdvisoryFinding, ignores []AdvisoryIgnore, now time.Time) bool {
	for _, ignore := range ignores {
		if !strings.EqualFold(strings.TrimSpace(ignore.ID), finding.AdvisoryID) {
			continue
		}
		if pkg := strings.TrimSpace(ignore.Package); pkg != "" && !strings.EqualFold(pkg, finding.Package) {
			continue
		}
		if project := strings.TrimSpace(ignore.ProjectPath); project != "" && filepath.Clean(project) != filepath.Clean(finding.ProjectPath) {
			continue
		}
		if ignoreExpired(ignore.Expires, now) {
			continue
		}
		return true
	}
	return false
}

func ignoreExpired(expires string, now time.Time) bool {
	expires = strings.TrimSpace(expires)
	if expires == "" {
		return false
	}
	if ts, err := time.Parse(time.RFC3339, expires); err == nil {
		return now.After(ts)
	}
	if ts, err := time.Parse("2006-01-02", expires); err == nil {
		return now.After(ts.Add(24 * time.Hour))
	}
	return false
}

func buildAdvisoryRemediation(record PackageRecord, advisory Advisory) string {
	target := "Upgrade"
	if defaultRelationship(record.Relationship) == "transitive" {
		target = "Upgrade or pin the nearest direct dependency"
	}
	if advisory.FixedVersion == "" {
		if defaultRelationship(record.Relationship) == "transitive" {
			return target + " that brings " + record.Name + " onto a non-vulnerable version."
		}
		return target + " " + record.Name + " to a non-vulnerable version."
	}
	if defaultRelationship(record.Relationship) == "transitive" {
		return fmt.Sprintf("%s so %s resolves to %s or later.", target, record.Name, advisory.FixedVersion)
	}
	return fmt.Sprintf("%s %s to %s or later.", target, record.Name, advisory.FixedVersion)
}

func matchesAnyVersionRange(ranges []string, version string) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, constraint := range ranges {
		if matchesVersionConstraint(constraint, version) {
			return true
		}
	}
	return false
}

func matchesVersionConstraint(constraint string, version string) bool {
	constraint = strings.TrimSpace(constraint)
	version = normalizeAdvisoryVersionToken(version)
	if constraint == "" {
		return true
	}
	for _, branch := range strings.Split(constraint, "||") {
		branch = strings.TrimSpace(branch)
		if branch == "" {
			continue
		}
		ok := true
		for _, token := range splitConstraintBranch(branch) {
			if !matchesComparator(token, version) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func splitConstraintBranch(branch string) []string {
	branch = strings.ReplaceAll(branch, ",", " ")
	return strings.Fields(branch)
}

func matchesComparator(token string, version string) bool {
	token = strings.TrimSpace(token)
	if token == "" || token == "*" {
		return true
	}
	if strings.HasPrefix(token, "^") {
		base := normalizeAdvisoryVersionToken(strings.TrimPrefix(token, "^"))
		if compareVersions(version, base) < 0 {
			return false
		}
		upper := caretUpperBound(base)
		return upper == "" || compareVersions(version, upper) < 0
	}
	if strings.HasPrefix(token, "~") {
		base := normalizeAdvisoryVersionToken(strings.TrimPrefix(token, "~"))
		if compareVersions(version, base) < 0 {
			return false
		}
		upper := tildeUpperBound(base)
		return upper == "" || compareVersions(version, upper) < 0
	}
	for _, wildcard := range []string{"x", "X", "*"} {
		if strings.Contains(token, wildcard) {
			return matchesWildcard(token, version)
		}
	}

	op := ""
	value := token
	for _, candidate := range []string{"<=", ">=", "==", "!=", "<", ">", "="} {
		if strings.HasPrefix(token, candidate) {
			op = candidate
			value = strings.TrimSpace(strings.TrimPrefix(token, candidate))
			break
		}
	}
	value = normalizeAdvisoryVersionToken(value)
	switch op {
	case "", "=", "==":
		return compareVersions(version, value) == 0
	case "!=":
		return compareVersions(version, value) != 0
	case "<":
		return compareVersions(version, value) < 0
	case "<=":
		return compareVersions(version, value) <= 0
	case ">":
		return compareVersions(version, value) > 0
	case ">=":
		return compareVersions(version, value) >= 0
	default:
		return false
	}
}

func matchesWildcard(token string, version string) bool {
	want := splitVersionParts(normalizeAdvisoryVersionToken(token))
	have := splitVersionParts(version)
	for idx, part := range want {
		if part == "" || part == "*" || strings.EqualFold(part, "x") {
			return true
		}
		if idx >= len(have) || compareVersionPart(have[idx], part) != 0 {
			return false
		}
	}
	return len(have) >= len(want)
}

func caretUpperBound(base string) string {
	parts := numericVersionParts(base, 3)
	switch {
	case parts[0] > 0:
		return fmt.Sprintf("%d.0.0", parts[0]+1)
	case parts[1] > 0:
		return fmt.Sprintf("0.%d.0", parts[1]+1)
	default:
		return fmt.Sprintf("0.0.%d", parts[2]+1)
	}
}

func tildeUpperBound(base string) string {
	parts := numericVersionParts(base, 3)
	return fmt.Sprintf("%d.%d.0", parts[0], parts[1]+1)
}

func numericVersionParts(version string, minLen int) []int {
	raw := splitVersionParts(version)
	out := make([]int, 0, max(minLen, len(raw)))
	for _, part := range raw {
		value, _ := strconv.Atoi(part)
		out = append(out, value)
	}
	for len(out) < minLen {
		out = append(out, 0)
	}
	return out
}

func compareVersions(a string, b string) int {
	left := splitVersionParts(normalizeAdvisoryVersionToken(a))
	right := splitVersionParts(normalizeAdvisoryVersionToken(b))
	maxParts := max(len(left), len(right))
	for idx := 0; idx < maxParts; idx++ {
		lhs := "0"
		if idx < len(left) {
			lhs = left[idx]
		}
		rhs := "0"
		if idx < len(right) {
			rhs = right[idx]
		}
		if cmp := compareVersionPart(lhs, rhs); cmp != 0 {
			return cmp
		}
	}
	return 0
}

func compareVersionPart(a string, b string) int {
	if ai, errA := strconv.Atoi(a); errA == nil {
		if bi, errB := strconv.Atoi(b); errB == nil {
			switch {
			case ai < bi:
				return -1
			case ai > bi:
				return 1
			default:
				return 0
			}
		}
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func splitVersionParts(version string) []string {
	replacer := strings.NewReplacer("-", ".", "+", ".", "_", ".")
	parts := strings.Split(replacer.Replace(version), ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return []string{"0"}
	}
	return out
}

func normalizeAdvisoryVersionToken(version string) string {
	version = strings.TrimSpace(version)
	version = strings.Trim(version, `"'`)
	version = strings.TrimPrefix(version, "v")
	for _, prefix := range []string{"==", ">=", "<=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(version, prefix) {
			version = strings.TrimSpace(strings.TrimPrefix(version, prefix))
			break
		}
	}
	if idx := strings.IndexAny(version, " ,"); idx >= 0 {
		version = version[:idx]
	}
	return version
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
