package heuristics

import (
	"fmt"
	"strings"

	"javascript-security-scanner/internal/engine"
)

var severityWeight = map[string]int{
	"CRITICAL": 40,
	"HIGH":     30,
	"MEDIUM":   20,
	"LOW":      10,
}

var confidenceWeight = map[string]int{
	"HIGH":   20,
	"MEDIUM": 10,
	"LOW":    5,
}

var sinkMarkers = []string{
	"eval(",
	"innerhtml",
	"document.write",
	"exec.command",
	"child_process.exec",
	"os.system",
	"system(",
	"sql.query",
	"query(",
	"pickle.loads",
	"yaml.load",
	"deserial",
}

var sourceMarkers = []string{
	"req.body",
	"req.query",
	"req.params",
	"userinput",
	"input(",
	"argv",
	"$_get",
	"$_post",
	"context.request",
	"event.body",
}

// Enrich annotates findings with attacker-style exploitability heuristics.
// It returns the number of findings that were enriched.
func Enrich(findings []engine.Finding) int {
	enriched := 0
	for i := range findings {
		if enrichOne(&findings[i]) {
			enriched++
		}
	}
	return enriched
}

func enrichOne(f *engine.Finding) bool {
	score := 0
	reasons := make([]string, 0, 5)

	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	score += severityWeight[sev]
	if sev != "" {
		reasons = append(reasons, fmt.Sprintf("Base risk from severity %s.", sev))
	}

	conf := strings.ToUpper(strings.TrimSpace(f.Confidence))
	score += confidenceWeight[conf]
	if conf != "" {
		reasons = append(reasons, fmt.Sprintf("Signal strength increased by confidence %s.", conf))
	}

	haystack := strings.ToLower(strings.Join([]string{
		f.RuleID,
		f.Category,
		f.Description,
		f.Snippet,
		f.MatchedCode,
		f.HighlightedSnippet,
	}, " "))

	if marker := firstMarker(haystack, sinkMarkers); marker != "" {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Dangerous sink marker found (%s).", marker))
	}
	if marker := firstMarker(haystack, sourceMarkers); marker != "" {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Untrusted input marker found (%s).", marker))
	}

	switch strings.ToUpper(strings.TrimSpace(f.TriageVerdict)) {
	case "REACHABLE":
		score += 20
		reasons = append(reasons, "Reachability review marked this code path as REACHABLE.")
	case "LIKELY_UNREACHABLE":
		score -= 15
		reasons = append(reasons, "Reachability review marked this code path as LIKELY_UNREACHABLE.")
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	f.ExploitabilityScore = score
	switch {
	case score >= 75:
		f.Exploitability = "HIGH"
	case score >= 50:
		f.Exploitability = "MEDIUM"
	default:
		f.Exploitability = "LOW"
	}
	f.AttackerReasoning = reasons
	return true
}

func firstMarker(haystack string, markers []string) string {
	for _, marker := range markers {
		if strings.Contains(haystack, marker) {
			return marker
		}
	}
	return ""
}
