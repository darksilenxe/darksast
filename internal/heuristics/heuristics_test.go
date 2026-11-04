package heuristics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"javascript-security-scanner/internal/engine"
)

func TestEnrichMarksReachableSourceToSinkAsHigh(t *testing.T) {
	findings := []engine.Finding{
		{
			RuleID:        "JS-EVAL-EXEC",
			Severity:      "HIGH",
			Confidence:    "HIGH",
			TriageVerdict: "REACHABLE",
			Snippet:       "eval(req.body.payload)",
		},
	}

	count := Enrich(findings)
	assert.Equal(t, 1, count)
	assert.Equal(t, "HIGH", findings[0].Exploitability)
	assert.GreaterOrEqual(t, findings[0].ExploitabilityScore, 75)
	assert.NotEmpty(t, findings[0].AttackerReasoning)
}

func TestEnrichDowngradesLikelyUnreachableFinding(t *testing.T) {
	findings := []engine.Finding{
		{
			RuleID:        "DOM-XSS-INNERHTML-ASSIGN",
			Severity:      "HIGH",
			Confidence:    "MEDIUM",
			TriageVerdict: "LIKELY_UNREACHABLE",
			Snippet:       "node.innerHTML = req.query.x",
		},
	}

	Enrich(findings)
	assert.Equal(t, "LOW", findings[0].Exploitability)
	assert.Greater(t, findings[0].ExploitabilityScore, 0)
	assert.Less(t, findings[0].ExploitabilityScore, 50)
}

func TestEnrichHandlesLowSignalFinding(t *testing.T) {
	findings := []engine.Finding{
		{
			RuleID:     "LOW-NOISE",
			Severity:   "LOW",
			Confidence: "LOW",
			Snippet:    "const safe = 1",
		},
	}

	Enrich(findings)
	assert.Equal(t, "LOW", findings[0].Exploitability)
	assert.Less(t, findings[0].ExploitabilityScore, 50)
	assert.NotEmpty(t, findings[0].AttackerReasoning)
}
