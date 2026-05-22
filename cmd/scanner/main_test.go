package main

import (
	"testing"

	"javascript-security-scanner/internal/engine"

	"github.com/stretchr/testify/assert"
)

func TestParseCategoryGate(t *testing.T) {
	gate := parseCategoryGate("Secrets Exposure, Injection , ,privacy risk")
	assert.Contains(t, gate, "SECRETS EXPOSURE")
	assert.Contains(t, gate, "INJECTION")
	assert.Contains(t, gate, "PRIVACY RISK")
}

func TestShouldFailForCategories(t *testing.T) {
	findings := []engine.Finding{
		{RuleID: "HARDCODED-SECRET", Category: "Secrets Exposure"},
		{RuleID: "DOM-XSS", Category: "Cross-Site Scripting"},
	}
	assert.True(t, shouldFailForCategories(findings, parseCategoryGate("injection,secrets exposure")))
	assert.False(t, shouldFailForCategories(findings, parseCategoryGate("access control")))
	assert.False(t, shouldFailForCategories(findings, nil))
}
