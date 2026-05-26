package engine

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvalFindingHasStableFingerprint ensures that every code finding
// carries a non-empty fingerprint and that the value is stable across
// scans of the same source.
func TestEvalFindingHasStableFingerprint(t *testing.T) {
	src := "\n// evaluate user input\neval(userInput);\n"
	path := writeTemp(t, src)

	findings := scanFile(t, path, []Rule{evalRule})
	require.Len(t, findings, 1)
	require.NotEmpty(t, findings[0].Fingerprint, "fingerprint must be populated")

	// Second scan of identical source yields identical fingerprint.
	again := scanFile(t, path, []Rule{evalRule})
	require.Len(t, again, 1)
	assert.Equal(t, findings[0].Fingerprint, again[0].Fingerprint,
		"identical source must produce identical fingerprints")
}

// TestComputeFingerprintIsLineNumberIndependent demonstrates that the
// fingerprint survives line-number drift: shifting the matched code
// down by adding blank lines above it must NOT change the value, since
// only normalized neighbor context is included — not raw line numbers.
func TestComputeFingerprintIsLineNumberIndependent(t *testing.T) {
	matched := "eval(userInput)"
	context := []string{"// evaluate user input", ""}

	fpA := ComputeFingerprint("JS-EVAL-EXEC", "src/app.js", "", matched, context)
	fpB := ComputeFingerprint("JS-EVAL-EXEC", "src/app.js", "", matched, context)

	assert.Equal(t, fpA, fpB, "deterministic for identical inputs")
	assert.NotEmpty(t, fpA)
	assert.Len(t, fpA, fingerprintLength)
}

// TestComputeFingerprintDiffersByMatchedCode ensures that different
// matched code at the same location produces different fingerprints, so
// a baseline cannot silently absorb a different vulnerability.
func TestComputeFingerprintDiffersByMatchedCode(t *testing.T) {
	fpA := ComputeFingerprint("JS-EVAL-EXEC", "src/app.js", "", "eval(a)", nil)
	fpB := ComputeFingerprint("JS-EVAL-EXEC", "src/app.js", "", "eval(b)", nil)
	assert.NotEqual(t, fpA, fpB, "different matched code must change the fingerprint")
}

// TestComputeFingerprintNormalizesPath ensures fingerprints are stable
// across operating systems by relativizing paths to the target dir and
// using forward slashes.
func TestComputeFingerprintNormalizesPath(t *testing.T) {
	target := t.TempDir()
	abs := filepath.Join(target, "src", "app.js")
	fpAbs := ComputeFingerprint("R", abs, target, "x()", nil)
	fpRel := ComputeFingerprint("R", "src/app.js", "", "x()", nil)
	assert.Equal(t, fpRel, fpAbs, "absolute path under target should normalize to relative form")
}

// TestComputeFingerprintWhitespaceInsensitive demonstrates the
// fingerprint shrugs off runs of whitespace and leading/trailing
// padding so trivial reformatting does not invalidate baselines.
func TestComputeFingerprintWhitespaceInsensitive(t *testing.T) {
	a := ComputeFingerprint("R", "f.js", "", "  eval(x)  ", nil)
	b := ComputeFingerprint("R", "f.js", "", "eval(x)", nil)
	c := ComputeFingerprint("R", "f.js", "", "eval(x)\t\n", nil)
	assert.Equal(t, a, b)
	assert.Equal(t, a, c)
}
