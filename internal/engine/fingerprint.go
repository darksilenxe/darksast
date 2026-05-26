package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// fingerprintLength is the number of hex characters kept from the
// SHA-256 digest. 16 characters (8 bytes) is enough to avoid practical
// collisions in a single project while remaining short enough to read.
const fingerprintLength = 16

// ComputeFingerprint produces a deterministic, location-independent
// fingerprint for a finding. The fingerprint is intentionally derived
// from semantically stable inputs so it survives line-number drift,
// reformatting of unrelated code, and absolute-path differences across
// CI environments.
//
// Inputs:
//   - ruleID       — the rule identifier
//   - file         — the absolute or relative path of the source file
//   - targetDir    — when non-empty, file is normalized relative to it
//   - matchedCode  — the AST-matched fragment (preferred) or snippet
//   - context      — already-extracted neighbor-line context strings
//
// The fingerprint omits raw line/column numbers so cosmetic edits
// elsewhere in the file do not invalidate baselines.
func ComputeFingerprint(ruleID, file, targetDir, matchedCode string, context []string) string {
	relFile := normalizeFingerprintPath(file, targetDir)

	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(ruleID)))
	h.Write([]byte{0})
	h.Write([]byte(relFile))
	h.Write([]byte{0})
	h.Write([]byte(normalizeFingerprintText(matchedCode)))
	h.Write([]byte{0})
	for _, line := range context {
		h.Write([]byte(normalizeFingerprintText(line)))
		h.Write([]byte{0})
	}

	sum := h.Sum(nil)
	encoded := hex.EncodeToString(sum)
	if len(encoded) > fingerprintLength {
		encoded = encoded[:fingerprintLength]
	}
	return encoded
}

// normalizeFingerprintPath returns a forward-slash relative path so the
// same finding produces the same fingerprint regardless of operating
// system or absolute path prefix.
func normalizeFingerprintPath(file, targetDir string) string {
	clean := strings.TrimSpace(file)
	if clean == "" {
		return ""
	}
	if td := strings.TrimSpace(targetDir); td != "" {
		if absFile, err := filepath.Abs(clean); err == nil {
			if absDir, err := filepath.Abs(td); err == nil {
				if rel, err := filepath.Rel(absDir, absFile); err == nil &&
					!strings.HasPrefix(rel, ".."+string(filepath.Separator)) &&
					rel != ".." {
					clean = rel
				}
			}
		}
	}
	return filepath.ToSlash(clean)
}

// normalizeFingerprintText collapses runs of whitespace so trivial
// reformatting does not invalidate the fingerprint.
func normalizeFingerprintText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return strings.Join(strings.Fields(trimmed), " ")
}

// neighborLines extracts up to two normalized neighbor lines (the line
// above and the line below the matched row) to feed into the
// fingerprint. The matched line itself is omitted because its content
// is already represented by matchedCode.
func neighborLines(sourceCode []byte, row uint32) []string {
	if len(sourceCode) == 0 {
		return nil
	}
	lines := bytes.Split(sourceCode, []byte("\n"))
	if len(lines) == 0 {
		return nil
	}
	out := make([]string, 0, 2)
	if row > 0 && int(row-1) < len(lines) {
		out = append(out, strings.TrimSpace(string(lines[row-1])))
	}
	if int(row+1) < len(lines) {
		out = append(out, strings.TrimSpace(string(lines[row+1])))
	}
	return out
}
