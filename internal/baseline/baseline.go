// Package baseline implements baseline file support: reading a list of
// previously-accepted finding fingerprints from disk, filtering current
// findings against that list to surface only net-new issues, and
// writing the current fingerprint set back to disk so a freshly-blessed
// baseline can be committed alongside the code.
//
// The baseline file is a small JSON document so it is comfortable to
// review in pull requests:
//
//	{
//	  "version": 1,
//	  "generated_at": "2026-05-26T14:33:57Z",
//	  "fingerprints": [
//	    "abc123def4567890",
//	    "fedcba0987654321"
//	  ]
//	}
//
// The format is intentionally minimal and forward-compatible: unknown
// fields are ignored on read so future scanner versions can add data
// (for example per-rule metadata) without breaking older callers.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"javascript-security-scanner/internal/engine"
)

// File describes the on-disk baseline document.
type File struct {
	Version      int      `json:"version"`
	GeneratedAt  string   `json:"generated_at,omitempty"`
	Fingerprints []string `json:"fingerprints"`
}

// Load reads a baseline JSON file and returns the set of fingerprints
// it contains. A missing or empty path returns an empty (non-nil) set
// without error so callers can use the result unconditionally.
func Load(path string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	clean := strings.TrimSpace(path)
	if clean == "" {
		return out, nil
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("failed to read baseline %s: %w", clean, err)
	}
	if len(data) == 0 {
		return out, nil
	}
	var file File
	if err := json.Unmarshal(data, &file); err != nil {
		// Backwards-compatible fallback: accept a bare JSON array of
		// fingerprints in addition to the documented object form.
		var bare []string
		if err2 := json.Unmarshal(data, &bare); err2 == nil {
			for _, fp := range bare {
				if trimmed := strings.TrimSpace(fp); trimmed != "" {
					out[trimmed] = struct{}{}
				}
			}
			return out, nil
		}
		return nil, fmt.Errorf("failed to parse baseline %s: %w", clean, err)
	}
	for _, fp := range file.Fingerprints {
		if trimmed := strings.TrimSpace(fp); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out, nil
}

// Write serializes the fingerprints of the supplied findings to a
// baseline JSON file. Findings without a fingerprint are skipped
// (they cannot be reliably matched across runs anyway).
func Write(path string, findings []engine.Finding) error {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return fmt.Errorf("baseline output path is empty")
	}

	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		fp := strings.TrimSpace(finding.Fingerprint)
		if fp == "" {
			continue
		}
		seen[fp] = struct{}{}
	}

	fingerprints := make([]string, 0, len(seen))
	for fp := range seen {
		fingerprints = append(fingerprints, fp)
	}
	sort.Strings(fingerprints)

	doc := File{
		Version:      1,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Fingerprints: fingerprints,
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	if dir := filepath.Dir(clean); dir != "" && dir != "." {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return fmt.Errorf("failed to create baseline directory %s: %w", dir, mkErr)
		}
	}

	if err := os.WriteFile(clean, data, 0o644); err != nil {
		return fmt.Errorf("failed to write baseline %s: %w", clean, err)
	}
	return nil
}

// Filter splits the supplied findings into two groups:
//   - kept:    the findings that should be reported (those whose
//     fingerprint is NOT in the baseline, plus any finding that has
//     no fingerprint at all because dropping such findings would be
//     unsafe).
//   - matched: the findings that were suppressed by the baseline.
//
// A nil or empty baseline returns all findings as kept.
func Filter(findings []engine.Finding, baseline map[string]struct{}) (kept []engine.Finding, matched []engine.Finding) {
	if len(baseline) == 0 {
		return findings, nil
	}
	kept = make([]engine.Finding, 0, len(findings))
	for _, finding := range findings {
		fp := strings.TrimSpace(finding.Fingerprint)
		if fp == "" {
			kept = append(kept, finding)
			continue
		}
		if _, ok := baseline[fp]; ok {
			matched = append(matched, finding)
			continue
		}
		kept = append(kept, finding)
	}
	return kept, matched
}
