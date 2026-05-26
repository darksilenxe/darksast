package dataclass

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"javascript-security-scanner/internal/engine"
)

// Detection records one occurrence of a sensitive data type. Fields
// mirror the shape used by engine.Finding to keep downstream tooling
// (CSV/JSON consumers, dashboards) consistent across both pipelines.
type Detection struct {
	DetectorID string `json:"detector_id"`
	Category   string `json:"category"`
	DataType   string `json:"data_type"`
	Severity   string `json:"severity"`
	MatchKind  string `json:"match_kind"`
	File       string `json:"file"`
	Line       uint32 `json:"line"`
	Column     uint32 `json:"column"`
	EndColumn  uint32 `json:"end_column"`
	Match      string `json:"match"`
	Snippet    string `json:"snippet,omitempty"`
}

// Options controls how the scanner walks the target directory. The
// fields intentionally mirror the engine's flags so callers can route
// the same CLI inputs through both pipelines.
type Options struct {
	// IncludeTests, when true, scans test/spec files.
	IncludeTests bool
	// IncludeVendored, when true, scans vendored / build-output files.
	IncludeVendored bool
	// ChangedFiles, when non-nil and non-empty, restricts scanning to
	// the listed absolute file paths.
	ChangedFiles map[string]struct{}
	// ExtraExtensions lists additional file extensions (with leading
	// dot, e.g. ".env") to scan beyond the source extensions recognised
	// by the engine. Useful for pulling sensitive data out of configs.
	ExtraExtensions []string
	// MaxFileBytes caps the size of files the scanner is willing to
	// open. Zero means use the default cap (5 MiB).
	MaxFileBytes int64
}

const defaultMaxFileBytes = 5 * 1024 * 1024
const maxInventorySnippetLen = 200

// Scan walks targetDir, classifies sensitive data using the supplied
// detectors, and returns the deduplicated set of detections sorted by
// file then line/column. Detectors are compiled lazily; a compile
// failure aborts the scan so misconfigured detectors are surfaced
// loudly.
func Scan(targetDir string, detectors []Detector, opts Options) ([]Detection, error) {
	for i := range detectors {
		if err := detectors[i].compile(); err != nil {
			return nil, fmt.Errorf("data inventory detector %s: %w", detectors[i].ID, err)
		}
	}

	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}

	extras := normalizeExtensions(opts.ExtraExtensions)

	var detections []Detection
	walkErr := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if !opts.IncludeVendored {
				name := d.Name()
				if name == "node_modules" || name == ".git" || name == "dist" ||
					name == "build" || name == "out" || name == "coverage" ||
					name == ".next" || name == "vendor" {
					return filepath.SkipDir
				}
			}
			if !opts.IncludeTests {
				name := d.Name()
				if name == "__tests__" || name == "__mocks__" ||
					name == "cypress" || name == "e2e" || name == "playwright" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !isScannablePath(path, extras) {
			return nil
		}
		if !opts.IncludeVendored && engine.IsVendoredPath(path) {
			return nil
		}
		if !opts.IncludeTests && engine.IsTestPath(path) {
			return nil
		}
		if !isChangedFile(path, opts.ChangedFiles) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr == nil && info.Size() > maxBytes {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fileDetections := classifyFile(path, content, detectors)
		if len(fileDetections) > 0 {
			detections = append(detections, fileDetections...)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.SliceStable(detections, func(i, j int) bool {
		if detections[i].File != detections[j].File {
			return detections[i].File < detections[j].File
		}
		if detections[i].Line != detections[j].Line {
			return detections[i].Line < detections[j].Line
		}
		if detections[i].Column != detections[j].Column {
			return detections[i].Column < detections[j].Column
		}
		return detections[i].DetectorID < detections[j].DetectorID
	})
	return detections, nil
}

// classifyFile runs every detector against the file's text and returns
// the deduplicated set of detections. Each (file,line,column,detector,
// match-kind,match) tuple is reported at most once so multi-detector
// overlap on the same token doesn't inflate counts.
func classifyFile(path string, content []byte, detectors []Detector) []Detection {
	lines := splitLines(content)
	seen := make(map[string]struct{}, 16)
	out := make([]Detection, 0)

	for di := range detectors {
		// Defensive: callers that bypass Scan must still get compiled
		// regexes. Errors here drop the detector silently for the file
		// since Scan surfaces them on entry.
		_ = detectors[di].compile()
	}

	for lineIdx, line := range lines {
		if len(line) == 0 {
			continue
		}
		for di := range detectors {
			det := &detectors[di]
			for _, re := range det.idRegex {
				for _, idx := range re.FindAllIndex(line, -1) {
					addDetection(&out, seen, det, path, lineIdx, line, idx, "identifier")
				}
			}
			for _, re := range det.literalRegex {
				for _, idx := range re.FindAllIndex(line, -1) {
					addDetection(&out, seen, det, path, lineIdx, line, idx, "literal")
				}
			}
		}
	}
	return out
}

func addDetection(out *[]Detection, seen map[string]struct{}, det *Detector, path string, lineIdx int, line []byte, idx []int, kind string) {
	if len(idx) < 2 || idx[0] < 0 || idx[1] > len(line) {
		return
	}
	match := string(line[idx[0]:idx[1]])
	key := fmt.Sprintf("%s|%d|%d|%s|%s|%s", path, lineIdx, idx[0], det.ID, kind, match)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}

	snippet := strings.TrimSpace(string(line))
	if len(snippet) > maxInventorySnippetLen {
		snippet = snippet[:maxInventorySnippetLen] + "..."
	}

	*out = append(*out, Detection{
		DetectorID: det.ID,
		Category:   det.Category,
		DataType:   det.DataType,
		Severity:   det.EffectiveSeverity(),
		MatchKind:  kind,
		File:       path,
		Line:       uint32(lineIdx + 1),
		Column:     uint32(idx[0] + 1),
		EndColumn:  uint32(idx[1] + 1),
		Match:      match,
		Snippet:    snippet,
	})
}

// splitLines splits the file content into per-line byte slices without
// allocating new strings, preserving zero-based indexing into the
// original buffer.
func splitLines(content []byte) [][]byte {
	return bytes.Split(content, []byte("\n"))
}

// isScannablePath returns true when the file should be inspected by
// the data inventory pass. We accept anything the engine already
// parses as source plus a small set of extra extensions for config
// files.
func isScannablePath(path string, extras map[string]struct{}) bool {
	if engine.IsSupportedSourcePath(path) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return false
	}
	_, ok := extras[ext]
	return ok
}

func normalizeExtensions(extras []string) map[string]struct{} {
	out := map[string]struct{}{
		// Defaults: configs and structured text where sensitive data
		// often shows up. Callers can pass nil to use these defaults.
		".json": {},
		".yaml": {},
		".yml":  {},
		".env":  {},
		".ini":  {},
		".toml": {},
		".xml":  {},
		".html": {},
		".md":   {},
		".txt":  {},
		".csv":  {},
		".sql":  {},
	}
	for _, ext := range extras {
		trimmed := strings.ToLower(strings.TrimSpace(ext))
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, ".") {
			trimmed = "." + trimmed
		}
		out[trimmed] = struct{}{}
	}
	return out
}

func isChangedFile(path string, changed map[string]struct{}) bool {
	if len(changed) == 0 {
		return true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	_, ok := changed[filepath.Clean(abs)]
	return ok
}
