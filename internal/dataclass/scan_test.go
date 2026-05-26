package dataclass

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyFile_IdentifiersAndLiterals(t *testing.T) {
	content := []byte(`const userEmail = "alice@example.com";
let password = "hunter2";
let ssn = "123-45-6789";
let ipAddress = "192.168.0.1";
const dateOfBirth = "1980-01-01";
const jwtToken = "x";
`)
	dets := classifyFile("/tmp/sample.js", content, BuiltinDetectors())

	want := map[string]bool{
		"DATA-EMAIL/identifier":         false,
		"DATA-EMAIL/literal":            false,
		"DATA-PASSWORD/identifier":      false,
		"DATA-SSN/identifier":           false,
		"DATA-SSN/literal":              false,
		"DATA-IP-ADDRESS/identifier":    false,
		"DATA-IP-ADDRESS/literal":       false,
		"DATA-DATE-OF-BIRTH/identifier": false,
		"DATA-JWT/identifier":           false,
		// Literal JWT not asserted here; covered by dedicated test below.
	}
	for _, d := range dets {
		key := d.DetectorID + "/" + d.MatchKind
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, hit := range want {
		if !hit {
			t.Errorf("missing detection: %s", k)
		}
	}
}

func TestClassifyFile_JWTLiteralMatches(t *testing.T) {
	content := []byte(`const tok = "eyJabc.eyJpZCI6MQ.signaturepart";` + "\n")
	dets := classifyFile("/tmp/sample.js", content, BuiltinDetectors())
	var hit bool
	for _, d := range dets {
		if d.DetectorID == "DATA-JWT" && d.MatchKind == "literal" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected JWT literal detection, got %+v", dets)
	}
}

func TestClassifyFile_NoFalsePositiveOnPlainNumbers(t *testing.T) {
	// 9 digits without dashes should not trigger SSN literal pattern.
	content := []byte(`const total = 123456789;` + "\n")
	dets := classifyFile("/tmp/sample.js", content, BuiltinDetectors())
	for _, d := range dets {
		if d.DetectorID == "DATA-SSN" {
			t.Fatalf("unexpected SSN match: %+v", d)
		}
	}
}

func TestClassifyFile_DedupesIdenticalMatches(t *testing.T) {
	content := []byte(`email email email` + "\n")
	dets := classifyFile("/tmp/sample.js", content, BuiltinDetectors())
	count := 0
	for _, d := range dets {
		if d.DetectorID == "DATA-EMAIL" && d.MatchKind == "identifier" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 unique identifier hits on different columns, got %d (%+v)", count, dets)
	}
}

func TestScan_RespectsExcludedDirsAndChangedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "kept.js"), `const email = "a@b.co";`)
	writeFile(t, filepath.Join(dir, "skipped.js"), `const email = "c@d.co";`)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "node_modules", "pkg", "leak.js"), `const password = "x";`)

	dets, err := Scan(dir, BuiltinDetectors(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dets {
		if filepath.Base(filepath.Dir(d.File)) == "pkg" {
			t.Fatalf("node_modules file should be skipped: %+v", d)
		}
	}

	// Changed-files mode should restrict to the chosen file only.
	abs, err := filepath.Abs(filepath.Join(dir, "kept.js"))
	if err != nil {
		t.Fatal(err)
	}
	dets, err = Scan(dir, BuiltinDetectors(), Options{
		ChangedFiles: map[string]struct{}{filepath.Clean(abs): {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) == 0 {
		t.Fatal("expected detections in changed file")
	}
	for _, d := range dets {
		if filepath.Base(d.File) != "kept.js" {
			t.Fatalf("changed-files filter leaked %s", d.File)
		}
	}
}

func TestDetectorEffectiveSeverityDefaultsMedium(t *testing.T) {
	d := Detector{Severity: ""}
	if got := d.EffectiveSeverity(); got != "MEDIUM" {
		t.Fatalf("default severity = %q, want MEDIUM", got)
	}
	d2 := Detector{Severity: "high"}
	if got := d2.EffectiveSeverity(); got != "HIGH" {
		t.Fatalf("normalized severity = %q, want HIGH", got)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
