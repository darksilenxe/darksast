package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"javascript-security-scanner/internal/dataclass"
)

// DataInventoryReport is the JSON shape written by WriteDataInventoryJSON.
type DataInventoryReport struct {
	Timestamp        string                  `json:"timestamp"`
	TargetDir        string                  `json:"target_directory"`
	TotalDetections  int                     `json:"total_detections"`
	CategorySummary  map[string]int          `json:"category_summary,omitempty"`
	DataTypeSummary  map[string]int          `json:"data_type_summary,omitempty"`
	FilesWithData    int                     `json:"files_with_data,omitempty"`
	Detections       []dataclass.Detection   `json:"detections"`
}

// WriteDataInventoryJSON writes the full data inventory pass to JSON.
func WriteDataInventoryJSON(detections []dataclass.Detection, targetDir, outputPath string) error {
	report := DataInventoryReport{
		Timestamp:       time.Now().Format(time.RFC3339),
		TargetDir:       targetDir,
		TotalDetections: len(detections),
		CategorySummary: summarizeInventoryBy(detections, func(d dataclass.Detection) string { return d.Category }),
		DataTypeSummary: summarizeInventoryBy(detections, func(d dataclass.Detection) string { return d.DataType }),
		FilesWithData:   countUniqueFiles(detections),
		Detections:      detections,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data inventory report: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write data inventory JSON: %w", err)
	}
	fmt.Printf("[+] Successfully wrote data inventory JSON to: %s\n", outputPath)
	return nil
}

// WriteDataInventoryCSV writes one row per detection for BI/SQL ingestion.
func WriteDataInventoryCSV(detections []dataclass.Detection, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create data inventory CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"detector_id", "category", "data_type", "severity", "match_kind", "file", "line", "column", "end_column", "match", "snippet"}); err != nil {
		return fmt.Errorf("failed to write data inventory CSV header: %w", err)
	}
	for _, d := range detections {
		row := []string{
			d.DetectorID,
			d.Category,
			d.DataType,
			d.Severity,
			d.MatchKind,
			d.File,
			fmt.Sprintf("%d", d.Line),
			fmt.Sprintf("%d", d.Column),
			fmt.Sprintf("%d", d.EndColumn),
			d.Match,
			d.Snippet,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write data inventory CSV row: %w", err)
		}
	}
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize data inventory CSV write: %w", err)
	}
	fmt.Printf("[+] Successfully wrote data inventory CSV to: %s\n", outputPath)
	return nil
}

// WriteDataInventorySummaryCSV writes aggregated counts grouped by
// (category, data_type, severity) plus the distinct file count, making
// it easy to spot which sensitive categories the codebase touches.
func WriteDataInventorySummaryCSV(detections []dataclass.Detection, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create data inventory summary CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{"category", "data_type", "severity", "occurrences", "files"}); err != nil {
		return fmt.Errorf("failed to write data inventory summary CSV header: %w", err)
	}

	type key struct {
		category string
		dataType string
		severity string
	}
	occurrences := make(map[key]int)
	fileSets := make(map[key]map[string]struct{})
	for _, d := range detections {
		k := key{d.Category, d.DataType, d.Severity}
		occurrences[k]++
		if fileSets[k] == nil {
			fileSets[k] = make(map[string]struct{})
		}
		fileSets[k][d.File] = struct{}{}
	}

	keys := make([]key, 0, len(occurrences))
	for k := range occurrences {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].category != keys[j].category {
			return keys[i].category < keys[j].category
		}
		if keys[i].dataType != keys[j].dataType {
			return keys[i].dataType < keys[j].dataType
		}
		return keys[i].severity < keys[j].severity
	})

	for _, k := range keys {
		row := []string{
			k.category,
			k.dataType,
			k.severity,
			fmt.Sprintf("%d", occurrences[k]),
			fmt.Sprintf("%d", len(fileSets[k])),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write data inventory summary CSV row: %w", err)
		}
	}
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize data inventory summary CSV write: %w", err)
	}
	fmt.Printf("[+] Successfully wrote data inventory summary CSV to: %s\n", outputPath)
	return nil
}

func summarizeInventoryBy(detections []dataclass.Detection, key func(dataclass.Detection) string) map[string]int {
	if len(detections) == 0 {
		return nil
	}
	out := make(map[string]int, 8)
	for _, d := range detections {
		k := strings.TrimSpace(key(d))
		if k == "" {
			continue
		}
		out[k]++
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func countUniqueFiles(detections []dataclass.Detection) int {
	if len(detections) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, 8)
	for _, d := range detections {
		seen[d.File] = struct{}{}
	}
	return len(seen)
}

// PrintDataInventorySummary prints a short, console-friendly summary of
// the inventory pass. Output goes through fmt so it lines up with the
// existing scanner logs.
func PrintDataInventorySummary(detections []dataclass.Detection, targetDir string) {
	if len(detections) == 0 {
		fmt.Println("[*] Data inventory: no sensitive data types detected.")
		return
	}
	rel := targetDir
	if abs, err := filepath.Abs(targetDir); err == nil {
		rel = abs
	}
	fmt.Printf("[*] Data inventory: %d detection(s) across %d file(s) in %s.\n", len(detections), countUniqueFiles(detections), rel)
}
