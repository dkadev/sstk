package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dkadev/sstk/pkg/aggregator"
)

const secretPreviewLen = 8

// Write renders the aggregated result in the given format ("text", "json" or "csv").
// When showSecrets is true, human-readable formats emit the raw secret value
// instead of a masked preview (JSON always carries the raw value).
func Write(w io.Writer, format string, result *aggregator.AggregatedResult, showSecrets bool) error {
	switch strings.ToLower(format) {
	case "text":
		return WriteText(w, result, showSecrets)
	case "json":
		return WriteJSON(w, result)
	case "csv":
		return WriteCSV(w, result, showSecrets)
	default:
		return fmt.Errorf("unsupported output format %q (supported: text, json, csv)", format)
	}
}

// WriteText renders a human-readable summary of the aggregated result
func WriteText(w io.Writer, result *aggregator.AggregatedResult, showSecrets bool) error {
	if result == nil {
		return fmt.Errorf("no result to write")
	}

	findings := sortedFindings(result.Findings)
	scanners := sortedKeys(result.ScannerStats)

	var b strings.Builder

	fmt.Fprintf(&b, "=== Secret Scanner Tool Kit Results ===\n\n")
	fmt.Fprintf(&b, "Total Findings: %d\n", result.TotalFindings)
	fmt.Fprintf(&b, "Unique Secrets: %d\n", result.UniqueSecrets)

	fmt.Fprintf(&b, "\nScanner Statistics:\n")
	for _, name := range scanners {
		fmt.Fprintf(&b, "  %s: %d findings\n", name, result.ScannerStats[name])
	}

	fmt.Fprintf(&b, "\nFindings:\n=========\n\n")
	for i, f := range findings {
		fmt.Fprintf(&b, "[%d] %s\n", i+1, f.File)
		fmt.Fprintf(&b, "    Line: %d\n", f.Line)
		fmt.Fprintf(&b, "    Rule: %s\n", f.RuleID)
		fmt.Fprintf(&b, "    Description: %s\n", f.Description)
		fmt.Fprintf(&b, "    Found by: %s\n", strings.Join(f.FoundBy, ", "))
		secret := maskSecret(f.Secret)
		if showSecrets {
			secret = f.Secret
		}
		fmt.Fprintf(&b, "    Secret: %s\n", secret)
		if len(f.Occurrences) > 1 {
			fmt.Fprintf(&b, "    Occurrences (%d):\n", len(f.Occurrences))
			for _, o := range f.Occurrences {
				fmt.Fprintf(&b, "      - %s:%d\n", o.File, o.Line)
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	if result.UniqueSecrets > 0 {
		fmt.Fprintf(&b, "WARNING: %d unique secret(s) detected!\n", result.UniqueSecrets)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// WriteJSON renders the aggregated result as indented JSON
func WriteJSON(w io.Writer, result *aggregator.AggregatedResult) error {
	if result == nil {
		return fmt.Errorf("no result to write")
	}

	sorted := *result
	sorted.Findings = sortedFindings(result.Findings)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sorted)
}

// maskSecret returns a truncated preview of the secret for safe display
func maskSecret(secret string) string {
	if secret == "" {
		return "(none)"
	}
	if len(secret) <= secretPreviewLen {
		return secret
	}
	return secret[:secretPreviewLen] + "..."
}

// sortedFindings returns findings sorted by file, line and rule for stable output
func sortedFindings(findings []aggregator.AggregatedFinding) []aggregator.AggregatedFinding {
	sorted := make([]aggregator.AggregatedFinding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		if sorted[i].Line != sorted[j].Line {
			return sorted[i].Line < sorted[j].Line
		}
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].SecretHash < sorted[j].SecretHash
	})
	return sorted
}

// sortedKeys returns map keys in sorted order for stable output
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}