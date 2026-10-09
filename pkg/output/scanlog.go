package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dkadev/sstk/pkg/aggregator"
)

// WriteCSV renders the aggregated result as CSV, suitable for
// spreadsheets and data ingestion
func WriteCSV(w io.Writer, result *aggregator.AggregatedResult, showSecrets bool) error {
	if result == nil {
		return fmt.Errorf("no result to write")
	}

	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"File", "Line", "RuleID", "Description", "Secret", "Found By", "Occurrences"}); err != nil {
		return err
	}

	for _, f := range sortedFindings(result.Findings) {
		var occurrences string
		if len(f.Occurrences) > 1 {
			parts := make([]string, len(f.Occurrences))
			for i, o := range f.Occurrences {
				parts[i] = fmt.Sprintf("%s:%d", o.File, o.Line)
			}
			occurrences = strings.Join(parts, "; ")
		}

		secret := maskSecret(f.Secret)
		if showSecrets {
			secret = f.Secret
		}
		record := []string{
			f.File,
			fmt.Sprintf("%d", f.Line),
			f.RuleID,
			f.Description,
			secret,
			strings.Join(f.FoundBy, "; "),
			occurrences,
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

// WriteScanLog renders the summary statistics log generated with every scan
func WriteScanLog(w io.Writer, timestamp time.Time, target string, scanners []string, result *aggregator.AggregatedResult) error {
	if result == nil {
		return fmt.Errorf("no result to write")
	}

	var b strings.Builder

	fmt.Fprintf(&b, "=== SSTK Scan Log ===\n")
	fmt.Fprintf(&b, "Timestamp: %s\n", timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Target: %s\n", target)

	fmt.Fprintf(&b, "\nScanners Used:\n")
	for _, name := range scanners {
		fmt.Fprintf(&b, "  - %s\n", name)
	}

	fmt.Fprintf(&b, "\n=== Summary Statistics ===\n")
	fmt.Fprintf(&b, "Total Findings: %d\n", result.TotalFindings)
	fmt.Fprintf(&b, "Unique Secrets: %d\n", result.UniqueSecrets)

	fmt.Fprintf(&b, "\nFindings by Scanner:\n")
	for _, name := range sortedKeys(result.ScannerStats) {
		fmt.Fprintf(&b, "  %s: %d\n", name, result.ScannerStats[name])
	}

	if result.UniqueSecrets > 0 {
		fmt.Fprintf(&b, "\nWARNING: %d unique secret(s) detected!\n", result.UniqueSecrets)
	}

	_, err := io.WriteString(w, b.String())
	return err
}