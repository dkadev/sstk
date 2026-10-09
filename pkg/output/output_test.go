package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dkadev/sstk/pkg/aggregator"
	"github.com/dkadev/sstk/pkg/scanner"
)

func sampleResult() *aggregator.AggregatedResult {
	agg, err := aggregator.Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{
			{File: "src/app.js", Line: 7, Secret: "short", SecretHash: "hash-b", RuleID: "aws-key", Description: "AWS Key"},
			{File: "config/production.env", Line: 15, Secret: "sk_live_abcdefghijklmnop", SecretHash: "hash-a", RuleID: "stripe-access-token", Description: "Stripe Token"},
			{File: "backup/old.env", Line: 3, Secret: "sk_live_abcdefghijklmnop", SecretHash: "hash-a", RuleID: "stripe-access-token", Description: "Stripe Token"},
		}},
		{ScannerName: "trufflehog", Findings: []scanner.Finding{
			{File: "src/app.js", Line: 7, Secret: "short", SecretHash: "hash-b", RuleID: "aws-key", Description: "AWS Key"},
		}},
	}, aggregator.DedupByValue)
	if err != nil {
		panic(err)
	}
	return agg
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult(), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Total Findings: 4",
		"Unique Secrets: 2",
		"gitleaks: 3 findings",
		"trufflehog: 1 findings",
		"config/production.env",
		"Found by: gitleaks, trufflehog",
		// Secrets must be masked in text output
		"sk_live_...",
		// Same secret in two files: occurrences listed
		"Occurrences (2):",
		"      - config/production.env:15",
		"      - backup/old.env:3",
		// Sorted: config/... before src/...
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	if strings.Contains(out, "sk_live_abcdefghijklmnop") {
		t.Error("text output leaks full secret")
	}

	// Findings must be sorted by file
	if !strings.Contains(out, "config/production.env\n    Line: 15\n    Rule: stripe-access-token") {
		t.Errorf("findings not sorted or malformed:\n%s", out)
	}
}

func TestWriteTextShowSecrets(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult(), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "sk_live_abcdefghijklmnop") {
		t.Error("showSecrets must emit the raw secret value")
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var decoded aggregator.AggregatedResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.TotalFindings != 4 || decoded.UniqueSecrets != 2 {
		t.Errorf("unexpected counts: %+v", decoded)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(decoded.Findings))
	}
	if decoded.Findings[0].File != "config/production.env" {
		t.Errorf("findings not sorted: %+v", decoded.Findings)
	}
	if len(decoded.Findings[1].FoundBy) != 2 {
		t.Errorf("FoundBy = %v", decoded.Findings[1].FoundBy)
	}
	// Occurrences must be serialized for multi-location secrets
	if len(decoded.Findings[0].Occurrences) != 2 {
		t.Errorf("Occurrences = %v, want 2", decoded.Findings[0].Occurrences)
	}
	if decoded.Findings[0].Occurrences[1] != (aggregator.Occurrence{File: "backup/old.env", Line: 3}) {
		t.Errorf("unexpected occurrence: %+v", decoded.Findings[0].Occurrences[1])
	}
}

func TestWriteDispatch(t *testing.T) {
	tests := []struct {
		format string
		err    bool
	}{
		{"text", false},
		{"json", false},
		{"csv", false},
		{"xml", true},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		err := Write(&buf, tt.format, sampleResult(), false)
		if (err != nil) != tt.err {
			t.Errorf("Write(%q) error = %v, want error %v", tt.format, err, tt.err)
		}
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleResult(), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 { // header + 2 unique findings
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), buf.String())
	}

	if lines[0] != "File,Line,RuleID,Description,Secret,Found By,Occurrences" {
		t.Errorf("unexpected header: %q", lines[0])
	}

	// Rows must be sorted by file like the other formats
	if !strings.HasPrefix(lines[1], "config/production.env,15,stripe-access-token") {
		t.Errorf("first row not sorted or malformed: %q", lines[1])
	}
	// Secret must be masked
	if strings.Contains(lines[1], "sk_live_abcdefghijklmnop") {
		t.Errorf("csv leaks full secret: %q", lines[1])
	}
	// Multi-location secret lists its occurrences
	if !strings.HasSuffix(lines[1], "config/production.env:15; backup/old.env:3") {
		t.Errorf("Occurrences not listed: %q", lines[1])
	}
	// Second finding was found by both scanners
	if !strings.Contains(lines[2], "src/app.js,7,aws-key") || !strings.HasSuffix(lines[2], "gitleaks; trufflehog,") {
		t.Errorf("second row malformed: %q", lines[2])
	}
}

func TestWriteCSVShowSecrets(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleResult(), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// Row for the stripe key must carry the raw secret value
	if !strings.Contains(lines[1], "sk_live_abcdefghijklmnop") {
		t.Errorf("showSecrets must emit the raw secret value: %q", lines[1])
	}
}

func TestWriteLocationMode(t *testing.T) {
	agg, err := aggregator.Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{
			{File: "a.env", Line: 1, Secret: "s3cr3t", SecretHash: "h1", RuleID: "r"},
			{File: "b.env", Line: 2, Secret: "s3cr3t", SecretHash: "h1", RuleID: "r"},
		}},
	}, aggregator.DedupByLocation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Text output in location mode: two findings, no occurrences section
	var buf bytes.Buffer
	if err := WriteText(&buf, agg, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Occurrences (") {
		t.Error("location mode should not render an occurrences section")
	}
	if !strings.Contains(out, "a.env") || !strings.Contains(out, "b.env") {
		t.Errorf("both locations must appear as findings:\n%s", out)
	}
}

func TestWriteScanLog(t *testing.T) {
	ts := time.Date(2026, 1, 26, 23, 28, 34, 0, time.FixedZone("+01", 3600))
	var buf bytes.Buffer
	err := WriteScanLog(&buf, ts, "./samples", []string{"gitleaks", "trufflehog"}, sampleResult())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"=== SSTK Scan Log ===",
		"Timestamp: 2026-01-26T23:28:34+01:00",
		"Target: ./samples",
		"  - gitleaks",
		"Total Findings: 4",
		"Unique Secrets: 2",
		"  gitleaks: 3",
		"  trufflehog: 1",
		"WARNING: 2 unique secret(s) detected!",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan log missing %q", want)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "(none)"},
		{"abc", "abc"},
		{"abcdefgh", "abcdefgh"},
		{"abcdefghi", "abcdefgh..."},
	}
	for _, tt := range tests {
		if got := maskSecret(tt.in); got != tt.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}