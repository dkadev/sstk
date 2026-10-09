package aggregator

import (
	"testing"

	"github.com/dkadev/sstk/pkg/scanner"
)

var (
	secretA  = scanner.Finding{File: "a.env", Line: 1, Secret: "secret-a", SecretHash: "hash-a", RuleID: "rule-1"}
	secretA2 = scanner.Finding{File: "other.txt", Line: 9, Secret: "secret-a", SecretHash: "hash-a", RuleID: "rule-1"}
	secretB  = scanner.Finding{File: "b.env", Line: 2, Secret: "secret-b", SecretHash: "hash-b", RuleID: "rule-2"}
)

func TestAggregateByValue(t *testing.T) {
	got, err := Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{secretA}},
		{ScannerName: "trufflehog", Findings: []scanner.Finding{secretA, secretB}},
		{ScannerName: "noseyparker", Findings: []scanner.Finding{secretA2}},
	}, DedupByValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.TotalFindings != 4 {
		t.Errorf("TotalFindings = %d, want 4", got.TotalFindings)
	}
	if got.UniqueSecrets != 2 {
		t.Errorf("UniqueSecrets = %d, want 2", got.UniqueSecrets)
	}

	byHash := make(map[string]AggregatedFinding, len(got.Findings))
	for _, f := range got.Findings {
		byHash[f.SecretHash] = f
	}

	fa, ok := byHash["hash-a"]
	if !ok {
		t.Fatal("missing finding with hash-a")
	}
	// Same value found in two locations by three scanners: one finding,
	// all scanners listed, all locations tracked
	if len(fa.FoundBy) != 3 {
		t.Errorf("FoundBy = %v, want 3 scanners", fa.FoundBy)
	}
	if len(fa.Occurrences) != 2 {
		t.Errorf("Occurrences = %v, want 2 locations", fa.Occurrences)
	}
	want := Occurrence{File: "other.txt", Line: 9}
	found := false
	for _, o := range fa.Occurrences {
		if o == want {
			found = true
		}
	}
	if !found {
		t.Errorf("Occurrences missing other.txt:9: %v", fa.Occurrences)
	}

	fb, ok := byHash["hash-b"]
	if !ok {
		t.Fatal("missing finding with hash-b")
	}
	if len(fb.FoundBy) != 1 || fb.FoundBy[0] != "trufflehog" {
		t.Errorf("FoundBy = %v, want [trufflehog]", fb.FoundBy)
	}
}

func TestAggregateByLocation(t *testing.T) {
	got, err := Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{secretA}},
		{ScannerName: "trufflehog", Findings: []scanner.Finding{secretA2, secretA}},
	}, DedupByLocation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same secret in two locations: two independent findings
	if got.UniqueSecrets != 2 {
		t.Errorf("UniqueSecrets = %d, want 2", got.UniqueSecrets)
	}

	byLoc := make(map[string]AggregatedFinding)
	for _, f := range got.Findings {
		byLoc[f.File] = f
	}

	fa, ok := byLoc["a.env"]
	if !ok {
		t.Fatal("missing finding at a.env")
	}
	if fa.Line != 1 {
		t.Errorf("Line = %d, want 1", fa.Line)
	}
	if len(fa.FoundBy) != 2 {
		t.Errorf("FoundBy = %v, want both scanners", fa.FoundBy)
	}
	if len(fa.Occurrences) != 0 {
		t.Errorf("Occurrences should be empty in location mode, got %v", fa.Occurrences)
	}

	fo, ok := byLoc["other.txt"]
	if !ok {
		t.Fatal("missing finding at other.txt")
	}
	if len(fo.FoundBy) != 1 || fo.FoundBy[0] != "trufflehog" {
		t.Errorf("FoundBy = %v, want [trufflehog]", fo.FoundBy)
	}
}

func TestAggregateEmptyResults(t *testing.T) {
	got, err := Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{}},
		nil,
	}, DedupByValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TotalFindings != 0 || got.UniqueSecrets != 0 {
		t.Errorf("unexpected counts for empty results: %+v", got)
	}
}

func TestAggregateInvalidMode(t *testing.T) {
	if _, err := Aggregate(nil, "nonsense"); err == nil {
		t.Fatal("expected error for invalid dedup mode")
	}
}

func TestAggregateRedactsPrivateKeys(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplB\n-----END RSA PRIVATE KEY-----"
	got, err := Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{
			{File: "key.pem", Line: 1, Secret: pem, SecretHash: "hash-pem", RuleID: "private-key"},
		}},
		{ScannerName: "trufflehog", Findings: []scanner.Finding{
			{File: "key.pem", Line: 1, Secret: pem, SecretHash: "hash-pem", RuleID: "PrivateKey"},
		}},
	}, DedupByValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (same value dedups)", len(got.Findings))
	}
	f := got.Findings[0]
	if f.Secret != scanner.RedactedSecret {
		t.Errorf("private key material not redacted: %q", f.Secret)
	}
	// Hash and scanner attribution survive redaction
	if f.SecretHash != "hash-pem" {
		t.Errorf("SecretHash changed by redaction: %q", f.SecretHash)
	}
	if len(f.FoundBy) != 2 {
		t.Errorf("FoundBy = %v, want both scanners", f.FoundBy)
	}
}

func TestAggregateScannerStats(t *testing.T) {
	got, err := Aggregate([]*scanner.ScanResult{
		{ScannerName: "gitleaks", Findings: []scanner.Finding{secretA}},
		{ScannerName: "trufflehog", Findings: []scanner.Finding{secretA, secretB}},
	}, DedupByValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ScannerStats["gitleaks"] != 1 {
		t.Errorf("gitleaks stats = %d, want 1", got.ScannerStats["gitleaks"])
	}
	if got.ScannerStats["trufflehog"] != 2 {
		t.Errorf("trufflehog stats = %d, want 2", got.ScannerStats["trufflehog"])
	}
}