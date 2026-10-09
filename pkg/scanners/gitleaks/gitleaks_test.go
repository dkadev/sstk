package gitleaks

import (
	"testing"
)

const sampleReport = `[
  {
    "Description": "Stripe Access Token",
    "StartLine": 15,
    "EndLine": 15,
    "StartColumn": 12,
    "EndColumn": 47,
    "Match": "sk_live_abcdefghijklmnop",
    "Secret": "sk_live_abcdefghijklmnop",
    "File": "config/production.env",
    "RuleID": "stripe-access-token"
  }
]`

func TestParseGitleaksOutput(t *testing.T) {
	findings, err := parseGitleaksOutput([]byte(sampleReport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.File != "config/production.env" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 15 {
		t.Errorf("Line = %d", f.Line)
	}
	if f.RuleID != "stripe-access-token" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Secret != "sk_live_abcdefghijklmnop" {
		t.Errorf("Secret = %q", f.Secret)
	}
	if f.SecretHash == "" {
		t.Error("SecretHash is empty")
	}
	if f.StartColumn != 12 || f.EndColumn != 47 {
		t.Errorf("columns = %d-%d", f.StartColumn, f.EndColumn)
	}
}

func TestParseGitleaksOutputEmpty(t *testing.T) {
	findings, err := parseGitleaksOutput([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseGitleaksOutputInvalid(t *testing.T) {
	if _, err := parseGitleaksOutput([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}