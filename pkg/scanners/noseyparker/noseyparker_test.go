package noseyparker

import (
	"encoding/base64"
	"testing"
)

var sampleReport = `[
  {
    "rule_name": "Generic API Key",
    "rule_text_id": "np.generic.2",
    "matches": [
      {
        "provenance": [{"kind": "file", "path": "repo/more.txt"}],
        "location": {
          "source_span": {
            "start": {"line": 2, "column": 1},
            "end": {"line": 2, "column": 46}
          }
        },
        "groups": ["` + base64.StdEncoding.EncodeToString([]byte("sk_live_dummy000000000000000")) + `"],
        "snippet": {"matching": "api_key=\"sk_live_dummy000000000000000"}
      }
    ]
  },
  {
    "rule_name": "Generic Password",
    "rule_text_id": "np.generic.5",
    "matches": []
  }
]`

func TestParseNoseyparkerOutput(t *testing.T) {
	findings, err := parseNoseyparkerOutput([]byte(sampleReport))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Findings without matches are skipped
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.File != "repo/more.txt" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 2 {
		t.Errorf("Line = %d", f.Line)
	}
	if f.RuleID != "np.generic.2" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Description != "Generic API Key" {
		t.Errorf("Description = %q", f.Description)
	}
	// The base64 group must be decoded into the secret
	if f.Secret != "sk_live_dummy000000000000000" {
		t.Errorf("Secret = %q", f.Secret)
	}
	if f.SecretHash == "" {
		t.Error("SecretHash is empty")
	}
	if f.StartColumn != 1 || f.EndColumn != 46 {
		t.Errorf("columns = %d-%d", f.StartColumn, f.EndColumn)
	}
}

func TestParseNoseyparkerOutputEmpty(t *testing.T) {
	findings, err := parseNoseyparkerOutput([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseNoseyparkerOutputEmptyReport(t *testing.T) {
	findings, err := parseNoseyparkerOutput([]byte("[]"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseNoseyparkerOutputInvalid(t *testing.T) {
	if _, err := parseNoseyparkerOutput([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}