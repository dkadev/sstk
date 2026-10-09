package titus

import (
	"encoding/base64"
	"testing"
)

var sampleReport = `[
  {
    "ID": "abc123",
    "RuleID": "np.generic.2",
    "Groups": ["` + base64.StdEncoding.EncodeToString([]byte("sk_live_dummy000000000000000")) + `"],
    "Matches": [
      {
        "BlobID": "deadbeef",
        "StructuralID": "sid",
        "FindingID": "abc123",
        "RuleID": "np.generic.2",
        "RuleName": "Generic API Key",
        "Location": {
          "Offset": {"Start": 10, "End": 50},
          "Source": {
            "Start": {"Line": 2, "Column": 1},
            "End": {"Line": 2, "Column": 46}
          }
        },
        "Groups": ["` + base64.StdEncoding.EncodeToString([]byte("sk_live_dummy000000000000000")) + `"],
        "NamedGroups": null,
        "Snippet": {
          "Before": "` + base64.StdEncoding.EncodeToString([]byte("api_key=\"")) + `",
          "Matching": "` + base64.StdEncoding.EncodeToString([]byte("api_key=\"sk_live_dummy000000000000000")) + `",
          "After": ""
        },
        "file_path": "repo/more.txt"
      }
    ],
    "Score": null
  },
  {
    "ID": "def456",
    "RuleID": "np.generic.5",
    "Groups": [],
    "Matches": [],
    "Score": null
  }
]`

func TestParseTitusOutput(t *testing.T) {
	findings, err := parseTitusOutput([]byte(sampleReport))
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

func TestParseTitusOutputFallbackToSnippet(t *testing.T) {
	report := `[
  {
    "RuleID": "np.generic.5",
    "Matches": [
      {
        "RuleName": "Generic Password",
        "Location": {"Source": {"Start": {"Line": 3, "Column": 5}, "End": {"Line": 3, "Column": 20}}},
        "Groups": null,
        "Snippet": {"Matching": "` + base64.StdEncoding.EncodeToString([]byte("hunter2")) + `"},
        "file_path": "repo/pw.txt"
      }
    ]
  }
]`
	findings, err := parseTitusOutput([]byte(report))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Secret != "hunter2" {
		t.Errorf("Secret = %q", findings[0].Secret)
	}
}

func TestParseTitusOutputEmpty(t *testing.T) {
	findings, err := parseTitusOutput([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseTitusOutputEmptyReport(t *testing.T) {
	findings, err := parseTitusOutput([]byte("[]"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseTitusOutputInvalid(t *testing.T) {
	if _, err := parseTitusOutput([]byte("not json")); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
