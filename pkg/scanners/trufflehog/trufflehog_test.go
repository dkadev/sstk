package trufflehog

import (
	"testing"
)

const sampleNDJSON = `
{"SourceMetadata":{"Data":{"Filesystem":{"file":"src/auth.js","line":42}}},"DetectorName":"github-token","Raw":"ghp_abcdefghijklmnop","Verified":false}
not a json line
{"SourceMetadata":{"Data":{"Filesystem":{"file":"src/app.js","line":7}}},"DetectorName":"aws-key","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":true}`

func TestParseTrufflehogOutput(t *testing.T) {
	findings, err := parseTrufflehogOutput([]byte(sampleNDJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (invalid line skipped)", len(findings))
	}

	f := findings[0]
	if f.File != "src/auth.js" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 42 {
		t.Errorf("Line = %d", f.Line)
	}
	if f.RuleID != "github-token" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Secret != "ghp_abcdefghijklmnop" {
		t.Errorf("Secret = %q", f.Secret)
	}
	if f.SecretHash == "" {
		t.Error("SecretHash is empty")
	}

	// Last line without trailing newline must be parsed
	if findings[1].File != "src/app.js" || findings[1].Line != 7 {
		t.Errorf("last line not parsed correctly: %+v", findings[1])
	}
}

func TestParseTrufflehogOutputSkipsIncomplete(t *testing.T) {
	incomplete := `{"SourceMetadata":{"Data":{"Filesystem":{"file":"","line":1}}},"DetectorName":"","Raw":""}`
	findings, err := parseTrufflehogOutput([]byte(incomplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseTrufflehogOutputEmpty(t *testing.T) {
	findings, err := parseTrufflehogOutput([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}