package detectsecrets

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleReport = `{
  "version": "1.5.0",
  "plugins_used": [],
  "results": {
    "repo/aws.txt": [
      {
        "type": "AWS Access Key",
        "filename": "repo/aws.txt",
        "hashed_secret": "1db7fa67f2cf0a8f92f567b1757275df337c140e",
        "is_verified": false,
        "line_number": 1
      }
    ]
  }
}`

func TestParseDetectSecretsOutputWithoutFile(t *testing.T) {
	findings, err := parseDetectSecretsOutput([]byte(sampleReport), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.File != "repo/aws.txt" {
		t.Errorf("File = %q", f.File)
	}
	if f.Line != 1 {
		t.Errorf("Line = %d", f.Line)
	}
	if f.RuleID != "AWS Access Key" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	// Without the source file the secret cannot be recovered
	if f.Secret != "[REDACTED]" {
		t.Errorf("Secret = %q, want [REDACTED]", f.Secret)
	}
	if f.SecretHash == "" {
		t.Error("SecretHash is empty")
	}
}

func TestParseDetectSecretsOutputRecoversSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.env")
	// sha1("dummy_secret_12345") = 20e0a6c8ce13fbef8439fde4c5a2f18fb759893f
	if err := os.WriteFile(path, []byte("password = \"dummy_secret_12345\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report := `{
      "results": {
        "` + path + `": [
          {
            "type": "Secret Keyword",
            "hashed_secret": "20e0a6c8ce13fbef8439fde4c5a2f18fb759893f",
            "line_number": 1
          }
        ]
      }
    }`

	findings, err := parseDetectSecretsOutput([]byte(report), ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Secret != "dummy_secret_12345" {
		t.Errorf("Secret = %q, want recovered dummy_secret_12345", f.Secret)
	}
	if f.SecretHash == "" {
		t.Error("SecretHash is empty")
	}
}

func TestLineCandidates(t *testing.T) {
	candidates := lineCandidates(`db_password: "Dummy_PgPass!2024",`)
	found := false
	for _, c := range candidates {
		if c == "Dummy_PgPass!2024" {
			found = true
		}
	}
	if !found {
		t.Errorf("candidates missing secret value: %v", candidates)
	}
}

func TestLineCandidatesURLPassword(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`# sqlalchemy.url = driver://user:pass@localhost/dbname`, "pass"},
		{`sqlalchemy.url = postgresql://shopflow_admin:Dummy_PgPass!2024@prod-db:5432/shopflow`, "Dummy_PgPass!2024"},
		// Password containing "@": both the first-@ and last-@ cuts are tried
		{`_MONGO_URI = "mongodb://admin:Dummy_M0ng0_P@ss@prod-mongo:27017/db"`, "Dummy_M0ng0_P@ss"},
		// Password with several "@" (last @ separates credentials from host)
		{`_URI = "mongodb://admin:p@ss@w@rd@prod-mongo:27017/db"`, "p@ss@w@rd"},
		// "@" in password AND in path: every @ is tried as a cut point
		{`_URI2 = "redis://:dummy_r3d1s_P@ss@cache:6379/db@shard1"`, "dummy_r3d1s_P@ss"},
	}
	for _, tt := range tests {
		found := false
		for _, c := range lineCandidates(tt.line) {
			if c == tt.want {
				found = true
			}
		}
		if !found {
			t.Errorf("lineCandidates(%q) missing %q", tt.line, tt.want)
		}
	}
}

func TestLineCandidatesUnescape(t *testing.T) {
	line := `"privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA==\n-----END RSA PRIVATE KEY-----"`
	want := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA==\n-----END RSA PRIVATE KEY-----"

	found := false
	for _, c := range lineCandidates(line) {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Error("candidates missing unescaped private key value")
	}
}

func TestUnescape(t *testing.T) {
	got := unescape(`a\nb\tc\"d\\e`)
	want := "a\nb\tc\"d\\e"
	if got != want {
		t.Errorf("unescape result = %q, want %q", got, want)
	}
}

func TestParseDetectSecretsOutputEmpty(t *testing.T) {
	findings, err := parseDetectSecretsOutput([]byte(`{"results": {}}`), ".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestParseDetectSecretsOutputInvalid(t *testing.T) {
	if _, err := parseDetectSecretsOutput([]byte("not json"), "."); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}