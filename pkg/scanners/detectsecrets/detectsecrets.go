package detectsecrets

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dkadev/sstk/pkg/scanner"
)

type Scanner struct{}

func (s *Scanner) Name() string {
	return "detect-secrets"
}

func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("detect-secrets")
	return err == nil
}

func (s *Scanner) Scan(target string) (*scanner.ScanResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("detect-secrets is not installed")
	}

	// Execute detect-secrets scan
	cmd := exec.Command("detect-secrets", "scan", target, "--all-files")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("detect-secrets execution failed: %w", err)
	}

	// Parse detect-secrets JSON output; recover the raw secret value
	// from the source file where possible
	findings, err := parseDetectSecretsOutput(output, target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse detect-secrets output: %w", err)
	}

	return &scanner.ScanResult{
		ScannerName: s.Name(),
		Findings:    findings,
		RawOutput:   output,
	}, nil
}

type detectSecretsOutput struct {
	Results map[string][]struct {
		Type         string `json:"type"`
		LineNumber   int    `json:"line_number"`
		HashedSecret string `json:"hashed_secret"`
	} `json:"results"`
}

func parseDetectSecretsOutput(data []byte, target string) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return []scanner.Finding{}, nil
	}

	var dsOutput detectSecretsOutput
	if err := json.Unmarshal(data, &dsOutput); err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	for path, secrets := range dsOutput.Results {
		for _, secret := range secrets {
			// detect-secrets only exposes sha1(secret); recover the raw
			// value from the reported file line where possible.
			// Note: Private Key findings hash a denylist marker, not the
			// key material, so they stay redacted by design.
			value := recoverSecret(resolvePath(path, target), secret.LineNumber, secret.HashedSecret)

			// Hash the raw secret when recovered; otherwise fall back to
			// hashing detect-secrets' own hash so duplicates still dedup
			hashInput := secret.HashedSecret
			if value == "" {
				value = scanner.RedactedSecret
			} else {
				hashInput = value
			}
			hash := sha256.Sum256([]byte(hashInput))

			findings = append(findings, scanner.Finding{
				File:        path,
				Line:        secret.LineNumber,
				Secret:      value,
				SecretHash:  hex.EncodeToString(hash[:]),
				RuleID:      secret.Type,
				Description: fmt.Sprintf("Secret Type: %s", secret.Type),
			})
		}
	}

	return findings, nil
}

// resolvePath finds a readable path for the file reported by detect-secrets,
// which emits paths relative to the scan invocation
func resolvePath(path, target string) string {
	for _, candidate := range []string{path, filepath.Join(target, path)} {
		if b, err := os.ReadFile(candidate); err == nil {
			_ = b
			return candidate
		}
	}
	return path
}

// recoverSecret returns the raw secret value whose sha1 matches hashedSecret,
// searching the candidate tokens of the given file line
func recoverSecret(path string, line int, hashedSecret string) string {
	if hashedSecret == "" || line <= 0 {
		return ""
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(content), "\n")
	if line > len(lines) {
		return ""
	}

	for _, candidate := range lineCandidates(lines[line-1]) {
		sum := sha1.Sum([]byte(candidate))
		if hex.EncodeToString(sum[:]) == hashedSecret {
			return candidate
		}
	}
	return ""
}

// lineCandidates returns plausible secret candidates from a source line
func lineCandidates(line string) []string {
	var candidates []string
	seen := make(map[string]bool)

	add := func(s string) {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ",")
		s = strings.TrimSuffix(s, ";")
		s = strings.Trim(s, "\"'`")
		if s != "" && !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	// The whole line
	add(line)

	for _, field := range strings.Fields(line) {
		// The field itself (stripped of quotes and separators)
		add(field)
		// Value after "key=" assignments
		if i := strings.Index(field, "="); i >= 0 {
			add(field[i+1:])
		}
		// Value after "key:" assignments (yaml, json-ish)
		if i := strings.LastIndex(field, ":"); i >= 0 {
			add(field[i+1:])
		}
		// Password inside URL credentials: scheme://user:pass@host
		if i := strings.Index(field, "://"); i >= 0 {
			rest := field[i+3:]
			if j := strings.Index(rest, ":"); j >= 0 {
				userpass := rest[j+1:]
				// The password (or anything after it: host, path) may
				// contain "@"; since the credential terminator is
				// ambiguous, enumerate a cut at every "@" and let the
				// sha1 comparison pick the right one
				for at := 0; at < len(userpass); at++ {
					if userpass[at] == '@' {
						add(userpass[:at])
					}
				}
			}
		}
	}

	// Values carrying JSON-style escapes (e.g. "\n" in multiline private
	// keys) are hashed by detect-secrets in their unescaped form
	// Quoted strings spanning several words (private keys, certificates)
	// are not covered by the field-based candidates above
	for _, q := range quotedValues(line) {
		add(q)
	}
	copies := append([]string(nil), candidates...)
	for _, c := range copies {
		if strings.Contains(c, `\n`) || strings.Contains(c, `\t`) || strings.Contains(c, `\"`) || strings.Contains(c, `\\`) {
			add(unescape(c))
		}
	}

	return candidates
}

// quotedValues returns the content of every double-quoted string in the line
func quotedValues(line string) []string {
	var values []string
	start := -1
	for i, r := range line {
		if r == '"' {
			if start >= 0 {
				values = append(values, line[start+1:i])
				start = -1
			} else {
				start = i
			}
		}
	}
	return values
}

// unescape replaces common JSON-style escape sequences with their real bytes
func unescape(s string) string {
	r := strings.NewReplacer(
		`\n`, "\n",
		`\t`, "\t",
		`\"`, `"`,
		`\\`, `\`,
	)
	return r.Replace(s)
}