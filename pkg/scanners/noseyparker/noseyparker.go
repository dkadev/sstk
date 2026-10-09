package noseyparker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/dkadev/sstk/pkg/scanner"
)

type Scanner struct{}

func (s *Scanner) Name() string {
	return "noseyparker"
}

func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("noseyparker")
	return err == nil
}

func (s *Scanner) Scan(target string) (*scanner.ScanResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("noseyparker is not installed")
	}

	// Noseyparker records findings into a datastore; reserve a temporary
	// path but let noseyparker create the datastore itself
	datastore, err := os.MkdirTemp("", "sstk-noseyparker-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary datastore: %w", err)
	}
	if err := os.Remove(datastore); err != nil {
		return nil, fmt.Errorf("failed to reserve temporary datastore path: %w", err)
	}
	defer os.RemoveAll(datastore)

	cmd := exec.Command("noseyparker", "scan", "--datastore", datastore, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("noseyparker scan failed: %w: %s", err, out)
	}

	cmd = exec.Command("noseyparker", "report", "--datastore", datastore, "--format", "json")
	reportData, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("noseyparker report failed: %w: %s", err, reportData)
	}

	findings, err := parseNoseyparkerOutput(reportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse noseyparker output: %w", err)
	}

	return &scanner.ScanResult{
		ScannerName: s.Name(),
		Findings:    findings,
		RawOutput:   reportData,
	}, nil
}

type npProvenance struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type npSourceSpan struct {
	Start struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"end"`
}

type npMatch struct {
	Provenance []npProvenance `json:"provenance"`
	Location   struct {
		SourceSpan npSourceSpan `json:"source_span"`
	} `json:"location"`
	Groups  []string `json:"groups"`
	Snippet struct {
		Matching string `json:"matching"`
	} `json:"snippet"`
}

type npFinding struct {
	RuleName   string    `json:"rule_name"`
	RuleTextID string    `json:"rule_text_id"`
	Matches    []npMatch `json:"matches"`
}

func parseNoseyparkerOutput(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return []scanner.Finding{}, nil
	}

	var npFindings []npFinding
	if err := json.Unmarshal(data, &npFindings); err != nil {
		return nil, err
	}

	findings := []scanner.Finding{}
	for _, nf := range npFindings {
		if len(nf.Matches) == 0 {
			continue
		}
		match := nf.Matches[0]

		var file string
		if len(match.Provenance) > 0 {
			file = match.Provenance[0].Path
		}

		// Prefer the captured secret group (base64-encoded) over the raw snippet
		secret := match.Snippet.Matching
		if len(match.Groups) > 0 {
			if decoded, err := base64.StdEncoding.DecodeString(match.Groups[0]); err == nil && len(decoded) > 0 {
				secret = string(decoded)
			}
		}

		hash := sha256.Sum256([]byte(secret))

		findings = append(findings, scanner.Finding{
			File:        file,
			Line:        match.Location.SourceSpan.Start.Line,
			Secret:      secret,
			SecretHash:  fmt.Sprintf("%x", hash),
			RuleID:      nf.RuleTextID,
			Description: nf.RuleName,
			StartColumn: match.Location.SourceSpan.Start.Column,
			EndColumn:   match.Location.SourceSpan.End.Column,
		})
	}

	return findings, nil
}