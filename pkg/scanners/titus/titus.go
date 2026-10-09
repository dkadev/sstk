package titus

import (
	"bytes"
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
	return "titus"
}

func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("titus")
	return err == nil
}

func (s *Scanner) Scan(target string) (*scanner.ScanResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("titus is not installed")
	}

	// Titus records findings into a datastore; reserve a temporary
	// path but let titus create the datastore itself
	datastore, err := os.MkdirTemp("", "sstk-titus-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary datastore: %w", err)
	}
	if err := os.Remove(datastore); err != nil {
		return nil, fmt.Errorf("failed to reserve temporary datastore path: %w", err)
	}
	defer os.RemoveAll(datastore)

	cmd := exec.Command("titus", "scan", "--output", datastore, target)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("titus scan failed: %w: %s", err, out)
	}

	cmd = exec.Command("titus", "report", "--datastore", datastore, "--format", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	reportData, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("titus report failed: %w: %s", err, stderr.String())
	}

	findings, err := parseTitusOutput(reportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse titus output: %w", err)
	}

	return &scanner.ScanResult{
		ScannerName: s.Name(),
		Findings:    findings,
		RawOutput:   reportData,
	}, nil
}

type tSourcePoint struct {
	Line   int `json:"Line"`
	Column int `json:"Column"`
}

type tSourceSpan struct {
	Start tSourcePoint `json:"Start"`
	End   tSourcePoint `json:"End"`
}

type tLocation struct {
	Source tSourceSpan `json:"Source"`
}

type tSnippet struct {
	Matching string `json:"Matching"`
}

type tMatch struct {
	RuleName  string    `json:"RuleName"`
	FilePath  string    `json:"file_path"`
	Location  tLocation `json:"Location"`
	Groups    []string  `json:"Groups"`
	Snippet   tSnippet   `json:"Snippet"`
}

type tFinding struct {
	RuleID  string   `json:"RuleID"`
	Matches []tMatch `json:"Matches"`
}

func parseTitusOutput(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return []scanner.Finding{}, nil
	}

	var tFindings []tFinding
	if err := json.Unmarshal(data, &tFindings); err != nil {
		return nil, err
	}

	findings := []scanner.Finding{}
	for _, tf := range tFindings {
		if len(tf.Matches) == 0 {
			continue
		}
		match := tf.Matches[0]

		// Prefer the captured secret group (base64-encoded) over the raw
		// snippet; both groups and snippet fields are base64-encoded bytes
		secret := match.Snippet.Matching
		if decoded, err := base64.StdEncoding.DecodeString(secret); err == nil && len(decoded) > 0 {
			secret = string(decoded)
		}
		if len(match.Groups) > 0 {
			if decoded, err := base64.StdEncoding.DecodeString(match.Groups[0]); err == nil && len(decoded) > 0 {
				secret = string(decoded)
			}
		}

		hash := sha256.Sum256([]byte(secret))

		findings = append(findings, scanner.Finding{
			File:        match.FilePath,
			Line:        match.Location.Source.Start.Line,
			Secret:      secret,
			SecretHash:  fmt.Sprintf("%x", hash),
			RuleID:      tf.RuleID,
			Description: match.RuleName,
			StartColumn: match.Location.Source.Start.Column,
			EndColumn:   match.Location.Source.End.Column,
		})
	}

	return findings, nil
}
