package trufflehog

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"

	scannerpkg "github.com/dkadev/sstk/pkg/scanner"
)

type Scanner struct{}

func (s *Scanner) Name() string {
	return "trufflehog"
}

func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("trufflehog")
	return err == nil
}

func (s *Scanner) Scan(target string) (*scannerpkg.ScanResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("trufflehog is not installed")
	}

	// Execute trufflehog with JSON output
	cmd := exec.Command("trufflehog", "filesystem", target, "--json")
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Trufflehog may return errors even on success
		if len(output) == 0 {
			return nil, fmt.Errorf("trufflehog execution failed: %w", err)
		}
	}

	// Parse trufflehog JSON output (one JSON object per line)
	findings, err := parseTrufflehogOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trufflehog output: %w", err)
	}

	return &scannerpkg.ScanResult{
		ScannerName: s.Name(),
		Findings:    findings,
		RawOutput:   output,
	}, nil
}

type trufflehogOutput struct {
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	DetectorName string `json:"DetectorName"`
	Raw          string `json:"Raw"`
	Verified     bool   `json:"Verified"`
}

func parseTrufflehogOutput(data []byte) ([]scannerpkg.Finding, error) {
	if len(data) == 0 {
		return []scannerpkg.Finding{}, nil
	}

	var findings []scannerpkg.Finding

	// Simple line-by-line parsing for NDJSON (newline-delimited JSON)
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				finding := parseTrufflehogLine(data[start:i])
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
			start = i + 1
		}
	}

	// Handle last line if no trailing newline
	if start < len(data) {
		finding := parseTrufflehogLine(data[start:])
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// parseTrufflehogLine parses a single line of trufflehog JSON output
// Returns nil if the line is invalid or contains empty/invalid data
func parseTrufflehogLine(line []byte) *scannerpkg.Finding {
	var tf trufflehogOutput
	if err := json.Unmarshal(line, &tf); err != nil {
		return nil
	}

	// Validate that we have actual data (not empty fields)
	if tf.Raw == "" || tf.DetectorName == "" || tf.SourceMetadata.Data.Filesystem.File == "" {
		return nil
	}

	// Create hash for deduplication
	hash := sha256.Sum256([]byte(tf.Raw))

	return &scannerpkg.Finding{
		File:        tf.SourceMetadata.Data.Filesystem.File,
		Line:        tf.SourceMetadata.Data.Filesystem.Line,
		Secret:      tf.Raw,
		SecretHash:  fmt.Sprintf("%x", hash),
		RuleID:      tf.DetectorName,
		Description: fmt.Sprintf("Detector: %s (Verified: %v)", tf.DetectorName, tf.Verified),
	}
}
