package gitleaks

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dkadev/sstk/pkg/scanner"
)

type Scanner struct{}

func (s *Scanner) Name() string {
	return "gitleaks"
}

func (s *Scanner) IsInstalled() bool {
	_, err := exec.LookPath("gitleaks")
	return err == nil
}

func (s *Scanner) Scan(target string) (*scanner.ScanResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("gitleaks is not installed")
	}

	// Create temporary file for report
	tmpDir := os.TempDir()
	reportFile := filepath.Join(tmpDir, "gitleaks-report.json")
	defer os.Remove(reportFile)

	// Execute gitleaks with JSON output to file
	cmd := exec.Command("gitleaks", "detect", "--source", target, "--report-path", reportFile, "--report-format", "json", "--no-git")

	// Run command and ignore exit code 1 (secrets found)
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means secrets found, which is fine
			if exitErr.ExitCode() != 1 {
				return nil, fmt.Errorf("gitleaks execution failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("gitleaks execution failed: %w", err)
		}
	}

	// Read report file
	var reportData []byte
	if _, err := os.Stat(reportFile); err == nil {
		reportData, err = os.ReadFile(reportFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read gitleaks report: %w", err)
		}
	}

	// Parse gitleaks JSON output
	findings, err := parseGitleaksOutput(reportData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output: %w", err)
	}

	return &scanner.ScanResult{
		ScannerName: s.Name(),
		Findings:    findings,
		RawOutput:   reportData,
	}, nil
}

type gitleaksOutput struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
}

func parseGitleaksOutput(data []byte) ([]scanner.Finding, error) {
	if len(data) == 0 {
		return []scanner.Finding{}, nil
	}

	var gitleaksFindings []gitleaksOutput
	if err := json.Unmarshal(data, &gitleaksFindings); err != nil {
		return nil, err
	}

	var findings []scanner.Finding
	for _, gf := range gitleaksFindings {
		// Create hash for deduplication
		hash := sha256.Sum256([]byte(gf.Secret))

		findings = append(findings, scanner.Finding{
			File:        gf.File,
			Line:        gf.StartLine,
			Secret:      gf.Secret,
			SecretHash:  fmt.Sprintf("%x", hash),
			RuleID:      gf.RuleID,
			Description: gf.Description,
			StartColumn: gf.StartColumn,
			EndColumn:   gf.EndColumn,
		})
	}

	return findings, nil
}
