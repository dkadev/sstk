package aggregator

import (
	"fmt"
	"strings"

	"github.com/dkadev/sstk/pkg/scanner"
)

// Dedup modes for Aggregate
const (
	// DedupByValue groups all findings with the same secret value into a
	// single aggregated finding that tracks every location it appeared in
	DedupByValue = "value"
	// DedupByLocation treats every (secret, file, line) occurrence as an
	// independent finding
	DedupByLocation = "location"
)

// AggregatedResult contains deduplicated findings with scanner tracking
type AggregatedResult struct {
	TotalFindings int
	UniqueSecrets int
	Findings      []AggregatedFinding
	ScannerStats  map[string]int // Scanner name -> number of findings
}

// AggregatedFinding represents a deduplicated finding
type AggregatedFinding struct {
	scanner.Finding
	FoundBy []string // List of scanner names that found this secret
	// All locations where this secret appeared (value mode only);
	// hidden in location mode, where the finding itself is one location
	Occurrences []Occurrence `json:"Occurrences,omitempty"`
}

// Occurrence is a single location where a secret was found
type Occurrence struct {
	File string `json:"File"`
	Line int    `json:"Line"`
}

// Aggregate combines results from multiple scanners and deduplicates
// according to mode (DedupByValue or DedupByLocation)
func Aggregate(results []*scanner.ScanResult, mode string) (*AggregatedResult, error) {
	switch mode {
	case DedupByValue, DedupByLocation:
	default:
		return nil, fmt.Errorf("unsupported dedup mode %q (supported: %s, %s)", mode, DedupByValue, DedupByLocation)
	}

	// Map of dedup key -> AggregatedFinding
	findingMap := make(map[string]*AggregatedFinding)
	scannerStats := make(map[string]int)

	totalFindings := 0

	for _, result := range results {
		if result == nil {
			continue
		}

		scannerStats[result.ScannerName] = len(result.Findings)
		totalFindings += len(result.Findings)

		for _, finding := range result.Findings {
			// Private key material is never exposed in the output;
			// the finding itself (hash, locations) is kept intact
			if isPrivateKey(finding.Secret) {
				finding.Secret = scanner.RedactedSecret
			}

			key := dedupKey(finding, mode)
			existing, found := findingMap[key]
			if !found {
				existing = &AggregatedFinding{
					Finding: finding,
				}
				if mode == DedupByValue {
					existing.Occurrences = []Occurrence{{File: finding.File, Line: finding.Line}}
				}
				findingMap[key] = existing
			}

			// Track which scanners found this finding
			if !contains(existing.FoundBy, result.ScannerName) {
				existing.FoundBy = append(existing.FoundBy, result.ScannerName)
			}

			// Track every location the secret appeared in (value mode)
			if mode == DedupByValue {
				occ := Occurrence{File: finding.File, Line: finding.Line}
				if !containsOccurrence(existing.Occurrences, occ) {
					existing.Occurrences = append(existing.Occurrences, occ)
				}
			}
		}
	}

	// Convert map to slice
	var findings []AggregatedFinding
	for _, finding := range findingMap {
		findings = append(findings, *finding)
	}

	return &AggregatedResult{
		TotalFindings: totalFindings,
		UniqueSecrets:  len(findings),
		Findings:       findings,
		ScannerStats:   scannerStats,
	}, nil
}

// dedupKey returns the deduplication key for a finding in the given mode
func dedupKey(f scanner.Finding, mode string) string {
	if mode == DedupByLocation {
		return fmt.Sprintf("%s|%s|%d", f.SecretHash, f.File, f.Line)
	}
	return f.SecretHash
}

// isPrivateKey reports whether a secret value looks like private key
// material (PEM blocks: RSA, EC, OPENSSH, PGP, PKCS8...)
func isPrivateKey(secret string) bool {
	return strings.Contains(secret, "-----BEGIN") && strings.Contains(secret, "PRIVATE KEY")
}

// contains checks if a string slice contains a specific value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// containsOccurrence checks if an occurrence slice contains a specific location
func containsOccurrence(occurrences []Occurrence, occ Occurrence) bool {
	for _, o := range occurrences {
		if o == occ {
			return true
		}
	}
	return false
}