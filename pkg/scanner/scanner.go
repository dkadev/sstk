package scanner

// RedactedSecret is the placeholder used when the raw secret value must
// not be exposed (e.g. private key material)
const RedactedSecret = "[REDACTED]"

// Scanner defines the interface for secret scanning tools.
type Scanner interface {
	// Name returns the scanner's name
	Name() string

	// Scan executes the scanner against the specified target
	Scan(target string) (*ScanResult, error)

	// IsInstalled checks if the scanner binary is available
	IsInstalled() bool
}

// ScanResult represents the results from a scanner
type ScanResult struct {
	ScannerName string
	Findings    []Finding
	RawOutput   []byte // Original output from the scanner
	Error       error
}

// Finding represents a single secret found by a scanner
type Finding struct {
	File        string
	Line        int
	Secret      string
	SecretHash  string // For deduplication
	RuleID      string
	Description string
	StartColumn int
	EndColumn   int
}
