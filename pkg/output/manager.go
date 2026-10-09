package output

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// OutputManager manages the creation and organization of output files
type OutputManager struct {
	BaseDir       string // output/
	SessionDir    string // output/sstk_20260126_231845/
	RawOutputsDir string // output/sstk_20260126_231845/raw_outputs/
	LogFile       string // output/sstk_20260126_231845/scan.log
}

// NewOutputManager creates a new output manager with timestamped directories
func NewOutputManager(baseDir string) (*OutputManager, error) {
	if baseDir == "" {
		baseDir = "output"
	}

	// Create timestamp-based session directory
	timestamp := time.Now().Format("20060102_150405")
	sessionDir := filepath.Join(baseDir, fmt.Sprintf("sstk_%s", timestamp))

	// Create raw outputs subdirectory
	rawOutputsDir := filepath.Join(sessionDir, "raw_outputs")

	// Create all directories
	if err := os.MkdirAll(rawOutputsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directories: %w", err)
	}

	logFile := filepath.Join(sessionDir, "scan.log")

	return &OutputManager{
		BaseDir:       baseDir,
		SessionDir:    sessionDir,
		RawOutputsDir: rawOutputsDir,
		LogFile:       logFile,
	}, nil
}

// GetResultPath returns the path for a result file with the given format
func (om *OutputManager) GetResultPath(format string) string {
	return filepath.Join(om.SessionDir, fmt.Sprintf("results.%s", format))
}

// GetRawOutputPath returns the path for a scanner's raw output
func (om *OutputManager) GetRawOutputPath(scannerName, extension string) string {
	return filepath.Join(om.RawOutputsDir, fmt.Sprintf("%s_output.%s", scannerName, extension))
}

// CreateFile creates a file at the specified path and returns a file handle
func (om *OutputManager) CreateFile(path string) (*os.File, error) {
	return os.Create(path)
}
