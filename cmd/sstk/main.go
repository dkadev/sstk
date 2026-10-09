package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dkadev/sstk/pkg/aggregator"
	"github.com/dkadev/sstk/pkg/output"
	"github.com/dkadev/sstk/pkg/scanner"
	"github.com/dkadev/sstk/pkg/scanners/detectsecrets"
	"github.com/dkadev/sstk/pkg/scanners/gitleaks"
	"github.com/dkadev/sstk/pkg/scanners/noseyparker"
	"github.com/dkadev/sstk/pkg/scanners/titus"
	"github.com/dkadev/sstk/pkg/scanners/trufflehog"
)

const (
	defaultOutputDir    = "output"
	timestampedDirTmpl  = "sstk_20060102_150405"
	defaultOutputFormat = "text"
)

// registry returns all supported scanners in stable order.
// Deprecated scanners are only run when selected explicitly via --scanners.
func registry() []scanner.Scanner {
	return []scanner.Scanner{
		&gitleaks.Scanner{},
		&trufflehog.Scanner{},
		&titus.Scanner{},
		&detectsecrets.Scanner{},
		&noseyparker.Scanner{},
	}
}

func main() {
	var scannersFlag, formatFlag, outputFlag, outputDirFlag, dedupeByFlag string
	var allFormats, showSecrets bool

	rootCmd := &cobra.Command{
		Use:   "sstk",
		Short: "Secret Scanner Tool Kit - a unified interface for multiple secret scanners",
	}

	scanCmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target path for secrets using the selected scanners",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], scannersFlag, formatFlag, outputFlag, outputDirFlag, dedupeByFlag, allFormats, showSecrets)
		},
	}
	scanCmd.Flags().StringVarP(&scannersFlag, "scanners", "s", "", "comma-separated list of scanners to use (default: all installed, excluding deprecated ones like noseyparker)")
	scanCmd.Flags().StringVarP(&formatFlag, "format", "f", defaultOutputFormat, "output format (text, json or csv)")
	scanCmd.Flags().StringVarP(&outputFlag, "output", "o", "", "output file for results (default: <output-dir>/<timestamp>/results.<format>)")
	scanCmd.Flags().StringVar(&outputDirFlag, "output-dir", defaultOutputDir, "base directory for timestamped scan outputs")
	scanCmd.Flags().StringVar(&dedupeByFlag, "dedupe-by", aggregator.DedupByValue,
		"deduplication strategy: value (default) groups findings with the same secret and tracks all their locations; location treats every (secret, file, line) occurrence as an independent finding")
	scanCmd.Flags().BoolVar(&allFormats, "all-formats", false, "export results in all formats (text, json and csv)")
	scanCmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "show the raw secret value in text and csv output (masked by default; json always carries it)")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available scanners and their installation status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList()
		},
	}

	rootCmd.AddCommand(scanCmd, listCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(target string, scannerNames, format, outputFile, outputDir, dedupeBy string, allFormats, showSecrets bool) error {
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("invalid target path %q: %w", target, err)
	}

	formats := []string{format}
	if allFormats {
		formats = []string{"text", "json", "csv"}
	} else {
		for _, f := range formats {
			switch strings.ToLower(f) {
			case "text", "json", "csv":
			default:
				return fmt.Errorf("unsupported format %q (supported: text, json, csv)", f)
			}
		}
	}
	if outputFile != "" && allFormats {
		return fmt.Errorf("--output cannot be combined with --all-formats")
	}

	scanners, err := selectScanners(scannerNames)
	if err != nil {
		return err
	}

	// Run scanners; a scanner failure is reported but does not abort the scan
	timestamp := time.Now()
	var results []*scanner.ScanResult
	var used []string
	var failed int
	for _, s := range scanners {
		fmt.Fprintf(os.Stderr, "Running %s...\n", s.Name())
		result, err := s.Scan(target)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			continue
		}
		results = append(results, result)
		used = append(used, s.Name())
	}

	if len(results) == 0 {
		return fmt.Errorf("all %d selected scanner(s) failed", failed)
	}

	agg, err := aggregator.Aggregate(results, dedupeBy)
	if err != nil {
		return err
	}

	// Every scan produces a timestamped directory with scan.log,
	// raw scanner outputs and the result files
	scanDir := filepath.Join(outputDir, timestamp.Format(timestampedDirTmpl))
	if err := os.MkdirAll(filepath.Join(scanDir, "raw_outputs"), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory %q: %w", scanDir, err)
	}

	for _, r := range results {
		rawPath := filepath.Join(scanDir, "raw_outputs", fmt.Sprintf("%s_output.json", r.ScannerName))
		if err := os.WriteFile(rawPath, r.RawOutput, 0o644); err != nil {
			return fmt.Errorf("failed to write raw output for %s: %w", r.ScannerName, err)
		}
		fmt.Fprintf(os.Stderr, "  Raw output saved to: %s\n", rawPath)
	}

	logPath := filepath.Join(scanDir, "scan.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("failed to create scan log %q: %w", logPath, err)
	}
	if err := output.WriteScanLog(logFile, timestamp, target, used, agg); err != nil {
		logFile.Close()
		return fmt.Errorf("failed to write scan log: %w", err)
	}
	logFile.Close()
	fmt.Fprintf(os.Stderr, "Summary log saved to: %s\n", logPath)

	// Write results: to the --output file, or to results.<format> in the scan dir
	for _, f := range formats {
		path := outputFile
		if path == "" {
			path = filepath.Join(scanDir, "results."+f)
		}
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create results file %q: %w", path, err)
		}
		if err := output.Write(file, f, agg, showSecrets); err != nil {
			file.Close()
			return fmt.Errorf("failed to write results file %q: %w", path, err)
		}
		file.Close()
		fmt.Fprintf(os.Stderr, "Results saved to: %s\n", path)
	}

	fmt.Fprintf(os.Stderr, "Output directory: %s\n", scanDir)
	fmt.Fprintf(os.Stderr, "Scan complete: %d total finding(s), %d unique secret(s)\n", agg.TotalFindings, agg.UniqueSecrets)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d scanner(s) failed\n", failed)
	}
	return nil
}

// selectScanners returns the scanners to run: an explicit list by name, or all installed
func selectScanners(scannerNames string) ([]scanner.Scanner, error) {
	all := registry()
	byName := make(map[string]scanner.Scanner, len(all))
	for _, s := range all {
		byName[s.Name()] = s
	}

	var selected []scanner.Scanner
	if strings.TrimSpace(scannerNames) != "" {
		for _, name := range strings.Split(scannerNames, ",") {
			name = strings.TrimSpace(name)
			s, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("unknown scanner %q (supported: %s)", name, scannerNamesOf(all))
			}
			if !s.IsInstalled() {
				return nil, fmt.Errorf("scanner %q is not installed", name)
			}
			selected = append(selected, s)
		}
	} else {
		for _, s := range all {
			// Deprecated scanners are opt-in only: run them when named
			// explicitly via --scanners, not as part of the default set
			if isDeprecated(s) {
				continue
			}
			if s.IsInstalled() {
				selected = append(selected, s)
			}
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("no scanners available; install at least one of: %s", scannerNamesOf(all))
	}
	return selected, nil
}

func runList() error {
	fmt.Println("Available Scanners:")
	fmt.Println("-------------------")
	for _, s := range registry() {
		status := "NOT installed"
		if s.IsInstalled() {
			status = "installed"
		}
		fmt.Printf("%-15s %s\n", s.Name(), status)
		if notice := deprecationNotice(s); notice != "" {
			fmt.Printf("%-15s deprecated: %s\n", "", notice)
		}
	}
	return nil
}

// isDeprecated reports whether the scanner implements scanner.DeprecatedScanner
func isDeprecated(s scanner.Scanner) bool {
	_, ok := s.(scanner.DeprecatedScanner)
	return ok
}

// deprecationNotice returns the scanner's deprecation notice, or ""
func deprecationNotice(s scanner.Scanner) string {
	if d, ok := s.(scanner.DeprecatedScanner); ok {
		return d.DeprecationNotice()
	}
	return ""
}

// scannerNamesOf returns a comma-separated list of scanner names
func scannerNamesOf(scanners []scanner.Scanner) string {
	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}
	return strings.Join(names, ", ")
}