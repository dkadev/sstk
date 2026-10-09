# sstk - Secret Scanner Tool Kit

A unified CLI tool that integrates multiple secret scanning tools into a single interface for easier security auditing.

## Overview

sstk wraps multiple popular secret scanning tools (gitleaks, trufflehog, noseyparker, detect-secrets) and provides:
- Unified command-line interface
- Result aggregation across scanners
- Automatic deduplication of findings
- Multiple output formats (text, JSON, CSV)
- Scanner attribution (shows which scanner(s) found each secret)
- Organized output with timestamped directories
- Automatic log generation with scan statistics
- Raw scanner output preservation

## Installation

### Prerequisites

You must have at least one of the following scanners installed:

- **gitleaks**: `brew install gitleaks` or see https://github.com/gitleaks/gitleaks
- **trufflehog**: `brew install trufflehog` or see https://github.com/trufflesecurity/trufflehog
- **noseyparker**: See https://github.com/praetorian-inc/noseyparker
- **detect-secrets**: `pip install detect-secrets` or see https://github.com/Yelp/detect-secrets

### Install sstk

```bash
go install github.com/dkadev/sstk@latest
```

Or build from source:

```bash
git clone https://github.com/dkadev/sstk
cd sstk
go build -o sstk ./cmd/sstk
```

## Usage

### List Available Scanners

Check which scanners are installed on your system:

```bash
sstk list
```

Output:
```
Available Scanners:
-------------------
gitleaks             ✓ Installed
trufflehog           ✗ Not Installed
noseyparker          ✗ Not Installed
detect-secrets       ✗ Not Installed
```

### Scan a Directory

Scan with all available scanners:

```bash
sstk scan /path/to/repo
```

### Output Management

sstk automatically organizes all output files in timestamped directories:

```
output/
└── sstk_20260126_232847/
    ├── scan.log                    # Always generated - summary statistics
    ├── results.json                # Aggregated results (format specified)
    └── raw_outputs/                # Original scanner outputs
        ├── gitleaks_output.json
        └── trufflehog_output.json
```

### Output Formats

**Text output (default):**
```bash
sstk scan /path/to/repo
```

**JSON output:**
```bash
sstk scan /path/to/repo --format json
```

**CSV output (for spreadsheets/data ingestion):**
```bash
sstk scan /path/to/repo --format csv
```

**Export to all formats at once:**
```bash
sstk scan /path/to/repo --all-formats
```
This generates `results.text`, `results.json`, and `results.csv` in the output directory.

**Custom output filename:**
```bash
sstk scan /path/to/repo --format json --output my_results.json
```

**Custom output base directory:**
```bash
sstk scan /path/to/repo --output-dir /my/custom/path
```

**Show raw (unmasked) secret values in text and CSV:**
```bash
sstk scan /path/to/repo --show-secrets
```
Secrets are masked by default in text and CSV for safe sharing; JSON always carries the raw value. Private key material is always redacted, even with `--show-secrets`.

### Select Specific Scanners

Run specific scanners only:

```bash
sstk scan /path/to/repo --scanners gitleaks,trufflehog
```

### Deduplication Strategy

By default (`--dedupe-by value`), findings with the same secret value are grouped
into a single result that keeps track of every location where the secret appeared
(`Occurrences` in text/JSON/CSV output) — ideal to know what needs rotation and
its blast radius:

```bash
sstk scan /path/to/repo            # default: value
sstk scan /path/to/repo --dedupe-by location
```

With `--dedupe-by location`, every `(secret, file, line)` occurrence is reported
as an independent finding — ideal for remediation checklists.

## Contributing

Contributions are welcome! Please open a pull request.

## License

MIT License

## Security Note

This tool helps identify secrets in your codebase. Always handle the output carefully and never commit scan results containing actual secrets to version control.
