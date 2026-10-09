# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-09

### Added

- Unified CLI wrapping gitleaks, trufflehog, noseyparker, and detect-secrets
- `sstk scan` command with result aggregation across scanners
- Automatic deduplication of findings with `--dedupe-by value|location` strategies
- Scanner attribution showing which scanner(s) found each secret
- Output formats: text (default), JSON, CSV, and `--all-formats`
- Secret masking by default in text/CSV output, with `--show-secrets` to reveal (private keys always redacted)
- Timestamped output directories with scan logs and raw scanner output preservation
- `sstk list` command showing installed/missing scanners

[0.1.0]: https://github.com/dkadev/sstk/releases/tag/v0.1.0
