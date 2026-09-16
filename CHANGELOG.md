# Changelog

This file records user-visible changes to the Trident CLI. It follows the
general structure of [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.1] - 2026-09-14

### Maintenance

- Removed generated release audit artifacts from the public source tree.
- Normalized development path examples.
- Expanded repository hygiene protections for generated release evidence.

## [0.2.0] - 2026-09-13

### Added

- External SonarQube JSON and OWASP Dependency-Check JSON ingestion.
- Repeatable JSON input files for one import job where supported by the CLI.
- User-facing validation and replay commands for frozen scanner and typed
  decision evidence.
- Rich relationship metadata for confirmed, false-positive, duplicate,
  related, and unresolved records.
- Ollama Cloud model identity compatibility for cloud aliases that return their
  exact native model name.

### Changed

- Correlation distinguishes exact duplicates from related evidence instead of
  representing every grouped record as a duplicate.
- Scanner severity is preserved separately from model assessment, guard
  adjustment, and final P0-P4 priority.
- Malformed, unresolved, timed-out, or failed model decisions remain
  unresolved and fail closed; they are never converted into security verdicts.
- JSON import preserves source report evidence and bypasses scanner
  subprocesses.

### Validation

- Completed public validation results are summarized in
  [docs/VALIDATION.md](docs/VALIDATION.md).

## [0.1.0] - Initial public CLI release

### Added

- Twelve scanner adapters covering SAST, software composition, secrets, and
  infrastructure/configuration analysis.
- Cross-tool correlation and deduplication before council review.
- Expert-council review with judge, red-team attack-chain, and novel-discovery
  passes.
- Class, corpus-profile, and reachability triage adjustments.
- Automatic triage that removes rejected candidates from the actionable queue
  while preserving them as audit evidence.
- Table, JSON, and SARIF 2.1.0 reports plus full triage sidecars.
- Local path, Git URL, and ZIP archive scan inputs.
- CLI configuration, scanner-tool installation, and optional model-feed
  refresh/build commands.

### Security

- Git sources are validated against argument and transport injection before
  cloning.
- ZIP extraction rejects path traversal.
- Scanner tools remain separate processes and retain their own licenses.

### Licensing

- Trident is licensed under the Business Source License 1.1. Each specific
  version changes to the MIT License four years after its first public
  distribution. See [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).
- See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for scanner licenses,
  including the AGPL-3.0 TruffleHog component.
