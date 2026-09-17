# Changelog

This file records user-visible changes to the Trident CLI. It follows the
general structure of [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.2] - 2026-09-17

### Added

- Universal vulnerability evidence ingestion through deterministic adapters for
  SonarQube, OWASP Dependency-Check, SARIF 2.1.0, and CycloneDX vulnerability
  JSON, plus bounded generic JSON mapping.
- `trident inspect` for non-mutating format detection, record accounting, and
  mapping inspection.

### Changed

- Generic mappings now use semantic validation for identifier classes, package
  and installed-version evidence, CVSS fields, and field-level provenance.
- Optional schema AI can propose a mapping only; Trident validates and executes
  that mapping deterministically, and fails closed when evidence is ambiguous.
- Imported evidence preserves source records, report hashes, JSON pointers,
  mapping identity, original values, source context, and terminal accounting.
- Native scanner output and imported evidence share correlation, Council,
  judge, red-team, guard, triage, and reporting stages.

### Fixed

- Improved Ollama transport and ledger observability, source-grounding
  correctness, malformed-record accounting, and release/package validation.
- Corrected release preparation so public publication requires an explicit
  human-controlled workflow action.

## [0.3.1] - 2026-09-15

> Historical local release candidate; withdrawn and not the current public
> release.

### Fixed

- Keep valid Dependency-Check vulnerability records when CVSS data is absent;
  original severity and other report evidence remain preserved.
- Improved live Ollama import reliability with an isolated SQLite LLM ledger,
  validated schema-AI mapping fallback, and deterministic numeric-severity
  handling.
- Corrected public documentation for heterogeneous JSON mapping and the
  default `nemotron-3-super:cloud` model.

## [0.3.0] - 2026-09-15

> Historical local release candidate; withdrawn and not the current public
> release.

### Added

- Deterministic vulnerability evidence adapters for SARIF 2.1.0 and CycloneDX
  vulnerability JSON alongside SonarQube and Dependency-Check imports.
- Safe versioned generic JSON mappings, bounded structural inference, `trident
  inspect`, field-level provenance, report hashes, and complete record accounting.
- Mixed-format import support through the existing correlation, Council, judge,
  attack-chain, guard, triage, and reporting pipeline.

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
- Ollama Cloud model identity compatibility for exact native cloud aliases.

### Changed

- Correlation distinguishes exact duplicates from related evidence.
- Scanner severity is preserved separately from model assessment, guard
  adjustment, and final P0-P4 priority.
- Malformed, unresolved, timed-out, or failed model decisions remain unresolved
  and fail closed.
- JSON import preserves source report evidence and bypasses scanner subprocesses.

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
