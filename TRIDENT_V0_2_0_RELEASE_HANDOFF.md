# Trident v0.2.0 release handoff

## Release identity

- Public repository: https://github.com/DrDeathLabs/trident-cli
- Baseline public `main` commit recorded in the specification: `73c9cbf93ca4c0f99475960bf79316df3f546988`
- Local validated implementation snapshot base: `b3abcf8eb19ca5112ec7bcb37665793fae8705bb`
- Release branch: `release/v0.2.0`
- Final release implementation/documentation commit: `b32e45044f4b33c7498e35c27245819935c971c2`.
- Release handoff evidence is committed immediately after that release commit; the final branch tip is the handoff commit.
- Pull request: https://github.com/DrDeathLabs/trident-cli/pull/12
- Merge commit: none; the PR was not merged automatically.
- Tag/release: none; tagging is intentionally downstream of merge and workflow verification.
- Package version: `0.2.0`

The release worktree is an isolated snapshot at
`C:\Software\trident-cli-release-v0.2.0`. The original user checkout at
`C:\Software\Trident CLI` stayed on branch `codex/readme-triage`; it was not
reset, stashed, or overwritten. The user implementation changes remain
preserved there.

## What changed

The release contains 78 intentional files changed from the validated local
base. The implementation commit includes the current scanner, import,
correlation, Council/Judge, guard, triage, report, Ollama identity, workspace,
reliability, and replay implementation plus the source-controlled test suite.
The documentation commit includes the public v0.2.0 refresh, `docs/VALIDATION.md`,
and the release audit.

The public documentation reviewed was:

`README.md`, `CHANGELOG.md`, `COMMERCIAL.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`SUPPORT.md`, `THIRD-PARTY-NOTICES.md`, `backend/README.md`, `docs/README.md`,
`docs/AGENTIC_MODE.md`, `docs/AI_COUNCIL.md`, `docs/ARCHITECTURE.md`,
`docs/ATTACK_CHAINS.md`, `docs/CI_CD.md`, `docs/CONFIGURATION.md`,
`docs/CORPUS_GUARD_MODEL.md`, `docs/DEVELOPMENT.md`, `docs/FEATURE_STATUS.md`,
`docs/GUARDS.md`, `docs/INSTALLATION.md`, `docs/LIMITATIONS.md`,
`docs/LLM_BACKENDS.md`, `docs/OPEN_SOURCE_READINESS.md`,
`docs/OUTPUT_FORMATS.md`, `docs/QUICK_START.md`, `docs/SCANNING.md`,
`docs/TOOLS.md`, `docs/TRIAGE.md`, `docs/TROUBLESHOOTING.md`, and the added
`docs/VALIDATION.md`.

The release documents the actual v0.2.0 architecture: native scanners or
supported SonarQube/OWASP Dependency-Check JSON input, normalized findings,
correlation, Council of Experts, Judge, attack-chain review, deterministic
guards, P0-P4 triage, and evidence-preserving table/JSON/SARIF reports. It
documents confirmed, false-positive, duplicate, related, and unresolved
relationships; scanner severity, model assessment, guard adjustment, and final
priority remain separate. CycloneDX is not documented as supported.

## Disk audit and cleanup

The required pre-cleanup inventory was captured before generated artifacts were
removed:

- Before: 15,408,431,824 bytes (approximately 14.35 GiB).
- After: 86,322,844 bytes (approximately 0.08 GiB) in the original checkout.
- Working-tree reduction: 15,322,108,980 bytes (approximately 14.27 GiB; 99.44%).
- `.git` before: 82,409,290 bytes; after: 82,425,104 bytes.
- No remaining working-tree file exceeds 10 MiB.
- Largest remaining product directories are `backend` (approximately 3.25 MiB),
  `docs` (approximately 0.41 MiB), and `release-audit` (small audit text/JSON).

The removed material was generated validation/test evidence: acceptance trees,
scanner binaries, Python environments, run databases, model ledgers, reports,
logs, ZIP packages, copied validation sources, scratch harnesses, temporary
build output, and private report documents. It was quarantined outside the
repository at `C:\Users\Ddeat\Downloads\trident-v0.2.0-cleanup-quarantine-20260913`
for recoverability. Source-controlled tests under `backend/tests` remain.

`git count-objects -vH` before cleanup reported 6,152 loose objects and 78.55
MiB, no pack files, and one 319-byte garbage object. After adding the release
worktree Git reports the same loose-object scale and two worktree-related
garbage warnings. No reachable blob over 10 MiB was found. The largest
unreachable blobs were approximately 19.47 MiB, 19.32 MiB, 6.14 MiB, 4.91 MiB,
and 3.92 MiB. Their object IDs and sizes were recorded during the audit. Git
history was not rewritten.

`.gitignore` now covers `.acceptance/`, `acceptance/`, `validation/`, benchmark
and evidence directories, report/build output, validation and handoff ZIPs,
scanner corpora, model ledgers, databases, stdout/stderr captures, and
temporary worktrees without ignoring source-controlled tests or public docs.

## Package validation

From `backend/`:

```text
python -m ruff check trident tests                 PASS
python -m pytest -q                               235 passed, 1 skipped
python -m build --wheel --sdist                  PASS
python -m twine check dist\*                      PASS (wheel and sdist)
```

The clean wheel was installed into an isolated Python 3.11 virtual environment
and its installed executable reported:

```text
trident, version 0.2.0
```

Wheel and sdist SHA-256 values from the validated build were:

- `trident-0.2.0-py3-none-any.whl`: `1A12818A20C0EDF4AF45B6A1DE53936625209002BD4FB6EB332E579287B5C2FB`
- `trident-0.2.0.tar.gz`: `BA144E3EAC4C0938EC76ABC3C181E1BE55B73F1802BEF8D8E8E1C261059FAE31`

The package metadata resolves its version from `trident.__version__`, which is
`0.2.0`, and uses the SPDX license string `BUSL-1.1`.

## Installed CLI smoke

All of the following were run from the clean wheel installation and returned
exit code 0:

```text
trident --version
trident --help
trident scan --help
trident config --help
trident config list
trident config path
trident config show
trident model --help
trident model path
trident model status
trident validate --help
trident install-tools --check
trident help
trident help setup
trident help backends
trident help ci
trident help config
trident help output
trident help guards
trident help experts
trident help tools
```

`install-tools --check` reported the twelve configured integrations and their
managed, pip, or system status without installing anything. No private or
large acceptance data was scanned. No source-controlled JSON fixture exists,
so no synthetic fixture was introduced for the smoke check; importer behavior
is covered by the source-controlled importer tests.

## Documentation verification

The documentation checker examined 30 public Markdown files, 129 local links,
and 8 remote links. All links resolved or returned HTTP 2xx/3xx. The command
verification table is in `release-audit/command-verification.md`; its JSON
record is `release-audit/command-verification.json`.

The stale-term review found only the intentional historical `0.1.0` changelog
entry. Public installation examples use `0.2.0`. Unsupported CycloneDX claims,
duplicate-only relationship language, private validation paths, and obsolete
model-substitution examples were removed or corrected.

## Secret and hygiene verification

Gitleaks 8.30.1 scanned the release worktree with `--no-git --redact` and
reported no leaks. The only manual AWS-shaped match is intentional synthetic
test data used to verify redaction. No credentials, `.env` files, private scan
reports, SQLite databases, PyGoat copies, validation ZIPs, screenshots, or
large generated binaries are present in the release branch.

## Approved public validation summary

`docs/VALIDATION.md` records the approved public `GREEN` summary only. It
contains no private findings, source paths, credentials, raw customer data, or
validation packages. The summary records scanner repeatability improvement,
execution-time improvement, separate duplicate/related representation, and
the SonarQube / OWASP Dependency-Check import accounting supplied for public
release.

## Release limitations

- Native scanner coverage depends on installed tools and target manifests;
  npm-audit requires Node/npm and Go scanners require Go or the bootstrap runtime.
- Imported JSON evidence does not itself prove source exploitability.
- Ollama Cloud may receive source context according to the configured backend;
  the operator must choose a suitable data-handling policy.
- P0/P1 findings still require qualified human review.
- CycloneDX ingestion is not supported by this release.
- The Git object database remains larger than the product source because public
  history and unreachable local objects were not rewritten; no reachable large
  generated blob remains.

## Final status

The release branch is pushed and PR #12 is open against `main`. The public
repository content on this branch accurately reflects the validated v0.2.0
system and the repository working tree is clean.
