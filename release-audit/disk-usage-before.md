# Disk usage before cleanup

Captured before release cleanup from the original checkout at `C:\Software\Trident CLI`.

| Area | Size / result |
|---|---:|
| Total working repository | 15,408,431,824 bytes (approximately 14.35 GiB) |
| `.acceptance/` | 12,346,741,288 bytes (approximately 11.5 GiB) |
| `backend/` | 2,653,232,799 bytes (approximately 2.47 GiB), including temporary virtual environments and run databases |
| `.release-smoke-data/` | 319,306,347 bytes (approximately 0.30 GiB) |
| `.git/` | 82,409,290 bytes (approximately 0.077 GiB) |
| `docs/` | 434,454 bytes |
| `validation/` | 651,102 bytes (generated harness and evidence) |

The initial top-level listing also contained `.pytest_cache/`, `.pytest-tmp/`, `.ruff_cache/`, `app.log`, a 5.3 MiB temporary handoff, and a 166.2 MiB validation ZIP outside the product source set.

## Large files and directories

The complete inventory identified generated records, SQLite databases, scanner executables, Go runtimes, Python virtual environments, reports, and validation packages above the requested thresholds. Representative largest files included:

- `.acceptance/json-only-authoritative-20260913h/review/record-traceability.json` (approximately 276.7 MiB)
- Semgrep runtime binaries (approximately 235.5 MiB each)
- TruffleHog and Trivy binaries (approximately 168.2 MiB and 164.3 MiB)
- Validation ZIPs (approximately 166.2 MiB, 27.1 MiB, and 12.9 MiB)
- Frozen validation databases and generated primary/triage JSON reports
- `backend` temporary Semgrep runtimes and Python environments

Directories above 50 MiB were the `.acceptance` validation campaigns and their nested `venv`, `tools`, `reports`, `review`, `source`, and database trees; `backend` temporary release/smoke environments and run-data trees; and `.release-smoke-data`.

## Git accounting

`git count-objects -vH` before cleanup:

```text
count: 6152
size: 78.55 MiB
in-pack: 0
packs: 0
size-pack: 0 bytes
prune-packable: 0
garbage: 1
size-garbage: 319 bytes
```

The large working-tree artifacts were not treated as product source. Git history was not rewritten. The large loose-object inventory will be rechecked after the release worktree is safe and clean.
