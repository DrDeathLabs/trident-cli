# Disk usage after cleanup

Captured after quarantining generated validation evidence from the original
checkout and removing generated release/build output from the release
worktree.

## Original checkout after cleanup

| Area | Size / result |
|---|---:|
| Total working repository | 86,322,844 bytes (approximately 0.08 GiB) |
| `.git/` | 82,425,104 bytes (approximately 0.077 GiB) |
| `backend/` | approximately 3.25 MiB of product source/tests |
| `docs/` | approximately 0.41 MiB of public Markdown |
| Files over 10 MiB | none |

The original checkout retained product source, source-controlled tests,
documentation, configuration, workflows, and normal repository metadata. The
private generated report docs and source materials were quarantined with the
validation artifacts.

## Reduction

- Before: 15,408,431,824 bytes (approximately 14.35 GiB)
- After: 86,322,844 bytes (approximately 0.08 GiB)
- Bytes removed from the working repository: 15,322,108,980 bytes
- Approximate reduction: 99.44%

The quarantined generated material remains outside the repository at
`C:\Users\Ddeat\Downloads\trident-v0.2.0-cleanup-quarantine-20260913` for
recoverability. It is not part of the release branch.

## Git history check

`git count-objects -vH` remains approximately 78.55 MiB of loose objects with
no pack files. No reachable blob over 10 MiB was found. Unreachable loose blobs
include two approximately 19 MiB objects and smaller generated-history
objects; they were recorded by object ID during the audit. Public history was
not rewritten. The worktree is materially small and the remaining `.git` size
is historical object storage, not current generated files.
