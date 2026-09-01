## Summary

What changed, and why is the change needed?

## Scope

- [ ] CLI/runtime behavior
- [ ] Scanner adapter or tool bootstrap
- [ ] Triage, guards, or report contract
- [ ] Documentation only
- [ ] Packaging/release automation

## Test plan

- [ ] python -m pytest -q
- [ ] python -m ruff check trident tests
- [ ] python -m build
- [ ] python -m twine check dist\*
- [ ] Relevant CLI help/manual smoke checks
- [ ] JSON, SARIF, table, or triage sidecar behavior checked when applicable

Describe any test that could not run and why.

## Documentation

- [ ] Command examples match current trident help output
- [ ] FEATURE_STATUS.md or LIMITATIONS.md updated when behavior changed
- [ ] Third-party tool/license documentation updated when applicable

## Release checklist

- [ ] No credentials, proprietary source, customer findings, or raw model context
- [ ] No generated reports, local databases, virtual environments, or downloads
- [ ] No unrelated deployment or product code
