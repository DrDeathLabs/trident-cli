# Trident CLI package

This is the Python package for the standalone Trident CLI. It contains the
scanner, AI review and triage engine, tests, build metadata, and development
dependencies. Installing this package provides the `trident` command.

From this directory:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check trident tests
python -m build
```

See the [repository README](../README.md) and the
[documentation map](../docs/README.md) for user installation, scanner
bootstrap, model feeds, report formats, triage behavior, and release checks.
