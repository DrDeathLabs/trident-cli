---
name: Bug report
about: Something is broken or producing incorrect CLI results
title: ''
labels: bug
assignees: ''
---

## Description

Tell us what went wrong and whether it affects installation, scanning, triage,
reports, configuration, model feeds, or tool bootstrap.

## Reproduction

1. Run the smallest command that reproduces the issue.
2. Record the exit code.
3. Describe the observed output.

~~~text
Paste sanitized output here.
~~~

## Expected behavior

What should have happened?

## Environment

- OS and version:
- Python version (python --version):
- Trident version (trident --version):
- LLM backend/model, if relevant:
- Tool status (trident install-tools --check):

## Scan target

If relevant, describe the target language, approximate size, and input type.
Do not attach proprietary or sensitive code, credentials, raw findings, or
unredacted model context. A small synthetic fixture is preferred.

## Additional context

Include a sanitized debug excerpt, upstream tool version, or relevant
documentation link. Do not report suspected security vulnerabilities here; use
the private process in SECURITY.md.
