# Trident CLI

Trident runs security scanners, imports existing vulnerability reports,
correlates evidence, sends findings to configured model reviewers, and writes
P0-P4 triage results in terminal, JSON, and SARIF formats. Use it only on code
and reports you are authorized to analyze. Model results require human review.

Python 3.11 or newer is required. Download a wheel from the
[GitHub Releases page](https://github.com/DrDeathLabs/trident-cli/releases),
install it in a virtual environment, then install scanner tools with
`trident install-tools --verify`.

For configuration, scan behavior, report interpretation, and privacy guidance,
start with the [project README](https://github.com/DrDeathLabs/trident-cli/blob/main/README.md)
and [documentation map](https://github.com/DrDeathLabs/trident-cli/tree/main/docs).
The guide [Connecting Trident to a Custom LLM Endpoint or Proxy](https://github.com/DrDeathLabs/trident-cli/blob/main/docs/CONNECTING_LLM_ENDPOINTS.md)
covers compatible HTTP and HTTPS gateways, authentication, model aliases, and
troubleshooting.

This directory contains the Python package and build metadata. Development
commands are in the repository's [contributor guide](https://github.com/DrDeathLabs/trident-cli/blob/main/CONTRIBUTING.md).
