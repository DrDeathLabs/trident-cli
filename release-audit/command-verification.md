# CLI documentation command verification

| Command | Exit code | Result |
|---|---:|---|
| `trident --version` | 0 | PASS |
| `trident --help` | 0 | PASS |
| `trident scan --help` | 0 | PASS |
| `trident config --help` | 0 | PASS |
| `trident config list` | 0 | PASS |
| `trident config path` | 0 | PASS |
| `trident config show` | 0 | PASS |
| `trident model --help` | 0 | PASS |
| `trident model path` | 0 | PASS |
| `trident model status` | 0 | PASS |
| `trident validate --help` | 0 | PASS |
| `trident install-tools --check` | 0 | PASS |
| `trident help` | 0 | PASS |
| `trident help setup` | 0 | PASS |
| `trident help backends` | 0 | PASS |
| `trident help ci` | 0 | PASS |
| `trident help config` | 0 | PASS |
| `trident help output` | 0 | PASS |
| `trident help guards` | 0 | PASS |
| `trident help experts` | 0 | PASS |
| `trident help tools` | 0 | PASS |

All documented read-only help, configuration inspection, model status, validation help, and scanner status commands were exercised from the installed wheel. No feed refresh, tool installation, config reset, or scan against private data was run.
