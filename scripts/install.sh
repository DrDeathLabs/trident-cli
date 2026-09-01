#!/usr/bin/env bash
# Install the Trident CLI and its scanner tools on Linux or macOS.
#
# Usage:
#   ./scripts/install.sh [--venv PATH] [--skip-warmup]
#
# Options:
#   --venv PATH       Virtualenv path (default: .venv in this checkout)
#   --skip-warmup     Install and verify tools without downloading databases

set -euo pipefail

VENV=""
SKIP_WARMUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --venv)
      [[ $# -ge 2 ]] || { echo "--venv requires a path" >&2; exit 2; }
      VENV="$2"
      shift 2
      ;;
    --skip-warmup)
      SKIP_WARMUP=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "$VENV" ]]; then
  VENV="$ROOT/.venv"
fi

step() { echo; echo "==> $*"; }

step "Creating virtual environment at $VENV"
python3 -m venv "$VENV"

PYTHON="$VENV/bin/python"
TRIDENT="$VENV/bin/trident"

step "Installing the Trident CLI"
"$PYTHON" -m pip install "$ROOT/backend" --quiet

step "Installing and verifying scanner tools"
TOOL_ARGS=(install-tools --verify)
if [[ $SKIP_WARMUP -eq 0 ]]; then
  TOOL_ARGS+=(--warmup)
fi
"$TRIDENT" "${TOOL_ARGS[@]}"

echo
echo "Trident CLI is installed and ready."
echo "  CLI:  $TRIDENT"
echo "  Scan: $TRIDENT scan <path>"
