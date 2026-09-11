#!/usr/bin/env bash
# Host-lane test runner.
#
# Why this exists: direnv's Nix shell provides every test dependency except the
# optional Azure SDK, and its `python3` is a shim that unsets PYTHONPATH. So a
# plain `pip install` cannot reach the interpreter that runs the tests, and a
# separate venv loses the Nix-provided test deps (72 failures when tried).
#
# The working combination is the real Nix interpreter with ONLY the Azure SDK
# on PYTHONPATH. Set it up once with:
#   ./run-host-tests.sh --install
set -euo pipefail
cd "$(dirname "$0")"

NIXPY="$(sed -n 's/^exec "\([^"]*\)".*/\1/p' "$(command -v python3)" 2>/dev/null || true)"
[ -x "${NIXPY:-}" ] || NIXPY="$(command -v python3)"
DEPS="$PWD/.azure-deps"

if [ "${1:-}" = "--install" ]; then
  "$NIXPY" -m pip install --target="$DEPS" \
    'azure-identity>=1.25,<2.0' 'azure-keyvault-certificates>=4.11,<5.0'
  shift
fi

exec env PYTHONPATH="$DEPS" "$NIXPY" -m pytest "${@:-tests/ -m unit -q}" -p no:django
