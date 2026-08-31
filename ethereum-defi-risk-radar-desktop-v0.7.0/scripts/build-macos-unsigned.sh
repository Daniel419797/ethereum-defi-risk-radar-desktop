#!/usr/bin/env bash
set -euo pipefail

echo "Ethereum DeFi Risk Radar - UNSIGNED macOS test build"
echo "WARNING: This output is only for local testing. Do not distribute it to end users."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: macOS packages must be built on macOS." >&2
  exit 1
fi

npm install --no-audit --no-fund
npm run check
npm run dist:mac:unsigned

echo
echo "Unsigned test artifacts are under ./release/. Gatekeeper will not treat these as trusted distribution builds."
