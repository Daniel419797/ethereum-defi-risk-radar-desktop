#!/usr/bin/env bash
set -euo pipefail

echo "Ethereum DeFi Risk Radar - macOS production build"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: macOS DMG signing/notarization builds must run on macOS." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js 20.12 or newer is required." >&2
  exit 1
fi

if ! command -v xcode-select >/dev/null 2>&1 || ! xcode-select -p >/dev/null 2>&1; then
  echo "ERROR: Xcode Command Line Tools are required. Run: xcode-select --install" >&2
  exit 1
fi

echo "Node: $(node --version)"
echo "Architecture: $(uname -m)"

if [[ -z "${CSC_LINK:-}" ]]; then
  if ! security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
    echo "ERROR: No Developer ID Application signing identity was found. Install it in Keychain or set CSC_LINK/CSC_KEY_PASSWORD." >&2
    exit 1
  fi
fi

NOTARY_READY=false
if [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_KEY_ID:-}" && -n "${APPLE_API_ISSUER:-}" ]]; then NOTARY_READY=true; fi
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then NOTARY_READY=true; fi
if [[ -n "${APPLE_KEYCHAIN_PROFILE:-}" ]]; then NOTARY_READY=true; fi
if [[ "$NOTARY_READY" != "true" ]]; then
  echo "ERROR: Notarization credentials are missing. Configure App Store Connect API credentials, Apple-ID credentials, or an APPLE_KEYCHAIN_PROFILE." >&2
  exit 1
fi

npm install --no-audit --no-fund
npm run check
npm run dist:mac
npm run verify:mac

echo
echo "Signed/notarized universal macOS artifacts are under ./release/"
find release -maxdepth 1 -type f \( -name '*.dmg' -o -name '*.zip' \) -print
