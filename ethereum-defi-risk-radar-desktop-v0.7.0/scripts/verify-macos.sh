#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: macOS signature/notarization verification must run on macOS." >&2
  exit 1
fi

APP_PATH="$(find release -type d -name 'Ethereum DeFi Risk Radar.app' -print -quit)"
if [[ -z "${APP_PATH}" ]]; then
  echo "ERROR: Packaged .app was not found below release/." >&2
  exit 1
fi

EXECUTABLE="${APP_PATH}/Contents/MacOS/Ethereum DeFi Risk Radar"
if [[ ! -f "${EXECUTABLE}" ]]; then
  echo "ERROR: Main application executable not found: ${EXECUTABLE}" >&2
  exit 1
fi

echo "Verifying code signature..."
codesign --verify --deep --strict --verbose=2 "${APP_PATH}"

echo "Verifying Gatekeeper acceptance..."
spctl --assess --verbose=4 --type exec "${APP_PATH}"

echo "Verifying notarization ticket..."
xcrun stapler validate "${APP_PATH}"

CLI_LAUNCHER="${APP_PATH}/Contents/Resources/cli/launch.cjs"
if [[ ! -f "${CLI_LAUNCHER}" ]]; then
  echo "ERROR: Bundled CLI launcher not found: ${CLI_LAUNCHER}" >&2
  exit 1
fi

echo "Verifying packaged risk-radar CLI runtime..."
CLI_VERSION="$(ELECTRON_RUN_AS_NODE=1 "${EXECUTABLE}" "${CLI_LAUNCHER}" version | tr -d '\r')"
if [[ "${CLI_VERSION}" != "0.7.0" ]]; then
  echo "ERROR: Packaged CLI returned unexpected version: ${CLI_VERSION}" >&2
  exit 1
fi

echo "Verifying universal x64 + arm64 binary..."
LIPO_OUTPUT="$(lipo -info "${EXECUTABLE}")"
echo "${LIPO_OUTPUT}"
if [[ "${LIPO_OUTPUT}" != *"x86_64"* || "${LIPO_OUTPUT}" != *"arm64"* ]]; then
  echo "ERROR: Packaged executable is not universal (x86_64 + arm64)." >&2
  exit 1
fi

echo "macOS verification passed: signed, Gatekeeper accepted, notarized/stapled, universal binary, bundled CLI runtime verified."
