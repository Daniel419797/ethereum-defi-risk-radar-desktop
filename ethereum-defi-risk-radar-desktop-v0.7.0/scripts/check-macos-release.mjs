import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

function fail(message) {
  console.error(`macOS release preflight failed: ${message}`);
  process.exit(1);
}

if (process.platform !== "darwin") {
  fail("production macOS signing/notarization must run on macOS.");
}

for (const required of [
  "build/icon.icns",
  "build/entitlements.mac.plist",
  "build/entitlements.mac.inherit.plist"
]) {
  if (!fs.existsSync(path.resolve(required))) fail(`missing ${required}`);
}

let signingReady = Boolean(process.env.CSC_LINK);
if (!signingReady) {
  const result = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], {
    encoding: "utf8"
  });
  signingReady = result.status === 0 && /Developer ID Application/.test(result.stdout || "");
}
if (!signingReady) {
  fail("no Developer ID Application certificate was found. Install it in Keychain or configure CSC_LINK/CSC_KEY_PASSWORD.");
}

const hasApiKey = Boolean(
  process.env.APPLE_API_KEY &&
  process.env.APPLE_API_KEY_ID &&
  process.env.APPLE_API_ISSUER
);
const hasAppleId = Boolean(
  process.env.APPLE_ID &&
  process.env.APPLE_APP_SPECIFIC_PASSWORD &&
  process.env.APPLE_TEAM_ID
);
const hasKeychainProfile = Boolean(process.env.APPLE_KEYCHAIN_PROFILE);

if (!hasApiKey && !hasAppleId && !hasKeychainProfile) {
  fail("notarization credentials are missing. Configure App Store Connect API credentials, Apple-ID credentials, or APPLE_KEYCHAIN_PROFILE.");
}

console.log("macOS release preflight passed: signing identity and notarization credentials are available.");
