import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appDir = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(appDir, "..");
const productionWorkflowPath = path.join(repoRoot, ".github", "workflows", "desktop-release.yml");
const unsignedWorkflowPath = path.join(repoRoot, ".github", "workflows", "macos-unsigned-test.yml");
const verifyMacPath = path.join(appDir, "scripts", "verify-macos.sh");

for (const required of [productionWorkflowPath, unsignedWorkflowPath, verifyMacPath]) {
  assert.ok(fs.existsSync(required), `Required release file is missing: ${required}`);
}

const production = fs.readFileSync(productionWorkflowPath, "utf8");
const unsigned = fs.readFileSync(unsignedWorkflowPath, "utf8");
const verifyMac = fs.readFileSync(verifyMacPath, "utf8");

const requiredProductionTokens = [
  "push:",
  "tags:",
  "v*",
  "working-directory: ethereum-defi-risk-radar-desktop-v0.7.0",
  "git merge-base --is-ancestor",
  "MAC_CSC_LINK",
  "APPLE_API_KEY_BASE64",
  "npm ci",
  "npm run check",
  "npm run dist:mac",
  "npm run verify:mac",
  "npm run dist:win",
  "SHA256SUMS.txt",
  "gh release create",
  "gh release upload",
  "contents: write",
  "github.ref_type == 'tag'"
];

for (const token of requiredProductionTokens) {
  assert.ok(production.includes(token), `Production release workflow is missing required token: ${token}`);
}

for (const token of [
  "workflow_dispatch:",
  "npm run dist:mac:unsigned",
  "SHA256SUMS-unsigned-test.txt",
  "working-directory: ethereum-defi-risk-radar-desktop-v0.7.0"
]) {
  assert.ok(unsigned.includes(token), `Unsigned macOS workflow is missing required token: ${token}`);
}

assert.ok(!unsigned.includes("push:\n    tags:"), "Unsigned macOS workflow must never publish from release tags.");
assert.ok(verifyMac.includes("require('./package.json').version"), "macOS verification must derive the expected CLI version from package.json.");
assert.ok(!verifyMac.includes('!= "0.7.0"'), "macOS verification must not hard-code a release version.");

for (const legacyPath of [
  path.join(appDir, ".github", "workflows", "macos-installer.yml"),
  path.join(appDir, ".github", "workflows", "macos-unsigned-test.yml"),
  path.join(appDir, ".github", "workflows", "windows-installer.yml")
]) {
  assert.equal(fs.existsSync(legacyPath), false, `Ignored nested workflow still exists: ${legacyPath}`);
}

console.log("Release workflow checks passed: repository-level workflows, gated publishing, dynamic version verification, and nested-workflow cleanup are present.");
