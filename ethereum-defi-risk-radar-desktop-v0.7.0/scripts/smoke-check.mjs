import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanLegacyEthereumDefi } from "../dist/scanner.js";
import { writeReports } from "../dist/report.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const rendererDir = path.join(root, "desktop", "renderer");
const html = await fs.readFile(path.join(rendererDir, "index.html"), "utf8");
const js = await fs.readFile(path.join(rendererDir, "app.js"), "utf8");
const preload = await fs.readFile(path.join(root, "desktop", "preload.cjs"), "utf8");
const packageJson = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));

const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
if (duplicates.length) throw new Error(`Duplicate renderer IDs: ${[...new Set(duplicates)].join(", ")}`);

const idSet = new Set(ids);
const jsRefs = [...js.matchAll(/\$\("([^"]+)"\)/g)].map(match => match[1]);
const missing = [...new Set(jsRefs.filter(id => !idSet.has(id)))];
if (missing.length) throw new Error(`Renderer references missing IDs: ${missing.join(", ")}`);

for (const unsafe of ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function("]) {
  if (js.includes(unsafe)) throw new Error(`Unsafe renderer API found: ${unsafe}`);
}
if (/\sstyle=/.test(html)) throw new Error("Inline style attribute found; CSP requires external styles.");

for (const bridgeMethod of [
  "getAppInfo", "getSettings", "saveSettings", "chooseOutputDir", "testConnections", "startScan",
  "getLastScan", "exportScanSummary", "showReport", "openOutputFolder", "openExternal",
  "getCliStatus", "installCli", "uninstallCli", "getAnalysisCapabilities", "onNavigate"
]) {
  if (!preload.includes(bridgeMethod)) throw new Error(`Missing preload bridge method: ${bridgeMethod}`);
}

if (packageJson.version !== "0.7.0") throw new Error("Desktop release version must be 0.7.0.");
if (!String(packageJson.devDependencies?.electron || "").startsWith("^43.")) {
  throw new Error("Electron 43.x is required for the macOS 12+ compatibility target.");
}
const cliResources = packageJson.build?.extraResources || [];
if (!cliResources.some(item => item?.from === "cli" && item?.to === "cli")) {
  throw new Error("Bundled CLI launcher must be copied through extraResources.");
}
if (packageJson.build?.nsis?.include !== "build/installer.nsh") {
  throw new Error("Windows NSIS CLI integration include is missing.");
}
for (const relative of ["cli/launch.cjs", "build/installer.nsh"]) {
  try { await fs.access(path.join(root, relative)); }
  catch { throw new Error(`Missing bundled CLI resource: ${relative}`); }
}
const mainProcessSource = await fs.readFile(path.join(root, "src", "desktop", "main.ts"), "utf8");
for (const required of ["--cli", "runDesktopCli", "installCliCommand", "cliInstallStatus", "case \"doctor\""]) {
  if (!mainProcessSource.includes(required)) throw new Error(`Desktop CLI runtime missing marker: ${required}`);
}
const launcherSource = await fs.readFile(path.join(root, "cli", "launch.cjs"), "utf8");
if (!launcherSource.includes("ELECTRON_RUN_AS_NODE") || !launcherSource.includes("--cli")) {
  throw new Error("Bundled CLI launcher does not bridge Node mode to Electron CLI mode.");
}
const macTargets = packageJson.build?.mac?.target || [];
for (const targetName of ["dmg", "zip"]) {
  const target = macTargets.find(item => item?.target === targetName);
  if (!target || !Array.isArray(target.arch) || !target.arch.includes("universal")) {
    throw new Error(`Missing universal macOS ${targetName} target.`);
  }
}
if (packageJson.build?.mac?.minimumSystemVersion !== "12.0") throw new Error("macOS minimum system version must be 12.0.");
if (packageJson.build?.mac?.notarize !== true) throw new Error("Production macOS notarization must remain enabled.");
if (packageJson.build?.mac?.hardenedRuntime !== true) throw new Error("Production macOS Hardened Runtime must remain enabled.");
for (const relative of [
  "build/icon.icns",
  "build/entitlements.mac.plist",
  "build/entitlements.mac.inherit.plist",
  ".github/workflows/macos-installer.yml",
  "scripts/check-macos-release.mjs",
  "scripts/verify-macos.sh"
]) {
  try { await fs.access(path.join(root, relative)); }
  catch { throw new Error(`Missing macOS distribution resource: ${relative}`); }
}
const icnsHeader = await fs.readFile(path.join(root, "build", "icon.icns"));
if (icnsHeader.subarray(0, 4).toString("ascii") !== "icns") throw new Error("build/icon.icns is not a valid ICNS container.");

const events = [];
const mockClient = { search: async () => ({ results: [] }) };
const mockCandidates = await scanLegacyEthereumDefi({
  client: mockClient,
  startYear: 2016,
  endYear: 2016,
  pagesPerQuery: 1,
  minPublicSignals: 2,
  maxEtherscanLookupsPerCandidate: 2,
  inspectVerifiedSource: true,
  maxSourceBytes: 2_000_000,
  maxSourceFindings: 80,
  onProgressEvent: event => events.push(event)
});
if (mockCandidates.length !== 0) throw new Error("Scanner mock should return zero candidates.");
if (events.at(-1)?.overallPercent !== 95) throw new Error("Scanner progress event regression.");

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "defi-risk-radar-smoke-"));
const address = "0x1111111111111111111111111111111111111111";
const candidate = {
  id: "smoke",
  label: `Contract ${address}`,
  hostname: "etherscan.io",
  chain: "ethereum",
  network: "mainnet",
  researchScore: 50,
  ethereumConfidence: 90,
  signalCount: 2,
  sourceDiversity: 1,
  kinds: ["deprecated", "historical_incident"],
  classification: "REVIEW",
  evidence: [{
    kind: "deprecated",
    weight: 25,
    sourceUrl: `https://etherscan.io/address/${address}`,
    sourceTitle: `Title ${address}`,
    sourceHost: "etherscan.io",
    sourceTrust: "HIGH",
    snippet: `Reference ${address}`,
    year: 2020,
    query: "q",
    ethereumTerms: ["ethereum"],
    contractReferenceCount: 1
  }],
  ethereum: {
    chainId: 1,
    network: "ethereum-mainnet",
    contractReferencesObserved: 1,
    etherscanLookupsAttempted: 1,
    verifiedSourceContracts: 1,
    proxyContracts: 0,
    sourceContractsInspected: 0,
    sourceFindingCount: 0,
    sourceHighReviewCount: 0,
    advancedFindingCount: 0,
    sourceInspections: []
  }
};
const reportPaths = await writeReports({ candidates: [candidate], outputDir: tempDir, startYear: 2020, endYear: 2020 });
const reportText = await fs.readFile(reportPaths.jsonPath, "utf8");
if (reportText.includes(address)) throw new Error("Contract address leaked into generated report.");
if (!reportText.includes("[contract-address]")) throw new Error("Report redaction marker missing.");
await fs.rm(tempDir, { recursive: true, force: true });

console.log("Smoke checks passed: renderer/preload structure, bundled CLI integration, macOS distribution config, scanner progress, and report redaction.");
