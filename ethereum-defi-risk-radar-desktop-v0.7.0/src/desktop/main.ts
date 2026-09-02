import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  safeStorage,
  shell
} from "electron";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { TinyFishSearchClient } from "../tinyfish.js";
import { EtherscanClient } from "../etherscan.js";
import { scanLegacyEthereumDefi } from "../scanner.js";
import { writeReports } from "../report.js";
import { detectAnalysisCapabilities } from "../analysis/capabilities.js";
import { runAnalysisPlan } from "../analysis/orchestrator.js";
import { DEFAULT_ANALYSIS_BUDGET, type AnalysisEngineId } from "../analysis/model.js";
import { simulateEconomicScenario, type EconomicAction, type EconomicState } from "../analysis/economic/simulator.js";
import { ECONOMIC_SCENARIO_PACKS } from "../analysis/economic/scenarios.js";
import { runProtocolScenarios, type ProtocolObservations } from "../analysis/protocol.js";
import { replayOnPinnedAnvil, type ForkReplaySpec } from "../analysis/reproduction.js";
import { analyzeProjectFromDesktop, replayForkFromDesktop, simulateEconomicFromDesktop, simulateProtocolFromDesktop } from "./analysisLab.js";
import type { Candidate } from "../types.js";

const STORE_VERSION = 1;
const execFileAsync = promisify(execFile);

interface Preferences {
  tinyfishEndpoint: string;
  maxEtherscanLookupsPerCandidate: number;
  inspectVerifiedSource: boolean;
  maxSourceBytes: number;
  maxSourceFindingsPerContract: number;
  maxPagesPerQuery: number;
  minPublicSignals: number;
  outputDir: string;
}

interface PersistedStore {
  version: number;
  encryptedTinyfishApiKey?: string;
  encryptedEtherscanApiKey?: string;
  preferences?: Partial<Preferences>;
}

interface PublicSettings extends Preferences {
  hasTinyfishApiKey: boolean;
  hasEtherscanApiKey: boolean;
  secureStorageAvailable: boolean;
  firstRun: boolean;
}

interface SaveSettingsPayload extends Partial<Preferences> {
  tinyfishApiKey?: string;
  etherscanApiKey?: string;
  clearEtherscanApiKey?: boolean;
}

interface ScanRequest {
  startYear: number;
  endYear: number;
  pagesPerQuery?: number;
}

interface ScanResult {
  candidates: Candidate[];
  paths: { jsonPath: string; csvPath: string };
  startYear: number;
  endYear: number;
  pagesPerQuery: number;
  startedAt: string;
  completedAt: string;
  durationMs: number;
}

let mainWindow: BrowserWindow | null = null;
let scanRunning = false;
let lastScan: ScanResult | null = null;
let analysisController: AbortController | null = null;
const authorizedAnalysisPaths = new Set<string>();

function clampInt(value: unknown, fallback: number, min: number, max: number) {
  const parsed = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(Math.trunc(parsed), max));
}

function defaultOutputDir() {
  return path.join(app.getPath("documents"), "Ethereum DeFi Risk Radar", "reports");
}

function defaultPreferences(): Preferences {
  return {
    tinyfishEndpoint: "https://api.search.tinyfish.ai",
    maxEtherscanLookupsPerCandidate: 2,
    inspectVerifiedSource: true,
    maxSourceBytes: 2_000_000,
    maxSourceFindingsPerContract: 80,
    maxPagesPerQuery: 1,
    minPublicSignals: 2,
    outputDir: defaultOutputDir()
  };
}

function storePath() {
  return path.join(app.getPath("userData"), "settings.json");
}

async function readStore(): Promise<PersistedStore> {
  try {
    const raw = await fs.readFile(storePath(), "utf8");
    const parsed = JSON.parse(raw) as PersistedStore;
    return parsed && typeof parsed === "object"
      ? parsed
      : { version: STORE_VERSION };
  } catch {
    return { version: STORE_VERSION };
  }
}

async function writeStore(store: PersistedStore) {
  await fs.mkdir(path.dirname(storePath()), { recursive: true });
  await fs.writeFile(storePath(), JSON.stringify(store, null, 2), {
    encoding: "utf8",
    mode: 0o600
  });
}

function encryptSecret(value: string) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error(
      "Secure OS credential encryption is unavailable. API keys were not saved."
    );
  }
  return safeStorage.encryptString(value).toString("base64");
}

function decryptSecret(value?: string) {
  if (!value || !safeStorage.isEncryptionAvailable()) return "";
  try {
    return safeStorage.decryptString(Buffer.from(value, "base64"));
  } catch {
    return "";
  }
}

function normalizePreferences(input?: Partial<Preferences>): Preferences {
  const defaults = defaultPreferences();
  const endpoint = String(input?.tinyfishEndpoint ?? defaults.tinyfishEndpoint).trim();
  let parsedEndpoint: URL;
  try {
    parsedEndpoint = new URL(endpoint);
  } catch {
    parsedEndpoint = new URL(defaults.tinyfishEndpoint);
  }

  return {
    tinyfishEndpoint:
      parsedEndpoint.protocol === "https:"
        ? parsedEndpoint.toString().replace(/\/$/, "")
        : defaults.tinyfishEndpoint,
    maxEtherscanLookupsPerCandidate: clampInt(
      input?.maxEtherscanLookupsPerCandidate,
      defaults.maxEtherscanLookupsPerCandidate,
      0,
      5
    ),
    inspectVerifiedSource:
      typeof input?.inspectVerifiedSource === "boolean"
        ? input.inspectVerifiedSource
        : defaults.inspectVerifiedSource,
    maxSourceBytes: clampInt(
      input?.maxSourceBytes,
      defaults.maxSourceBytes,
      10_000,
      5_000_000
    ),
    maxSourceFindingsPerContract: clampInt(
      input?.maxSourceFindingsPerContract,
      defaults.maxSourceFindingsPerContract,
      1,
      250
    ),
    maxPagesPerQuery: clampInt(
      input?.maxPagesPerQuery,
      defaults.maxPagesPerQuery,
      1,
      10
    ),
    minPublicSignals: clampInt(
      input?.minPublicSignals,
      defaults.minPublicSignals,
      2,
      8
    ),
    outputDir: String(input?.outputDir ?? defaults.outputDir).trim() || defaults.outputDir
  };
}

async function getPublicSettings(): Promise<PublicSettings> {
  const store = await readStore();
  const preferences = normalizePreferences(store.preferences);
  const hasTinyfishApiKey = Boolean(decryptSecret(store.encryptedTinyfishApiKey));
  const hasEtherscanApiKey = Boolean(decryptSecret(store.encryptedEtherscanApiKey));
  return {
    ...preferences,
    hasTinyfishApiKey,
    hasEtherscanApiKey,
    secureStorageAvailable: safeStorage.isEncryptionAvailable(),
    firstRun: !hasTinyfishApiKey
  };
}

async function saveSettings(payload: SaveSettingsPayload): Promise<PublicSettings> {
  const store = await readStore();
  const current = normalizePreferences(store.preferences);
  const preferences = normalizePreferences({ ...current, ...payload });

  if (payload.tinyfishApiKey?.trim()) {
    store.encryptedTinyfishApiKey = encryptSecret(payload.tinyfishApiKey.trim());
  }

  if (payload.clearEtherscanApiKey) {
    delete store.encryptedEtherscanApiKey;
  } else if (payload.etherscanApiKey?.trim()) {
    store.encryptedEtherscanApiKey = encryptSecret(payload.etherscanApiKey.trim());
  }

  if (!decryptSecret(store.encryptedTinyfishApiKey)) {
    throw new Error("TinyFish API key is required before scanning.");
  }

  store.version = STORE_VERSION;
  store.preferences = preferences;
  await writeStore(store);
  return getPublicSettings();
}

async function runtimeConfig() {
  const store = await readStore();
  return {
    preferences: normalizePreferences(store.preferences),
    tinyfishApiKey: decryptSecret(store.encryptedTinyfishApiKey),
    etherscanApiKey: decryptSecret(store.encryptedEtherscanApiKey)
  };
}

function send(channel: string, payload: unknown) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, payload);
  }
}

function requireAuthorizedAnalysisPath(value: unknown, kind: "directory" | "json") {
  if (typeof value !== "string") throw new Error("A selected path is required");
  const resolved = path.resolve(value);
  if (!authorizedAnalysisPaths.has(resolved)) throw new Error("Select this path through the desktop picker before running analysis");
  if (kind === "json" && path.extname(resolved).toLowerCase() !== ".json") throw new Error("A JSON file is required");
  return resolved;
}

async function chooseAnalysisPath(kind: "directory" | "json") {
  const response = await dialog.showOpenDialog(mainWindow!, kind === "directory"
    ? { title: "Select Solidity project", properties: ["openDirectory"] }
    : { title: "Select JSON input", properties: ["openFile"], filters: [{ name: "JSON", extensions: ["json"] }] });
  if (response.canceled || !response.filePaths[0]) return null;
  const resolved = path.resolve(response.filePaths[0]);
  authorizedAnalysisPaths.add(resolved);
  return resolved;
}

async function withAnalysisRun<T>(label: string, work: (signal: AbortSignal) => Promise<T>) {
  if (analysisController) throw new Error("Another Analysis Lab workflow is already running");
  analysisController = new AbortController();
  send("analysis:state", { running: true, label });
  send("analysis:progress", { phase: "starting", message: `${label} started` });
  try {
    const result = await work(analysisController.signal);
    send("analysis:progress", { phase: "complete", message: `${label} completed` });
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    send("analysis:error", { message });
    throw error;
  } finally {
    analysisController = null;
    send("analysis:state", { running: false, label });
  }
}

async function testConnections() {
  const cfg = await runtimeConfig();
  if (!cfg.tinyfishApiKey) throw new Error("TinyFish API key is not configured.");

  const result: {
    tinyfish: { ok: boolean; message: string };
    etherscan: { ok: boolean | null; message: string };
  } = {
    tinyfish: { ok: false, message: "Not tested" },
    etherscan: {
      ok: cfg.etherscanApiKey ? false : null,
      message: cfg.etherscanApiKey ? "Not tested" : "Not configured"
    }
  };

  try {
    const tinyfish = new TinyFishSearchClient({
      apiKey: cfg.tinyfishApiKey,
      endpoint: cfg.preferences.tinyfishEndpoint
    });
    const response = await tinyfish.search({
      query: "Ethereum DeFi security",
      purpose: "Connection test for a defensive Ethereum DeFi OSINT research application.",
      language: "en",
      page: 0
    });
    result.tinyfish = {
      ok: true,
      message: `Connected${Array.isArray(response.results) ? ` · ${response.results.length} results received` : ""}`
    };
  } catch (error) {
    result.tinyfish = {
      ok: false,
      message: error instanceof Error ? error.message : "Connection failed"
    };
  }

  if (cfg.etherscanApiKey) {
    try {
      const etherscan = new EtherscanClient(cfg.etherscanApiKey);
      // WETH Mainnet is used only as a harmless verified-source API connectivity check.
      await etherscan.getSourceMetadata("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", {
        inspectSource: false
      });
      result.etherscan = { ok: true, message: "Connected to Etherscan API V2" };
    } catch (error) {
      result.etherscan = {
        ok: false,
        message: error instanceof Error ? error.message : "Connection failed"
      };
    }
  }

  return result;
}

async function startScan(request: ScanRequest) {
  if (scanRunning) throw new Error("A scan is already running.");

  const currentYear = new Date().getUTCFullYear();
  const startYear = clampInt(request.startYear, 2016, 2016, currentYear);
  const endYear = clampInt(request.endYear, currentYear, 2016, currentYear);
  if (endYear < startYear) throw new Error("End year must be greater than or equal to start year.");

  const cfg = await runtimeConfig();
  if (!cfg.tinyfishApiKey) throw new Error("TinyFish API key is not configured.");

  const pagesPerQuery = clampInt(
    request.pagesPerQuery,
    cfg.preferences.maxPagesPerQuery,
    1,
    10
  );

  const startedAt = new Date().toISOString();
  const startedAtMs = Date.now();

  scanRunning = true;
  send("scan:state", { running: true });
  send("scan:progress", {
    phase: "STARTING",
    message: `Starting Ethereum Mainnet scan for ${startYear}-${endYear}`,
    completed: 0,
    total: 0,
    overallPercent: 0
  });

  try {
    const tinyfish = new TinyFishSearchClient({
      apiKey: cfg.tinyfishApiKey,
      endpoint: cfg.preferences.tinyfishEndpoint
    });
    const etherscan = cfg.etherscanApiKey
      ? new EtherscanClient(cfg.etherscanApiKey)
      : undefined;

    const candidates = await scanLegacyEthereumDefi({
      client: tinyfish,
      etherscan,
      startYear,
      endYear,
      pagesPerQuery,
      minPublicSignals: cfg.preferences.minPublicSignals,
      maxEtherscanLookupsPerCandidate:
        cfg.preferences.maxEtherscanLookupsPerCandidate,
      inspectVerifiedSource: cfg.preferences.inspectVerifiedSource,
      maxSourceBytes: cfg.preferences.maxSourceBytes,
      maxSourceFindings: cfg.preferences.maxSourceFindingsPerContract,
      onProgress: message =>
        send("scan:log", { message, at: new Date().toISOString() }),
      onProgressEvent: event => send("scan:progress", event)
    });

    send("scan:progress", {
      phase: "REPORT",
      message: "Writing JSON and CSV reports",
      completed: 1,
      total: 1,
      overallPercent: 98
    });

    const paths = await writeReports({
      candidates,
      outputDir: cfg.preferences.outputDir,
      startYear,
      endYear
    });

    lastScan = {
      candidates,
      paths,
      startYear,
      endYear,
      pagesPerQuery,
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAtMs
    };

    send("scan:progress", {
      phase: "COMPLETE",
      message: `Scan complete · ${candidates.length} candidates`,
      completed: 1,
      total: 1,
      overallPercent: 100
    });
    send("scan:complete", lastScan);
    return { accepted: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    send("scan:error", { message });
    throw error;
  } finally {
    scanRunning = false;
    send("scan:state", { running: false });
  }
}

async function exportScanSummary() {
  if (!lastScan) {
    throw new Error("No completed scan is available to export.");
  }

  const candidates = lastScan.candidates;
  const payload = {
    generatedAt: new Date().toISOString(),
    application: "Ethereum DeFi Risk Radar",
    version: app.getVersion(),
    scope: {
      chain: "ethereum",
      chainId: 1,
      network: "mainnet",
      startYear: lastScan.startYear,
      endYear: lastScan.endYear,
      pagesPerQuery: lastScan.pagesPerQuery
    },
    summary: {
      candidates: candidates.length,
      highResearchPriority: candidates.filter(c => c.classification === "HIGH_RESEARCH_PRIORITY").length,
      sourceContractsInspected: candidates.reduce((sum, c) => sum + c.ethereum.sourceContractsInspected, 0),
      highReviewFindings: candidates.reduce((sum, c) => sum + c.ethereum.sourceHighReviewCount, 0)
    },
    startedAt: lastScan.startedAt,
    completedAt: lastScan.completedAt,
    durationMs: lastScan.durationMs,
    reports: lastScan.paths,
    interpretation: "Research priority and source-review signals are for defensive/manual review and do not establish current exploitability."
  };

  const response = await dialog.showSaveDialog(mainWindow!, {
    title: "Export scan summary",
    defaultPath: path.join(
      app.getPath("documents"),
      `ethereum-defi-risk-radar-summary-${lastScan.startYear}-${lastScan.endYear}.json`
    ),
    filters: [{ name: "JSON", extensions: ["json"] }]
  });

  if (response.canceled || !response.filePath) return null;
  await fs.writeFile(response.filePath, JSON.stringify(payload, null, 2), "utf8");
  return response.filePath;
}

function isSafeExternalUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}


function appInfo() {
  return {
    name: app.getName(),
    version: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    minimumMacOS: "12.0",
    secureStorageLabel:
      process.platform === "darwin"
        ? "macOS Keychain"
        : process.platform === "win32"
          ? "Windows OS-backed secure storage"
          : "OS-backed secure storage"
  };
}

function navigateRenderer(view: "dashboard" | "results" | "activity" | "settings") {
  send("app:navigate", { view });
}

function installApplicationMenu() {
  if (process.platform !== "darwin") {
    Menu.setApplicationMenu(null);
    return;
  }

  app.setAboutPanelOptions({
    applicationName: "Ethereum DeFi Risk Radar",
    applicationVersion: app.getVersion(),
    version: app.getVersion(),
    credits: "Defensive Ethereum DeFi OSINT and verified-source research tooling."
  });

  const template = [
    {
      label: app.name,
      submenu: [
        { role: "about" },
        { type: "separator" },
        {
          label: "Settings…",
          accelerator: "CommandOrControl+,",
          click: () => navigateRenderer("settings")
        },
        { type: "separator" },
        { role: "services" },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit" }
      ]
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "pasteAndMatchStyle" },
        { role: "delete" },
        { role: "selectAll" }
      ]
    },
    {
      label: "View",
      submenu: [
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" }
      ]
    },
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        { type: "separator" },
        { role: "front" }
      ]
    }
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template as any));
}



const CLI_PROFILE_START = "# >>> Ethereum DeFi Risk Radar CLI >>>";
const CLI_PROFILE_END = "# <<< Ethereum DeFi Risk Radar CLI <<<";

function isCliInvocation() {
  return process.argv.includes("--cli");
}

function cliArgs() {
  const index = process.argv.indexOf("--cli");
  return index >= 0 ? process.argv.slice(index + 1) : [];
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function cliLauncherSource() {
  const launcher = path.join(process.resourcesPath, "cli", "launch.cjs");
  if (process.platform === "win32") {
    return [
      "@echo off",
      "setlocal",
      'set "ELECTRON_RUN_AS_NODE=1"',
      `"${process.execPath}" "${launcher}" %*`,
      "exit /b %ERRORLEVEL%",
      ""
    ].join("\r\n");
  }
  return [
    "#!/bin/sh",
    'export ELECTRON_RUN_AS_NODE=1',
    `exec ${shellQuote(process.execPath)} ${shellQuote(launcher)} \"$@\"`,
    ""
  ].join("\n");
}

function cliInstallLocation() {
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(app.getPath("home"), "AppData", "Local");
    return path.join(localAppData, "Microsoft", "WindowsApps", "risk-radar.cmd");
  }
  return path.join(app.getPath("home"), ".local", "bin", "risk-radar");
}

function preferredShellProfile() {
  const home = app.getPath("home");
  const shell = path.basename(process.env.SHELL || "").toLowerCase();
  if (shell.includes("zsh")) return path.join(home, ".zprofile");
  if (shell.includes("bash")) return path.join(home, ".bash_profile");
  return path.join(home, ".profile");
}

function normalizedPathEntries() {
  const separator = process.platform === "win32" ? ";" : ":";
  return (process.env.PATH || "")
    .split(separator)
    .map(entry => path.resolve(entry || "."));
}

async function pathExists(target: string) {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function cliInstallStatus() {
  const commandPath = cliInstallLocation();
  const binDir = path.dirname(commandPath);
  const entries = normalizedPathEntries();
  const normalizedBin = path.resolve(binDir);
  const pathConfigured = entries.some(entry =>
    process.platform === "win32"
      ? entry.toLowerCase() === normalizedBin.toLowerCase()
      : entry === normalizedBin
  );
  return {
    platform: process.platform,
    packaged: app.isPackaged,
    installed: await pathExists(commandPath),
    command: "risk-radar",
    commandPath,
    binDir,
    pathConfigured,
    managedByInstaller: process.platform === "win32",
    shellProfile: process.platform === "darwin" ? preferredShellProfile() : null
  };
}

async function ensureWindowsCliPath() {
  if (process.platform !== "win32") return;
  const binDir = path.dirname(cliInstallLocation());
  const normalizedBin = path.resolve(binDir).toLowerCase();
  if (normalizedPathEntries().some(entry => entry.toLowerCase() === normalizedBin)) return;

  const command = [
    "$bin=$env:RISK_RADAR_CLI_BIN",
    "$user=[Environment]::GetEnvironmentVariable('Path','User')",
    "$parts=@($user -split ';' | Where-Object { $_ -and $_.Trim() })",
    "if (-not ($parts | Where-Object { $_.TrimEnd('\\') -ieq $bin.TrimEnd('\\') })) {",
    "  $new=if ([string]::IsNullOrWhiteSpace($user)) {$bin} else {$user.TrimEnd(';')+';'+$bin}",
    "  [Environment]::SetEnvironmentVariable('Path',$new,'User')",
    "}"
  ].join("\n");
  try {
    await execFileAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command], {
      windowsHide: true,
      env: { ...process.env, RISK_RADAR_CLI_BIN: binDir }
    });
    process.env.PATH = `${binDir};${process.env.PATH || ""}`;
  } catch (error) {
    throw new Error(`CLI launcher was written, but Windows PATH could not be updated: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function ensureMacCliPath() {
  if (process.platform !== "darwin") return;
  const binDir = path.dirname(cliInstallLocation());
  const entries = normalizedPathEntries();
  const alreadyInPath = entries.includes(path.resolve(binDir));
  if (!alreadyInPath) process.env.PATH = `${binDir}:${process.env.PATH || ""}`;

  const profile = preferredShellProfile();
  let existing = "";
  try { existing = await fs.readFile(profile, "utf8"); } catch { /* create on demand */ }
  if (alreadyInPath || existing.includes(CLI_PROFILE_START)) return;
  const block = `${CLI_PROFILE_START}\nexport PATH=\"$HOME/.local/bin:$PATH\"\n${CLI_PROFILE_END}\n`;
  const prefix = existing && !existing.endsWith("\n") ? "\n" : "";
  await fs.writeFile(profile, existing + prefix + block, { encoding: "utf8", mode: 0o600 });
}

async function removeMacCliPathBlock() {
  if (process.platform !== "darwin") return;
  const profile = preferredShellProfile();
  let existing = "";
  try { existing = await fs.readFile(profile, "utf8"); } catch { return; }
  const start = existing.indexOf(CLI_PROFILE_START);
  const endMarker = existing.indexOf(CLI_PROFILE_END, start >= 0 ? start : 0);
  let updated = existing;
  if (start >= 0 && endMarker >= 0) {
    let end = endMarker + CLI_PROFILE_END.length;
    if (existing.slice(end, end + 2) === "\r\n") end += 2;
    else if (existing.slice(end, end + 1) === "\n") end += 1;
    let begin = start;
    if (begin > 0 && existing.slice(begin - 2, begin) === "\r\n") begin -= 2;
    else if (begin > 0 && existing.slice(begin - 1, begin) === "\n") begin -= 1;
    updated = existing.slice(0, begin) + existing.slice(end);
  }
  if (updated !== existing) await fs.writeFile(profile, updated, { encoding: "utf8", mode: 0o600 });
}

async function installCliCommand() {
  if (!app.isPackaged) {
    throw new Error("The global CLI command can only be installed from a packaged desktop application.");
  }
  if (!await pathExists(path.join(process.resourcesPath, "cli", "launch.cjs"))) {
    throw new Error("Bundled CLI launcher is missing from this installation.");
  }

  const commandPath = cliInstallLocation();
  await fs.mkdir(path.dirname(commandPath), { recursive: true });
  await fs.writeFile(commandPath, cliLauncherSource(), {
    encoding: "utf8",
    mode: process.platform === "win32" ? 0o600 : 0o755
  });
  if (process.platform !== "win32") await fs.chmod(commandPath, 0o755);
  await ensureWindowsCliPath();
  await ensureMacCliPath();
  return cliInstallStatus();
}

async function uninstallCliCommand() {
  const commandPath = cliInstallLocation();
  await fs.rm(commandPath, { force: true });
  await removeMacCliPathBlock();
  return cliInstallStatus();
}

function cliOption(args: string[], name: string) {
  const prefix = `--${name}=`;
  const inline = args.find(arg => arg.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);
  const index = args.indexOf(`--${name}`);
  if (index >= 0 && index + 1 < args.length) return args[index + 1];
  return undefined;
}

function cliFlag(args: string[], name: string) {
  return args.includes(`--${name}`);
}

function boolValue(value: string) {
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on", "enabled"].includes(normalized)) return true;
  if (["false", "0", "no", "off", "disabled"].includes(normalized)) return false;
  throw new Error(`Expected true/false value, received: ${value}`);
}

function printCliHelp() {
  console.log(`Ethereum DeFi Risk Radar CLI v${app.getVersion()}

Usage:
  risk-radar <command> [options]

Commands:
  scan                  Run a defensive Ethereum Mainnet research scan
  status                Show configuration and CLI installation status
  test-connections      Test TinyFish and optional Etherscan credentials
  config show           Show saved non-secret configuration
  config set <key> <v>  Update a saved setting (API keys prompt securely)
  config remove etherscan-key
                        Remove the optional Etherscan credential
  reports               List recent generated reports
  open-reports          Open the configured reports directory
  install-cli           Install/repair the global risk-radar command
  uninstall-cli         Remove the user-level global CLI launcher
  doctor                Run local configuration diagnostics
  capabilities          Show native and optional analysis-engine availability
  analyze-project <dir> Run native Solidity analysis for a local project
  economic-scenarios    List built-in DeFi economic scenario packs
  simulate-economic <file.json>
                        Run a deterministic economic state-transition scenario
  simulate-protocol <project> <observations.json>
                        Run scenario packs against a source-linked protocol model
  replay-fork <spec.json> --confirm-fork
                        Replay transactions on a pinned loopback Anvil fork
  version               Print the application version
  help                  Show this help

Scan options:
  --start=2016          Start year (2016 or later)
  --end=${new Date().getUTCFullYear()}            End year
  --pages=1             TinyFish pages per query (1-10)
  --quiet               Suppress per-query activity lines

Project analysis options:
  --deep                Include installed Slither, Mythril, Foundry, and Echidna
  --trust-project       Confirm project build/test code may execute (required by --deep)
  --timeout=120         Per-engine timeout in seconds (1-3600)

Configuration keys:
  tinyfish-key          Secure TinyFish API key (interactive prompt)
  etherscan-key         Secure Etherscan API key (interactive prompt)
  endpoint              TinyFish Search endpoint
  pages                 Default pages per query
  min-signals           Minimum public signals
  etherscan-lookups     Etherscan lookups per candidate
  inspect-source        true/false
  max-source-bytes      Maximum verified-source bytes
  max-findings          Maximum findings per contract
  output-dir            Report output directory

The installed CLI and desktop UI use the same OS-encrypted API credentials and settings.`);
}

async function promptSecret(label: string) {
  if (!process.stdin.isTTY || !process.stdout.isTTY || typeof process.stdin.setRawMode !== "function") {
    throw new Error(`${label} must be entered from an interactive terminal.`);
  }
  process.stdout.write(`${label}: `);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  return await new Promise<string>((resolve, reject) => {
    let value = "";
    const cleanup = () => {
      process.stdin.setRawMode?.(false);
      process.stdin.pause();
      process.stdin.removeListener("data", onData);
    };
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === "\u0003") {
          cleanup();
          process.stdout.write("\n");
          reject(new Error("Cancelled."));
          return;
        }
        if (char === "\r" || char === "\n") {
          cleanup();
          process.stdout.write("\n");
          resolve(value.trim());
          return;
        }
        if (char === "\u007f" || char === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        if (char >= " ") value += char;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function cliConfigShow() {
  const settings = await getPublicSettings();
  console.log(JSON.stringify({
    tinyfishApiKey: settings.hasTinyfishApiKey ? "configured" : "missing",
    etherscanApiKey: settings.hasEtherscanApiKey ? "configured" : "not configured",
    tinyfishEndpoint: settings.tinyfishEndpoint,
    maxPagesPerQuery: settings.maxPagesPerQuery,
    minPublicSignals: settings.minPublicSignals,
    maxEtherscanLookupsPerCandidate: settings.maxEtherscanLookupsPerCandidate,
    inspectVerifiedSource: settings.inspectVerifiedSource,
    maxSourceBytes: settings.maxSourceBytes,
    maxSourceFindingsPerContract: settings.maxSourceFindingsPerContract,
    outputDir: settings.outputDir,
    secureStorageAvailable: settings.secureStorageAvailable
  }, null, 2));
}

async function cliConfigSet(args: string[]) {
  const key = args[0];
  if (!key) throw new Error("Usage: risk-radar config set <key> <value>");
  if (key === "tinyfish-key" || key === "etherscan-key") {
    const secret = await promptSecret(key === "tinyfish-key" ? "TinyFish API key" : "Etherscan API key");
    if (!secret) throw new Error("API key cannot be empty.");
    await saveSettings(key === "tinyfish-key" ? { tinyfishApiKey: secret } : { etherscanApiKey: secret });
    console.log(`${key} saved with OS-backed encryption.`);
    return;
  }

  const value = args.slice(1).join(" ").trim();
  if (!value) throw new Error(`A value is required for ${key}.`);
  const settings = await getPublicSettings();
  const payload: SaveSettingsPayload = {};
  switch (key) {
    case "endpoint": payload.tinyfishEndpoint = value; break;
    case "pages": payload.maxPagesPerQuery = clampInt(value, settings.maxPagesPerQuery, 1, 10); break;
    case "min-signals": payload.minPublicSignals = clampInt(value, settings.minPublicSignals, 2, 8); break;
    case "etherscan-lookups": payload.maxEtherscanLookupsPerCandidate = clampInt(value, settings.maxEtherscanLookupsPerCandidate, 0, 5); break;
    case "inspect-source": payload.inspectVerifiedSource = boolValue(value); break;
    case "max-source-bytes": payload.maxSourceBytes = clampInt(value, settings.maxSourceBytes, 10_000, 5_000_000); break;
    case "max-findings": payload.maxSourceFindingsPerContract = clampInt(value, settings.maxSourceFindingsPerContract, 1, 250); break;
    case "output-dir": payload.outputDir = path.resolve(value); break;
    default: throw new Error(`Unknown configuration key: ${key}`);
  }
  await saveSettings(payload);
  console.log(`${key} updated.`);
}

async function cliReports() {
  const cfg = await runtimeConfig();
  await fs.mkdir(cfg.preferences.outputDir, { recursive: true });
  const entries = await fs.readdir(cfg.preferences.outputDir, { withFileTypes: true });
  const reports = [] as Array<{ name: string; modified: number; bytes: number }>;
  for (const entry of entries) {
    if (!entry.isFile() || !/\.(json|csv)$/i.test(entry.name)) continue;
    const stat = await fs.stat(path.join(cfg.preferences.outputDir, entry.name));
    reports.push({ name: entry.name, modified: stat.mtimeMs, bytes: stat.size });
  }
  reports.sort((a, b) => b.modified - a.modified);
  console.log(`Reports directory: ${cfg.preferences.outputDir}`);
  if (!reports.length) {
    console.log("No generated reports found.");
    return;
  }
  console.table(reports.slice(0, 20).map(item => ({
    file: item.name,
    modified: new Date(item.modified).toLocaleString(),
    sizeKB: Math.max(1, Math.round(item.bytes / 1024))
  })));
}

async function cliScan(args: string[]) {
  const cfg = await runtimeConfig();
  if (!cfg.tinyfishApiKey) {
    throw new Error("TinyFish API key is not configured. Open the desktop app or run: risk-radar config set tinyfish-key");
  }
  const currentYear = new Date().getUTCFullYear();
  const startYear = clampInt(cliOption(args, "start"), 2016, 2016, currentYear);
  const endYear = clampInt(cliOption(args, "end"), currentYear, 2016, currentYear);
  if (endYear < startYear) throw new Error("End year must be greater than or equal to start year.");
  const pagesPerQuery = clampInt(cliOption(args, "pages"), cfg.preferences.maxPagesPerQuery, 1, 10);
  const quiet = cliFlag(args, "quiet");

  const tinyfish = new TinyFishSearchClient({ apiKey: cfg.tinyfishApiKey, endpoint: cfg.preferences.tinyfishEndpoint });
  const etherscan = cfg.etherscanApiKey ? new EtherscanClient(cfg.etherscanApiKey) : undefined;
  console.log(`Ethereum DeFi Risk Radar v${app.getVersion()}`);
  console.log(`Ethereum Mainnet (chain 1) · ${startYear}-${endYear}`);
  console.log(`TinyFish pages/query: ${pagesPerQuery} · Etherscan: ${etherscan ? "ON" : "OFF"} · verified-source inspection: ${etherscan && cfg.preferences.inspectVerifiedSource ? "ON" : "OFF"}`);
  console.log("Defensive passive research only; findings are review signals, not proof of exploitability.\n");

  const candidates = await scanLegacyEthereumDefi({
    client: tinyfish,
    etherscan,
    startYear,
    endYear,
    pagesPerQuery,
    minPublicSignals: cfg.preferences.minPublicSignals,
    maxEtherscanLookupsPerCandidate: cfg.preferences.maxEtherscanLookupsPerCandidate,
    inspectVerifiedSource: cfg.preferences.inspectVerifiedSource,
    maxSourceBytes: cfg.preferences.maxSourceBytes,
    maxSourceFindings: cfg.preferences.maxSourceFindingsPerContract,
    onProgress: quiet ? undefined : message => console.log(message),
    onProgressEvent: quiet ? event => {
      if (event.overallPercent === 70 || event.overallPercent === 95) console.log(`${event.overallPercent}% · ${event.message}`);
    } : undefined
  });
  const paths = await writeReports({ candidates, outputDir: cfg.preferences.outputDir, startYear, endYear });
  console.log(`\nCandidates: ${candidates.length}`);
  console.table(candidates.slice(0, 25).map(c => ({
    score: c.researchScore,
    eth: `${c.ethereumConfidence}%`,
    class: c.classification,
    signals: c.signalCount,
    sources: c.sourceDiversity,
    verified: c.ethereum.verifiedSourceContracts,
    inspected: c.ethereum.sourceContractsInspected,
    highReview: c.ethereum.sourceHighReviewCount,
    candidate: c.label.slice(0, 54)
  })));
  console.log(`JSON: ${paths.jsonPath}`);
  console.log(`CSV:  ${paths.csvPath}`);
}

async function cliDoctor() {
  const settings = await getPublicSettings();
  const cli = await cliInstallStatus();
  const analysisCapabilities = await detectAnalysisCapabilities();
  let outputWritable = false;
  try {
    await fs.mkdir(settings.outputDir, { recursive: true });
    const probe = path.join(settings.outputDir, `.risk-radar-write-test-${process.pid}`);
    await fs.writeFile(probe, "ok", "utf8");
    await fs.rm(probe, { force: true });
    outputWritable = true;
  } catch { outputWritable = false; }
  const diagnostics = [
    ["Application", `v${app.getVersion()}`, true],
    ["Platform", `${process.platform}/${process.arch}`, true],
    ["Secure storage", settings.secureStorageAvailable ? "available" : "unavailable", settings.secureStorageAvailable],
    ["TinyFish key", settings.hasTinyfishApiKey ? "configured" : "missing", settings.hasTinyfishApiKey],
    ["Etherscan key", settings.hasEtherscanApiKey ? "configured" : "optional / not configured", true],
    ["Reports directory", outputWritable ? "writable" : "not writable", outputWritable],
    ["Global CLI", cli.installed ? cli.commandPath : "not installed", cli.installed]
  ] as Array<[string, string, boolean]>;
  for (const [label, value, ok] of diagnostics) console.log(`${ok ? "✓" : "✗"} ${label}: ${value}`);
  console.log("\nOptional analysis engines:");
  for (const capability of analysisCapabilities) {
    const detail = capability.available
      ? capability.version || capability.executable || "available"
      : "not installed (optional)";
    console.log(`${capability.available ? "+" : "-"} ${capability.id}: ${detail}`);
  }
  if (!settings.hasTinyfishApiKey || !settings.secureStorageAvailable || !outputWritable) return 2;
  return 0;
}

async function cliAnalyzeProject(args: string[]) {
  const targetArg = args.find(arg => !arg.startsWith("--"));
  if (!targetArg) throw new Error("Usage: risk-radar analyze-project <directory> [--deep --trust-project --timeout=120]");
  const targetPath = path.resolve(targetArg);
  const stat = await fs.stat(targetPath);
  if (!stat.isDirectory()) throw new Error("Analysis target must be a project directory");
  const deep = args.includes("--deep");
  const trusted = args.includes("--trust-project");
  if (deep && !trusted) throw new Error("--deep requires --trust-project because compiler/test hooks can execute project code");
  const timeoutArg = args.find(arg => arg.startsWith("--timeout="));
  const timeoutSeconds = Math.max(1, Math.min(Number(timeoutArg?.split("=")[1] ?? 120), 3_600));
  const framework: "foundry" | "hardhat" | "unknown" = await fs.access(path.join(targetPath, "foundry.toml")).then(() => "foundry" as const).catch(async () =>
    await fs.access(path.join(targetPath, "hardhat.config.js")).then(() => "hardhat" as const).catch(() => "unknown" as const));
  const engines = deep
    ? ["native", "slither", "mythril", "foundry", "echidna"] as const
    : ["native"] as const;
  const result = await runAnalysisPlan({
    target: { type: "local_project", path: targetPath, framework, trusted },
    engines: [...engines],
    budget: { ...DEFAULT_ANALYSIS_BUDGET, timeoutMs: timeoutSeconds * 1_000 }
  });
  const safe = {
    targetType: result.targetType,
    native: result.native ? {
      filesAnalyzed: result.native.filesAnalyzed,
      functionsAnalyzed: result.native.functionsAnalyzed,
      graphCount: result.native.graphs.length,
      dependencyCount: result.native.dependencies.length,
      storageSurfaceCount: result.native.storage.length,
      crossContractCallCount: result.native.calls.length,
      truncations: result.native.truncations,
      partial: result.native.partial,
      findings: result.native.findings
    } : undefined,
    engines: result.engines,
    findingCount: result.findings.length,
    protocol: result.protocol,
    state: result.state,
    notes: result.notes
  };
  console.log(JSON.stringify(safe, null, 2));
}

async function cliSimulateEconomic(args: string[]) {
  const targetArg = args.find(arg => !arg.startsWith("--"));
  if (!targetArg) throw new Error("Usage: risk-radar simulate-economic <scenario.json> [--max-steps=10000]");
  const inputPath = path.resolve(targetArg);
  const stat = await fs.stat(inputPath);
  if (!stat.isFile() || stat.size > 5_000_000) throw new Error("Economic scenario must be a JSON file no larger than 5 MB");
  const input = JSON.parse(await fs.readFile(inputPath, "utf8")) as { initial?: EconomicState; actions?: EconomicAction[] };
  if (!input.initial || !Array.isArray(input.actions)) throw new Error("Scenario JSON requires initial state and actions array");
  const maxArg = args.find(arg => arg.startsWith("--max-steps="));
  const maxSteps = Math.max(1, Math.min(Number(maxArg?.split("=")[1] ?? 10_000), 100_000));
  const result = simulateEconomicScenario(input.initial, input.actions, maxSteps);
  console.log(JSON.stringify(result, null, 2));
  return result.invariants.every(invariant => invariant.passed) ? 0 : 3;
}

async function cliSimulateProtocol(args: string[]) {
  const positional = args.filter(arg => !arg.startsWith("--"));
  if (positional.length < 2) throw new Error("Usage: risk-radar simulate-protocol <project> <observations.json> [--seed=1]");
  const projectPath = path.resolve(positional[0]);
  const inputPath = path.resolve(positional[1]);
  const stat = await fs.stat(inputPath);
  if (!stat.isFile() || stat.size > 5_000_000) throw new Error("Protocol observations must be JSON no larger than 5 MB");
  const observations = JSON.parse(await fs.readFile(inputPath, "utf8")) as ProtocolObservations;
  const run = await runAnalysisPlan({ target: { type: "local_project", path: projectPath, framework: "unknown", trusted: false }, engines: ["native"], budget: DEFAULT_ANALYSIS_BUDGET });
  if (!run.protocol) throw new Error("Protocol model was not produced");
  const seedArg = args.find(arg => arg.startsWith("--seed="));
  const parsedSeed = Number(seedArg?.split("=")[1] ?? 1);
  const seed = Number.isSafeInteger(parsedSeed) ? parsedSeed : 1;
  const results = runProtocolScenarios(run.protocol, observations, seed);
  console.log(JSON.stringify({ protocol: run.protocol, results }, null, 2));
  return results.some(item => item.finding) ? 3 : 0;
}

async function cliReplayFork(args: string[]) {
  const targetArg = args.find(arg => !arg.startsWith("--"));
  if (!targetArg || !args.includes("--confirm-fork")) throw new Error("Usage: risk-radar replay-fork <spec.json> --confirm-fork");
  const inputPath = path.resolve(targetArg);
  const stat = await fs.stat(inputPath);
  if (!stat.isFile() || stat.size > 2_000_000) throw new Error("Fork replay spec must be JSON no larger than 2 MB");
  const capability = (await detectAnalysisCapabilities(new Set(["anvil"]))).find(item => item.id === "anvil");
  if (!capability?.available) throw new Error("Anvil is not installed; fork replay is optional and was not run");
  const finding = await replayOnPinnedAnvil(JSON.parse(await fs.readFile(inputPath, "utf8")) as ForkReplaySpec);
  console.log(JSON.stringify({ reproduced: Boolean(finding), finding }, null, 2));
  return finding ? 3 : 0;
}

async function runDesktopCli() {
  const args = cliArgs();
  const command = (args.shift() || "help").toLowerCase();
  try {
    switch (command) {
      case "help": case "--help": case "-h": printCliHelp(); return 0;
      case "version": case "--version": case "-v": console.log(app.getVersion()); return 0;
      case "scan": await cliScan(args); return 0;
      case "status": {
        await cliConfigShow();
        console.log("\nCLI installation:");
        console.log(JSON.stringify(await cliInstallStatus(), null, 2));
        return 0;
      }
      case "test-connections": {
        const result = await testConnections();
        console.log(`TinyFish: ${result.tinyfish.ok ? "CONNECTED" : "FAILED"} · ${result.tinyfish.message}`);
        console.log(`Etherscan: ${result.etherscan.ok === null ? "NOT CONFIGURED" : result.etherscan.ok ? "CONNECTED" : "FAILED"} · ${result.etherscan.message}`);
        return result.tinyfish.ok && (result.etherscan.ok === null || result.etherscan.ok) ? 0 : 2;
      }
      case "config": {
        const sub = (args.shift() || "show").toLowerCase();
        if (sub === "show") { await cliConfigShow(); return 0; }
        if (sub === "set") { await cliConfigSet(args); return 0; }
        if (sub === "remove" && args[0] === "etherscan-key") {
          await saveSettings({ clearEtherscanApiKey: true });
          console.log("Etherscan API key removed.");
          return 0;
        }
        throw new Error("Usage: risk-radar config show | config set <key> <value> | config remove etherscan-key");
      }
      case "reports": await cliReports(); return 0;
      case "open-reports": {
        const cfg = await runtimeConfig();
        await fs.mkdir(cfg.preferences.outputDir, { recursive: true });
        const error = await shell.openPath(cfg.preferences.outputDir);
        if (error) throw new Error(error);
        return 0;
      }
      case "install-cli": console.log(JSON.stringify(await installCliCommand(), null, 2)); return 0;
      case "uninstall-cli": console.log(JSON.stringify(await uninstallCliCommand(), null, 2)); return 0;
      case "doctor": return await cliDoctor();
      case "capabilities": console.log(JSON.stringify(await detectAnalysisCapabilities(), null, 2)); return 0;
      case "analyze-project": await cliAnalyzeProject(args); return 0;
      case "economic-scenarios": console.log(JSON.stringify(ECONOMIC_SCENARIO_PACKS, null, 2)); return 0;
      case "simulate-economic": return await cliSimulateEconomic(args);
      case "simulate-protocol": return await cliSimulateProtocol(args);
      case "replay-fork": return await cliReplayFork(args);
      default: throw new Error(`Unknown command: ${command}. Run risk-radar help.`);
    }
  } catch (error) {
    console.error(`risk-radar: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

function registerIpc() {
  ipcMain.handle("app:get-info", () => appInfo());
  ipcMain.handle("settings:get", () => getPublicSettings());
  ipcMain.handle("settings:save", (_event: unknown, payload: SaveSettingsPayload) =>
    saveSettings(payload ?? {})
  );
  ipcMain.handle("settings:choose-output", async () => {
    const response = await dialog.showOpenDialog(mainWindow!, {
      properties: ["openDirectory", "createDirectory"],
      title: "Choose report output folder"
    });
    return response.canceled ? null : response.filePaths[0] ?? null;
  });
  ipcMain.handle("connections:test", () => testConnections());
  ipcMain.handle("analysis:capabilities", () => detectAnalysisCapabilities());
  ipcMain.handle("analysis:choose-project", () => chooseAnalysisPath("directory"));
  ipcMain.handle("analysis:choose-json", () => chooseAnalysisPath("json"));
  ipcMain.handle("analysis:run-project", async (_event: unknown, request: { projectPath?: string; engines?: AnalysisEngineId[]; trusted?: boolean; timeoutSeconds?: number; seed?: number }) => {
    const projectPath = requireAuthorizedAnalysisPath(request?.projectPath, "directory");
    const externalRequested = Array.isArray(request?.engines) && request.engines.some(engine => engine !== "native");
    if (externalRequested) {
      if (request.trusted !== true) throw new Error("External analyzers require explicit project trust");
      const confirmation = await dialog.showMessageBox(mainWindow!, { type: "warning", buttons: ["Cancel", "Run trusted tools"], defaultId: 0, cancelId: 0, noLink: true, title: "Run project-controlled tools?", message: "External analyzers may invoke compiler or test hooks from this project.", detail: `Only continue if you trust the selected project:\n${projectPath}` });
      if (confirmation.response !== 1) throw new Error("Trusted project execution was cancelled");
    }
    return withAnalysisRun("Project analysis", signal => analyzeProjectFromDesktop({ ...request, projectPath }, signal));
  });
  ipcMain.handle("analysis:simulate-economic", (_event: unknown, request: { scenarioPath?: string; maxSteps?: number }) => {
    const scenarioPath = requireAuthorizedAnalysisPath(request?.scenarioPath, "json");
    return withAnalysisRun("Economic simulation", () => simulateEconomicFromDesktop({ ...request, scenarioPath }));
  });
  ipcMain.handle("analysis:simulate-protocol", (_event: unknown, request: { projectPath?: string; observationsPath?: string; seed?: number }) => {
    const projectPath = requireAuthorizedAnalysisPath(request?.projectPath, "directory");
    const observationsPath = requireAuthorizedAnalysisPath(request?.observationsPath, "json");
    return withAnalysisRun("Protocol simulation", signal => simulateProtocolFromDesktop({ ...request, projectPath, observationsPath }, signal));
  });
  ipcMain.handle("analysis:replay-fork", (_event: unknown, request: { specPath?: string; confirmed?: boolean }) => {
    const specPath = requireAuthorizedAnalysisPath(request?.specPath, "json");
    return withAnalysisRun("External Anvil replay", signal => replayForkFromDesktop({ ...request, specPath }, signal));
  });
  ipcMain.handle("analysis:cancel", () => {
    if (!analysisController) return { cancelled: false };
    analysisController.abort(new Error("Analysis cancelled by user"));
    return { cancelled: true };
  });
  ipcMain.handle("scan:start", (_event: unknown, request: ScanRequest) => startScan(request));
  ipcMain.handle("scan:last", () => lastScan);
  ipcMain.handle("scan:export-summary", () => exportScanSummary());
  ipcMain.handle("app:show-report", (_event: unknown, filePath: string) => {
    if (typeof filePath === "string" && filePath) shell.showItemInFolder(filePath);
  });
  ipcMain.handle("app:open-output", async () => {
    const cfg = await runtimeConfig();
    await fs.mkdir(cfg.preferences.outputDir, { recursive: true });
    return shell.openPath(cfg.preferences.outputDir);
  });
  ipcMain.handle("app:open-external", (_event: unknown, url: string) => {
    if (!isSafeExternalUrl(url)) throw new Error("Blocked unsafe URL.");
    return shell.openExternal(url);
  });
  ipcMain.handle("cli:status", () => cliInstallStatus());
  ipcMain.handle("cli:install", () => installCliCommand());
  ipcMain.handle("cli:uninstall", () => uninstallCliCommand());
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1060,
    minHeight: 720,
    backgroundColor: "#07100d",
    show: false,
    title: "Ethereum DeFi Risk Radar",
    webPreferences: {
      preload: path.join(app.getAppPath(), "desktop", "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false
    }
  });

  if (process.platform !== "darwin") mainWindow.removeMenu();
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-navigate", (event: { preventDefault(): void }) => event.preventDefault());

  const renderer = path.join(app.getAppPath(), "desktop", "renderer", "index.html");
  void mainWindow.loadFile(renderer);
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  app.setAppUserModelId("com.defiriskradar.ethereum");

  if (isCliInvocation()) {
    const exitCode = await runDesktopCli();
    await Promise.all([
      new Promise<void>(resolve => process.stdout.write("", () => resolve())),
      new Promise<void>(resolve => process.stderr.write("", () => resolve()))
    ]);
    app.exit(exitCode);
    return;
  }

  registerIpc();
  installApplicationMenu();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
}).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  app.exit(1);
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
