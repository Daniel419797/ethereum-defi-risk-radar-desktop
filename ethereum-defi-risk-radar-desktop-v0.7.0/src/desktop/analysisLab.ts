import fs from "node:fs/promises";
import path from "node:path";
import { detectAnalysisCapabilities } from "../analysis/capabilities.js";
import { simulateEconomicScenario, type EconomicAction, type EconomicState } from "../analysis/economic/simulator.js";
import { DEFAULT_ANALYSIS_BUDGET, type AnalysisEngineId } from "../analysis/model.js";
import { runAnalysisPlan } from "../analysis/orchestrator.js";
import { runProtocolScenarios, type ProtocolObservations } from "../analysis/protocol.js";
import { replayOnPinnedAnvil, type ForkReplaySpec } from "../analysis/reproduction.js";

const EXTERNAL_ENGINES = new Set<AnalysisEngineId>(["slither", "mythril", "foundry", "echidna"]);
const DESKTOP_ENGINES = new Set<AnalysisEngineId>(["native", ...EXTERNAL_ENGINES]);

async function assertDirectory(targetPath: string) {
  if (!path.isAbsolute(targetPath)) throw new Error("Project path must be absolute");
  const stat = await fs.stat(targetPath);
  if (!stat.isDirectory()) throw new Error("Analysis target must be a project directory");
}

async function readJson<T>(inputPath: string, maxBytes: number, label: string): Promise<T> {
  if (!path.isAbsolute(inputPath) || path.extname(inputPath).toLowerCase() !== ".json") throw new Error(`${label} must be an absolute JSON file path`);
  const stat = await fs.stat(inputPath);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error(`${label} must be no larger than ${Math.floor(maxBytes / 1_000_000)} MB`);
  try { return JSON.parse(await fs.readFile(inputPath, "utf8")) as T; }
  catch { throw new Error(`${label} is not valid JSON`); }
}

async function frameworkFor(projectPath: string): Promise<"foundry" | "hardhat" | "unknown"> {
  if (await fs.access(path.join(projectPath, "foundry.toml")).then(() => true).catch(() => false)) return "foundry";
  const hardhatNames = ["hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs"];
  return (await Promise.all(hardhatNames.map(name => fs.access(path.join(projectPath, name)).then(() => true).catch(() => false)))).some(Boolean) ? "hardhat" : "unknown";
}

export async function analyzeProjectFromDesktop(request: { projectPath: string; engines?: AnalysisEngineId[]; trusted?: boolean; timeoutSeconds?: number; seed?: number }, signal?: AbortSignal) {
  await assertDirectory(request.projectPath);
  const engines = [...new Set(["native" as AnalysisEngineId, ...(request.engines ?? [])])].filter(engine => engine !== "anvil");
  if (engines.some(engine => !DESKTOP_ENGINES.has(engine))) throw new Error("Analysis request contains an unsupported engine");
  if (engines.some(engine => EXTERNAL_ENGINES.has(engine)) && request.trusted !== true) throw new Error("External analyzers require explicit project trust because compiler and test hooks can execute project code");
  const timeoutSeconds = Math.max(1, Math.min(Math.trunc(Number(request.timeoutSeconds) || 120), 3_600));
  const seed = Number.isSafeInteger(request.seed) ? request.seed : 1;
  return runAnalysisPlan({ target: { type: "local_project", path: request.projectPath, framework: await frameworkFor(request.projectPath), trusted: request.trusted === true }, engines, budget: { ...DEFAULT_ANALYSIS_BUDGET, timeoutMs: timeoutSeconds * 1_000, seed }, signal }, signal);
}

export async function simulateEconomicFromDesktop(request: { scenarioPath: string; maxSteps?: number }) {
  const input = await readJson<{ initial?: EconomicState; actions?: EconomicAction[] }>(request.scenarioPath, 5_000_000, "Economic scenario");
  if (!input.initial || !Array.isArray(input.actions)) throw new Error("Economic scenario requires initial and actions");
  const maxSteps = Math.max(1, Math.min(Math.trunc(Number(request.maxSteps) || 10_000), 100_000));
  return simulateEconomicScenario(input.initial, input.actions, maxSteps);
}

export async function simulateProtocolFromDesktop(request: { projectPath: string; observationsPath: string; seed?: number }, signal?: AbortSignal) {
  await assertDirectory(request.projectPath);
  const observations = await readJson<ProtocolObservations>(request.observationsPath, 5_000_000, "Protocol observations");
  const run = await runAnalysisPlan({ target: { type: "local_project", path: request.projectPath, framework: await frameworkFor(request.projectPath), trusted: false }, engines: ["native"], budget: DEFAULT_ANALYSIS_BUDGET, signal }, signal);
  if (!run.protocol) throw new Error("Protocol model was not produced");
  const seed = Number.isSafeInteger(request.seed) ? request.seed! : 1;
  return { protocol: run.protocol, results: runProtocolScenarios(run.protocol, observations, seed) };
}

export async function replayForkFromDesktop(request: { specPath: string; confirmed?: boolean }, signal?: AbortSignal) {
  if (request.confirmed !== true) throw new Error("Fork replay requires explicit confirmation");
  const capability = (await detectAnalysisCapabilities(new Set(["anvil"]))).find(item => item.id === "anvil");
  if (!capability?.available) throw new Error("Anvil is not installed; replay was not run");
  const spec = await readJson<ForkReplaySpec>(request.specPath, 2_000_000, "Fork replay specification");
  const finding = await replayOnPinnedAnvil(spec, { signal });
  return { observedViolation: Boolean(finding), finding, capability };
}
