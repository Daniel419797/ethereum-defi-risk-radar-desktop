import path from "node:path";
import type { AnalysisBudget, AnalysisEngineId, AnalysisFinding, EngineRunResult } from "../model.js";
import { runBoundedProcess } from "../processRunner.js";
import { finalizeFinding } from "../evidence.js";

type AdapterDefinition = {
  engine: Exclude<AnalysisEngineId, "native" | "anvil">;
  executable: string;
  argumentsFor: (target: string, budget: AnalysisBudget) => string[];
};

const DEFINITIONS: Record<"slither" | "mythril" | "foundry" | "echidna", AdapterDefinition> = {
  slither: { engine: "slither", executable: "slither", argumentsFor: target => [target, "--json", "-", "--disable-color"] },
  mythril: { engine: "mythril", executable: "myth", argumentsFor: (target, budget) => ["analyze", target, "-o", "json", "--execution-timeout", String(Math.max(1, Math.floor(budget.timeoutMs / 1_000)))] },
  foundry: { engine: "foundry", executable: "forge", argumentsFor: () => ["test", "--json"] },
  echidna: { engine: "echidna", executable: "echidna", argumentsFor: (target, budget) => [target, "--format", "json", "--timeout", String(Math.max(1, Math.floor(budget.timeoutMs / 1_000))), "--seed", String(budget.seed ?? 1)] }
};

function severity(value: unknown): AnalysisFinding["severity"] {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized.includes("critical")) return "CRITICAL";
  if (normalized.includes("high")) return "HIGH";
  if (normalized.includes("medium")) return "MEDIUM";
  if (normalized.includes("low")) return "LOW";
  return "INFO";
}

function jsonPayload(stdout: string): unknown {
  try { return JSON.parse(stdout); } catch {
    const rows = stdout.split(/\r?\n/).filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
    return rows.length ? { tests: rows } : undefined;
  }
}

function candidateRows(payload: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(payload)) return payload.filter(item => item && typeof item === "object") as Array<Record<string, unknown>>;
  if (!payload || typeof payload !== "object") return [];
  const root = payload as Record<string, unknown>;
  return ([root.results, root.issues, root.tests, (root.results as Record<string, unknown> | undefined)?.detectors]
    .find(Array.isArray) ?? []) as Array<Record<string, unknown>>;
}

function sequenceFor(item: Record<string, unknown>): string[] {
  const raw = item.transactions ?? item.callSequence ?? item.counterexample ?? item.sequence;
  if (!Array.isArray(raw)) return [];
  return raw.slice(0, 1_000).map(value => typeof value === "string" ? value.slice(0, 2_000) : JSON.stringify(value).slice(0, 2_000));
}

function violationFor(engine: AdapterDefinition["engine"], item: Record<string, unknown>) {
  const status = String(item.status ?? item.result ?? "").toLowerCase();
  const failed = item.success === false || item.passed === false || ["failed", "falsified", "broken"].some(value => status.includes(value));
  const mythrilIssue = engine === "mythril" && Boolean(item.swcID ?? item.title) && Boolean(item.error ?? item.description);
  if (!failed && !mythrilIssue) return "";
  return String(item.violation ?? item.error ?? item.message ?? item.description ?? item.name ?? item.title ?? "Property was falsified");
}

export function normalizeExternalFindings(engine: AdapterDefinition["engine"], stdout: string, maxFindings: number, seed = 1, executionTrusted = false) {
  const payload = jsonPayload(stdout); const rows = candidateRows(payload); const selected = rows.slice(0, maxFindings);
  const findings = selected.map((item, index) => {
    const sequence = sequenceFor(item); const violation = violationFor(engine, item); const hasCounterexample = executionTrusted && sequence.length > 0 && Boolean(violation);
    const evidenceStrength = engine === "slither" ? "STRUCTURAL" as const : hasCounterexample ? "EXECUTED" as const : "STRUCTURAL" as const;
    return finalizeFinding({
    id: `${engine}:${String(item.check ?? item.swcID ?? item.name ?? index)}`,
    kind: engine === "mythril" ? "symbolic_execution" : engine === "foundry" ? "invariant_testing" : engine === "echidna" ? "fuzzing" : "data_flow",
    engine,
    severity: severity(item.impact ?? item.severity),
    confidence: engine === "slither" ? "MEDIUM" : hasCounterexample ? "HIGH" : "MEDIUM",
    evidenceStrength,
    title: String(item.check ?? item.title ?? item.name ?? `${engine} result`),
    description: String(item.description ?? item.message ?? item.error ?? "Analyzer reported a review result."),
    evidencePath: sequence.length ? sequence : undefined,
    counterexample: hasCounterexample ? { engine, scope: "model", sequence, observedViolation: violation, invariantId: String(item.name ?? item.check ?? "property"), seed } : undefined,
    limitations: hasCounterexample ? [`Counterexample captured from ${engine}; independent replay is required for REPRODUCED.`] : [`${engine} emitted a result without a replayable counterexample; execution evidence was not granted.`]
  });
  });
  return { findings, total: rows.length, parsed: payload !== undefined };
}

export async function runExternalAdapter(opts: {
  engine: keyof typeof DEFINITIONS;
  targetPath: string;
  budget: AnalysisBudget;
  signal?: AbortSignal;
}): Promise<EngineRunResult> {
  if (!path.isAbsolute(opts.targetPath)) throw new Error("External analyzer target must be absolute");
  const definition = DEFINITIONS[opts.engine];
  const startedAt = new Date().toISOString();
  const started = Date.now();
  try {
    const processResult = await runBoundedProcess({
      executable: definition.executable,
      args: definition.argumentsFor(opts.targetPath, opts.budget),
      cwd: opts.engine === "foundry" ? opts.targetPath : path.dirname(opts.targetPath),
      timeoutMs: opts.budget.timeoutMs,
      maxOutputBytes: opts.budget.maxOutputBytes,
      signal: opts.signal
    });
    const outputIntegrity = processResult.state === "complete" && !processResult.truncated && [0, 1].includes(processResult.exitCode ?? -1);
    const preliminary = normalizeExternalFindings(definition.engine, processResult.stdout, opts.budget.maxFindings, opts.budget.seed, false);
    const outputUnparsed = Boolean(processResult.stdout.trim()) && !preliminary.parsed;
    const normalized = normalizeExternalFindings(definition.engine, processResult.stdout, opts.budget.maxFindings, opts.budget.seed, outputIntegrity && !outputUnparsed);
    return {
      engine: definition.engine,
      state: processResult.state,
      startedAt,
      finishedAt: new Date().toISOString(),
      durationMs: processResult.durationMs,
      findings: normalized.findings,
      diagnostics: processResult.stderr ? [processResult.stderr.slice(0, 2_000)] : [],
      exitCode: processResult.exitCode,
      truncated: processResult.truncated || normalized.total > opts.budget.maxFindings,
      outputUnparsed,
      truncations: normalized.total > opts.budget.maxFindings ? [{ ruleId: `${definition.engine}:normalized-results`, dropped: normalized.total - opts.budget.maxFindings, limit: opts.budget.maxFindings }] : []
    };
  } catch (error) {
    return {
      engine: definition.engine,
      state: "unavailable",
      startedAt,
      finishedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      findings: [],
      diagnostics: [error instanceof Error ? error.message : "Analyzer failed to start"],
      truncated: false
    };
  }
}
