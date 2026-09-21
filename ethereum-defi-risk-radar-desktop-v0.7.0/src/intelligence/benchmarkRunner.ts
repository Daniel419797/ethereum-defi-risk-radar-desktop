import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { inspectVerifiedSource } from "../sourceAnalyzer.js";
import type { BenchmarkCase, BenchmarkPrediction } from "./model.js";

const execFileAsync = promisify(execFile);

function safeCorpusPath(root: string, relative: string) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(root, relative);
  if (resolved !== resolvedRoot && !resolved.startsWith(resolvedRoot + path.sep)) {
    throw new Error("Benchmark case path escaped corpus root.");
  }
  return resolved;
}

function findingCategory(kind: string) {
  if (kind === "authorization") return "access_control";
  if (kind === "arithmetic_precision") return "arithmetic";
  return kind;
}

export async function runSourceBenchmark(opts: {
  root: string;
  cases: BenchmarkCase[];
  maxCases?: number;
  maxSourceBytes?: number;
  maxFindings?: number;
}): Promise<BenchmarkPrediction[]> {
  const limit = Math.max(1, Math.min(opts.maxCases ?? opts.cases.length, 10_000));
  const predictions: BenchmarkPrediction[] = [];

  for (const item of opts.cases.slice(0, limit)) {
    const started = Date.now();
    const sourcePath = safeCorpusPath(opts.root, item.sourcePath);
    const stat = await fs.stat(sourcePath);
    if (!stat.isFile()) throw new Error("Benchmark source is not a file: " + item.sourcePath);
    const maxBytes = Math.max(10_000, Math.min(opts.maxSourceBytes ?? 5_000_000, 20_000_000));
    if (stat.size > maxBytes) throw new Error("Benchmark source exceeds byte budget: " + item.sourcePath);
    const source = await fs.readFile(sourcePath, "utf8");
    const inspection = inspectVerifiedSource(source, {
      maxBytes,
      maxFindings: Math.max(1, Math.min(opts.maxFindings ?? 500, 2_000))
    });
    predictions.push({
      caseId: item.id,
      durationMs: Date.now() - started,
      findings: inspection.advancedAnalysis.findings.map(finding => ({
        category: findingCategory(finding.kind),
        line: finding.primaryLocation?.line,
        severity: finding.severity,
        evidenceStrength: finding.evidenceStrength,
        reproduced:
          finding.evidenceStrength === "REPRODUCED" &&
          (finding.evidenceScope === "model" || finding.evidenceScope === "fork")
      }))
    });
  }

  return predictions;
}

export async function runDefiHackLabsReproductionBenchmark(opts: {
  root: string;
  cases: BenchmarkCase[];
  maxCases?: number;
  timeoutMs?: number;
  trusted: boolean;
  forgeExecutable?: string;
}): Promise<BenchmarkPrediction[]> {
  if (!opts.trusted) {
    throw new Error(
      "DeFiHackLabs reproduction executes third-party Foundry tests. Explicit trusted=true confirmation is required."
    );
  }

  const limit = Math.max(1, Math.min(opts.maxCases ?? opts.cases.length, 500));
  const timeout = Math.max(5_000, Math.min(opts.timeoutMs ?? 180_000, 900_000));
  const forge = opts.forgeExecutable || "forge";
  const predictions: BenchmarkPrediction[] = [];

  for (const item of opts.cases.slice(0, limit)) {
    const sourcePath = safeCorpusPath(opts.root, item.sourcePath);
    const started = Date.now();
    let reproduced = false;
    try {
      await execFileAsync(
        forge,
        ["test", "--contracts", sourcePath, "-q"],
        {
          cwd: path.resolve(opts.root),
          timeout,
          maxBuffer: 10_000_000,
          env: { ...process.env, FOUNDRY_COLOR: "never" }
        }
      );
      reproduced = true;
    } catch {
      reproduced = false;
    }

    predictions.push({
      caseId: item.id,
      durationMs: Date.now() - started,
      findings: reproduced
        ? [
            {
              category: "historical_exploit",
              evidenceStrength: "REPRODUCED",
              reproduced: true
            }
          ]
        : []
    });
  }

  return predictions;
}
