import { detectAnalysisCapabilities } from "./capabilities.js";
import { runExternalAdapter } from "./adapters/external.js";
import { analyzeSoliditySources } from "./native/analyzer.js";
import { buildProtocolModel } from "./protocol.js";
import { assertEvidenceInvariant } from "./evidence.js";
import type { AnalysisFinding, AnalysisPlan, AnalysisRunReport, EngineRunResult } from "./model.js";
import os from "node:os";

const SKIP_DIRECTORIES = new Set([".git", "node_modules", "out", "cache", "artifacts", "dist", "release"]);

async function readBoundedFile(filePath: string, maxBytes: number, signal?: AbortSignal) {
  const handle = await fs.open(filePath, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maxBytes) throw new Error(`Project Solidity source exceeds the remaining ${maxBytes} byte budget`);
    const chunks: Buffer[] = [];
    let total = 0;
    while (true) {
      if (signal?.aborted) throw new Error("Project source analysis was cancelled");
      const chunk = Buffer.alloc(Math.min(64 * 1024, maxBytes - total + 1));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) throw new Error(`Project Solidity source exceeds the remaining ${maxBytes} byte budget`);
      chunks.push(chunk.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, total).toString("utf8");
  } finally {
    await handle.close();
  }
}

async function loadProjectSources(rootPath: string, maxBytes: number, maxPaths: number, signal?: AbortSignal) {
  const root = await fs.realpath(rootPath);
  const sources: Array<{ name: string; content: string }> = [];
  let bytes = 0;
  let entriesVisited = 0;
  async function visit(directory: string, depth: number) {
    if (signal?.aborted) throw new Error("Project source analysis was cancelled");
    if (depth > 64) throw new Error("Project directory depth exceeds the safety limit");
    const directoryHandle = await fs.opendir(directory);
    for await (const entry of directoryHandle) {
      entriesVisited += 1;
      if (entriesVisited > Math.max(maxPaths * 4, 1_000)) throw new Error("Project entry count exceeds the safety limit");
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory() && SKIP_DIRECTORIES.has(entry.name)) continue;
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) { await visit(target, depth + 1); continue; }
      if (!entry.isFile() || !entry.name.endsWith(".sol")) continue;
      if (sources.length >= maxPaths) throw new Error(`Project Solidity file count exceeds ${maxPaths}`);
      const content = await readBoundedFile(target, maxBytes - bytes, signal);
      bytes += Buffer.byteLength(content);
      if (bytes > maxBytes) throw new Error(`Project Solidity source exceeds ${maxBytes} bytes`);
      sources.push({ name: path.relative(root, target).replaceAll("\\", "/"), content });
    }
  }
  await visit(root, 0);
  return sources;
}

function deduplicate(findings: AnalysisFinding[]) {
  const seen = new Set<string>();
  return findings.filter(finding => {
    const key = `${finding.engine}:${finding.id}:${finding.primaryLocation?.file ?? ""}:${finding.primaryLocation?.line ?? 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function runAnalysisPlan(plan: AnalysisPlan, signal?: AbortSignal): Promise<AnalysisRunReport> {
  const requestedExternal = plan.engines.filter(engine => engine !== "native" && engine !== "anvil");
  const externalEngines = plan.target.type === "verified_source"
    ? requestedExternal.filter(engine => engine === "slither" || engine === "mythril")
    : requestedExternal;
  if (plan.target.type === "local_project" && externalEngines.length > 0 && !plan.target.trusted) {
    throw new Error("External project analysis requires explicit trusted=true confirmation");
  }
  const capabilities = externalEngines.length > 0
    ? await detectAnalysisCapabilities(new Set(externalEngines))
    : [];
  const engines: EngineRunResult[] = [];
  const sources = plan.target.type === "verified_source"
    ? plan.target.sources
    : await loadProjectSources(plan.target.path, Math.min(plan.budget.maxOutputBytes, 20_000_000), plan.budget.maxPaths, signal);
  const native = plan.engines.includes("native")
    ? analyzeSoliditySources(sources)
    : undefined;

  if (plan.target.type === "local_project") {
    for (const engine of plan.engines) {
      if (engine === "native" || engine === "anvil") continue;
      const capability = capabilities.find(item => item.id === engine);
      if (!capability?.available) {
        const now = new Date().toISOString();
        engines.push({ engine, state: "unavailable", startedAt: now, finishedAt: now, durationMs: 0, findings: [], diagnostics: [capability?.reason ?? `${engine} is not installed`], truncated: false });
        continue;
      }
      engines.push(await runExternalAdapter({ engine, targetPath: plan.target.path, budget: plan.budget, signal }));
    }
  }

  if (plan.target.type === "verified_source") {
    for (const engine of requestedExternal.filter(item => !externalEngines.includes(item))) {
      const now = new Date().toISOString(); engines.push({ engine, state: "unavailable", startedAt: now, finishedAt: now, durationMs: 0, findings: [], diagnostics: [`${engine} requires a trusted local project; verified-source mode supports only Slither and Mythril.`], unavailableReason: "project-only engine", truncated: false });
    }
    if (externalEngines.length && !plan.target.trustedForExecution) {
      for (const engine of externalEngines) {
        const now = new Date().toISOString(); engines.push({ engine, state: "unavailable", startedAt: now, finishedAt: now, durationMs: 0, findings: [], diagnostics: ["Verified-source compiler execution requires explicit trustedForExecution=true."], unavailableReason: "execution trust not confirmed", truncated: false });
      }
    } else if (externalEngines.length) {
      const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "risk-radar-verified-"));
      try {
        const written: string[] = [];
        for (const [index, source] of sources.entries()) {
          const safeName = path.basename(source.name).replace(/[^A-Za-z0-9_.-]/g, "_") || `Contract${index}.sol`;
          const target = path.join(tempRoot, safeName.endsWith(".sol") ? safeName : `${safeName}.sol`); await fs.writeFile(target, source.content, "utf8"); written.push(target);
        }
        for (const engine of externalEngines) {
          const capability = capabilities.find(item => item.id === engine);
          if (!capability?.available) { const now = new Date().toISOString(); engines.push({ engine, state: "unavailable", startedAt: now, finishedAt: now, durationMs: 0, findings: [], diagnostics: [capability?.reason ?? `${engine} is not installed`], truncated: false }); continue; }
          engines.push(await runExternalAdapter({ engine, targetPath: written[0] ?? tempRoot, budget: plan.budget, signal }));
        }
      } finally {
        const resolvedTemp = path.resolve(tempRoot); const tempPrefix = path.resolve(os.tmpdir()) + path.sep;
        if (resolvedTemp.startsWith(tempPrefix)) await fs.rm(resolvedTemp, { recursive: true, force: true });
      }
    }
  }

  const allFindings = deduplicate([...(native?.findings ?? []), ...engines.flatMap(run => run.findings)]);
  assertEvidenceInvariant(allFindings);

  return {
    targetType: plan.target.type,
    capabilities,
    native,
    engines,
    findings: allFindings,
    protocol: buildProtocolModel(sources, allFindings),
    state: native?.partial || engines.some(run => run.state !== "complete" && run.state !== "unavailable") ? "partial" : "complete",
    notes: native?.truncations?.length ? ["Native findings were capped; inspect truncation records before treating absence as meaningful."] : []
  };
}
import fs from "node:fs/promises";
import path from "node:path";
