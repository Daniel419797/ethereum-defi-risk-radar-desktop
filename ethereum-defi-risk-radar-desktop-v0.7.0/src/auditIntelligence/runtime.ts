import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AuditCorpusMetadata } from "./model.js";
import { AuditIntelligenceEngine } from "./engine.js";

const MAX_CORPUS_BYTES = 96 * 1024 * 1024;
let cachedPath = "";
let cachedMtimeMs = -1;
let cachedEngine: AuditIntelligenceEngine | undefined;
let cachedFailure = "";

export function defaultAuditIntelligenceDirectory() {
  return path.join(os.homedir(), ".defi-risk-radar", "audit-intelligence");
}

export function defaultAuditCorpusPath() {
  return process.env.RISK_RADAR_AUDIT_CORPUS?.trim() || path.join(defaultAuditIntelligenceDirectory(), "cleaned-audit-findings.jsonl");
}

export function defaultAuditMetadataPath(corpusPath = defaultAuditCorpusPath()) {
  return path.join(path.dirname(corpusPath), "audit-dataset-stats.json");
}

function safeMetadata(metadataPath: string): Partial<AuditCorpusMetadata> | undefined {
  try {
    const stat = fs.statSync(metadataPath);
    if (!stat.isFile() || stat.size > 1_000_000) return undefined;
    const parsed = JSON.parse(fs.readFileSync(metadataPath, "utf8")) as Partial<AuditCorpusMetadata>;
    return parsed && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export type AuditIntelligenceRuntimeStatus = {
  configured: boolean;
  available: boolean;
  corpusPath: string;
  recordCount: number;
  buildId?: string;
  generatedAt?: string;
  licenseStatus?: string;
  message: string;
};

export function tryGetDefaultAuditIntelligenceEngine(): AuditIntelligenceEngine | undefined {
  const corpusPath = defaultAuditCorpusPath();
  try {
    const stat = fs.statSync(corpusPath);
    if (!stat.isFile()) return undefined;
    if (stat.size <= 0 || stat.size > MAX_CORPUS_BYTES) {
      cachedFailure = `Audit corpus must be between 1 byte and ${MAX_CORPUS_BYTES} bytes.`;
      return undefined;
    }
    if (cachedEngine && cachedPath === corpusPath && cachedMtimeMs === stat.mtimeMs) return cachedEngine;
    const jsonl = fs.readFileSync(corpusPath, "utf8");
    const engine = AuditIntelligenceEngine.fromJsonl(jsonl, safeMetadata(defaultAuditMetadataPath(corpusPath)));
    if (engine.recordCount < 10) {
      cachedFailure = "Audit corpus contains fewer than 10 usable cleaned records.";
      return undefined;
    }
    cachedPath = corpusPath;
    cachedMtimeMs = stat.mtimeMs;
    cachedEngine = engine;
    cachedFailure = "";
    return engine;
  } catch (error) {
    cachedFailure = error instanceof Error ? error.message : String(error);
    return undefined;
  }
}

export function auditIntelligenceRuntimeStatus(): AuditIntelligenceRuntimeStatus {
  const corpusPath = defaultAuditCorpusPath();
  const engine = tryGetDefaultAuditIntelligenceEngine();
  return engine
    ? {
        configured: true,
        available: true,
        corpusPath,
        recordCount: engine.recordCount,
        buildId: engine.metadata.buildId,
        generatedAt: engine.metadata.generatedAt,
        licenseStatus: engine.metadata.licenseStatus,
        message: `Historical Audit Intelligence ready with ${engine.recordCount.toLocaleString()} local cleaned findings.`
      }
    : {
        configured: fs.existsSync(corpusPath),
        available: false,
        corpusPath,
        recordCount: 0,
        message: cachedFailure || `No cleaned audit corpus found. Run npm run audit:prepare or set RISK_RADAR_AUDIT_CORPUS.`
      };
}

export function resetAuditIntelligenceRuntimeCacheForTests() {
  cachedPath = "";
  cachedMtimeMs = -1;
  cachedEngine = undefined;
  cachedFailure = "";
}
