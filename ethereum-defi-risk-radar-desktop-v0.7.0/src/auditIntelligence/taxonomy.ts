import crypto from "node:crypto";
import type { AuditCategory, AuditSeverity, CleanAuditRecord } from "./model.js";

const PLACEHOLDERS = new Set([
  "", "n/a", "na", "none", "no data", "no recommendation",
  "no poc", "not provided", "not available", "unknown", "-"
]);

const CATEGORY_RULES: Array<{ category: AuditCategory; patterns: RegExp[]; tags: string[] }> = [
  { category: "reentrancy", patterns: [/re-?entr/i, /checks[- ]effects[- ]interactions/i, /external call.*state/i, /state.*external call/i], tags: ["reentrancy", "external-call-ordering"] },
  { category: "access_control", patterns: [/access control/i, /authorization/i, /onlyowner/i, /privileg/i, /admin(?:istrator)?\b/i, /missing.*modifier/i, /unauthori[sz]ed/i], tags: ["authorization", "privilege"] },
  { category: "oracle_price", patterns: [/oracle/i, /price feed/i, /latestRoundData/i, /stale price/i, /price manipulation/i, /twap/i, /spot price/i], tags: ["oracle", "price"] },
  { category: "accounting_state", patterns: [/accounting/i, /book[- ]?keep/i, /balance mismatch/i, /share inflation/i, /donation attack/i, /incorrect balance/i, /stale.*(?:balance|earning|state)/i, /state inconsist/i], tags: ["accounting", "state"] },
  { category: "precision_rounding", patterns: [/rounding/i, /precision/i, /decimal/i, /division/i, /truncate/i, /overflow/i, /underflow/i], tags: ["arithmetic", "precision"] },
  { category: "token_integration", patterns: [/fee[- ]on[- ]transfer/i, /deflationary token/i, /non[- ]?standard.*erc[- ]?20/i, /non[- ]?erc20/i, /transferfrom/i, /safeTransfer/i, /rebasing token/i, /erc[- ]?777/i], tags: ["token", "erc20"] },
  { category: "signature_replay", patterns: [/signature/i, /ecrecover/i, /eip[- ]?712/i, /permit\b/i, /nonce/i, /replay attack/i], tags: ["signature", "replay"] },
  { category: "upgradeability", patterns: [/upgrade/i, /proxy/i, /delegatecall/i, /initializer/i, /storage collision/i, /implementation/i], tags: ["proxy", "upgrade"] },
  { category: "denial_of_service", patterns: [/denial of service/i, /\bdos\b/i, /grief/i, /unbounded loop/i, /block gas/i, /transaction.*revert/i, /funds stuck/i], tags: ["dos", "availability"] },
  { category: "mev_front_running", patterns: [/front[- ]?run/i, /sandwich/i, /\bmev\b/i, /slippage/i, /deadline/i, /transaction ordering/i], tags: ["mev", "ordering"] },
  { category: "governance", patterns: [/governance/i, /quorum/i, /proposal/i, /timelock/i, /voting/i, /governance capture/i], tags: ["governance"] },
  { category: "bridge_cross_chain", patterns: [/cross[- ]chain/i, /bridge/i, /cross[- ]domain/i, /message replay/i, /anycall/i, /source chain/i, /destination chain/i], tags: ["bridge", "cross-chain"] },
  { category: "liquidation", patterns: [/liquidat/i, /collateral/i, /health factor/i, /bad debt/i, /insolven/i], tags: ["liquidation", "solvency"] },
  { category: "flash_liquidity", patterns: [/flash loan/i, /flashloan/i, /flash liquidity/i, /atomic liquidity/i], tags: ["flash-loan", "atomic"] },
  { category: "input_validation", patterns: [/input validation/i, /argument validation/i, /missing validation/i, /invalid.*(?:parameter|argument|address|index)/i, /zero address/i, /bounds check/i], tags: ["validation"] },
  { category: "gas_economic", patterns: [/gas optimization/i, /gas cost/i, /gas reserve/i, /gas grief/i, /execution fee/i, /fee calculation/i, /fee mismatch/i], tags: ["gas", "economic"] },
  { category: "business_logic", patterns: [/business logic/i, /incorrect logic/i, /logic error/i, /incorrect calculation/i, /wrong calculation/i, /unexpected behavior/i], tags: ["logic"] }
];

export function normalizeWhitespace(value: unknown) {
  return String(value ?? "").replace(/\u0000/g, "").replace(/\r\n?/g, "\n").replace(/[\t\f\v]+/g, " ").replace(/ {2,}/g, " ").trim();
}

export function isPlaceholder(value: unknown) {
  const normalized = normalizeWhitespace(value).toLowerCase().replace(/[.!]+$/g, "").trim();
  return PLACEHOLDERS.has(normalized) || /^no\s+(?:poc|proof of concept|recommendation|data)\b/i.test(normalized);
}

export function cleanAuditTitle(value: unknown) {
  return normalizeWhitespace(value)
    .replace(/\s+Submitted by\s+.+$/i, "")
    .replace(/\s+Reported by\s+.+$/i, "")
    .replace(/\s+also found by\s+.+$/i, "")
    .replace(/(?:^\s*[`*_#]+)|(?:[`*_#]+\s*$)/g, "")
    .trim()
    .slice(0, 400);
}

export function normalizeSeverity(value: unknown, raw?: unknown): AuditSeverity {
  const text = `${normalizeWhitespace(value)} ${normalizeWhitespace(raw)}`.toLowerCase();
  if (/critical|\bcrit\b/.test(text)) return "CRITICAL";
  if (/\bhigh\b|high risk/.test(text)) return "HIGH";
  if (/\bmedium\b|medium risk|moderate/.test(text)) return "MEDIUM";
  if (/\blow\b|low risk/.test(text)) return "LOW";
  if (/informational|\binfo\b/.test(text)) return "INFORMATIONAL";
  if (/gas optimization|gas optimisation/.test(text)) return "GAS";
  if (/^(?:\s*)$|unknown|undetermined|commit\s+location/.test(text)) return "UNKNOWN";
  if (/other/.test(text)) return "OTHER";
  return "UNKNOWN";
}

export function classifyAuditText(...parts: unknown[]): { category: AuditCategory; tags: string[] } {
  const text = parts.map(normalizeWhitespace).filter(Boolean).join("\n");
  const scores = new Map<AuditCategory, number>();
  const tags = new Set<string>();
  for (const rule of CATEGORY_RULES) {
    let score = 0;
    for (const pattern of rule.patterns) if (pattern.test(text)) score += 1;
    if (score > 0) {
      scores.set(rule.category, score);
      for (const tag of rule.tags) tags.add(tag);
    }
  }
  const ranked = [...scores.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return { category: ranked[0]?.[0] ?? "other", tags: [...tags].slice(0, 12) };
}

export function computeQualityScore(opts: { title: string; description: string; recommendation?: string; hasPoc: boolean; severity: AuditSeverity }) {
  const desc = Math.min(opts.description.length / 2_000, 1);
  const rec = Math.min((opts.recommendation?.length ?? 0) / 1_000, 1);
  const title = Math.min(opts.title.length / 120, 1);
  const poc = opts.hasPoc ? 0.15 : 0;
  const severityBonus = opts.severity === "CRITICAL" || opts.severity === "HIGH" ? 0.1 : opts.severity === "MEDIUM" ? 0.05 : 0;
  return Math.max(0, Math.min(1, Number((0.55 * desc + 0.2 * rec + 0.1 * title + poc + severityBonus).toFixed(6))));
}

export function stableRecordHash(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function deterministicSplit(sourceHash: string): "train" | "benchmark" {
  const bucket = Number.parseInt(sourceHash.slice(0, 8), 16) % 5;
  return bucket === 0 ? "benchmark" : "train";
}

export function cleanAuditRecord(raw: Record<string, unknown>): CleanAuditRecord | undefined {
  const title = cleanAuditTitle(raw.bug_title ?? raw.title);
  const description = normalizeWhitespace(raw.bug_desc ?? raw.description).slice(0, 12_000);
  if (title.length < 3 || description.length < 30) return undefined;
  const recommendationRaw = normalizeWhitespace(raw.bug_rec ?? raw.recommendation);
  const recommendation = isPlaceholder(recommendationRaw) ? undefined : recommendationRaw.slice(0, 6_000);
  const pocRaw = normalizeWhitespace(raw.bug_poc ?? raw.poc);
  const hasPoc = !isPlaceholder(pocRaw) && pocRaw.length >= 40;
  const severityRaw = normalizeWhitespace(raw.bug_sev_raw ?? raw.severity_raw).slice(0, 250);
  const severity = normalizeSeverity(raw.bug_sev ?? raw.severity, severityRaw);
  const taxonomy = classifyAuditText(title, description, recommendation);
  const sourceHash = stableRecordHash(`${title.toLowerCase()}\n${description.toLowerCase()}`);
  const sourceWeightValue = Number(raw.bug_weight ?? raw.sourceWeight);
  const sourceWeight = Number.isFinite(sourceWeightValue) ? Math.max(0, Math.min(1, sourceWeightValue)) : undefined;
  return {
    id: String(raw.id ?? sourceHash.slice(0, 16)),
    sourceHash,
    title,
    description,
    recommendation,
    severity,
    severityRaw: severityRaw || undefined,
    category: taxonomy.category,
    tags: taxonomy.tags,
    qualityScore: computeQualityScore({ title, description, recommendation, hasPoc, severity }),
    sourceWeight,
    hasPoc,
    split: deterministicSplit(sourceHash)
  };
}
