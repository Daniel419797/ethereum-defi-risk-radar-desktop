import { analyzeSoliditySources } from "./analysis/native/analyzer.js";
import { buildProtocolModel } from "./analysis/protocol.js";
import type { NativeAnalysisReport, ProtocolModel } from "./analysis/model.js";
import type { HistoricalAuditIntelligence } from "./auditIntelligence/model.js";
import { tryGetDefaultAuditIntelligenceEngine } from "./auditIntelligence/runtime.js";

export type SourceFindingSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH_REVIEW";

export type SourceFindingKind =
  | "legacy_solidity"
  | "tx_origin"
  | "delegatecall"
  | "selfdestruct"
  | "low_level_call"
  | "value_transfer_call"
  | "inline_assembly"
  | "privileged_access"
  | "upgradeability_pattern"
  | "initializer_pattern"
  | "reentrancy_guard_present"
  | "unchecked_block"
  | "signature_recovery"
  | "oracle_price_surface"
  | "token_accounting_surface"
  | "permit_signature_surface"
  | "cross_chain_surface"
  | "liquidation_surface"
  | "mev_slippage_surface";

export type SourceFinding = {
  kind: SourceFindingKind;
  severity: SourceFindingSeverity;
  title: string;
  description: string;
  file: string;
  line: number;
};

export type SourceInspection = {
  filesInspected: number;
  sourceBytesInspected: number;
  solidityVersionHints: string[];
  findingCount: number;
  totalFindingCount: number;
  truncatedFindingCount: number;
  findingLimit: number;
  partial: boolean;
  sourceTruncated: boolean;
  truncatedSourceCharacters: number;
  severityCounts: Record<SourceFindingSeverity, number>;
  findings: SourceFinding[];
  advancedAnalysis: NativeAnalysisReport;
  protocolModel: ProtocolModel;
  historicalIntelligence?: HistoricalAuditIntelligence;
};

type SourceFile = { name: string; content: string };
type Rule = { kind: SourceFindingKind; severity: SourceFindingSeverity; title: string; description: string; re: RegExp };

const RULES: Rule[] = [
  { kind: "tx_origin", severity: "HIGH_REVIEW", title: "tx.origin usage", description: "tx.origin appears in the verified source. Review authentication/authorization logic carefully; presence alone is not proof of a vulnerability.", re: /\btx\.origin\b/g },
  { kind: "delegatecall", severity: "HIGH_REVIEW", title: "delegatecall surface", description: "delegatecall appears in the verified source. Review trust boundaries, implementation selection, and storage-layout assumptions.", re: /\.delegatecall\s*\(|\bdelegatecall\s*\(/g },
  { kind: "selfdestruct", severity: "HIGH_REVIEW", title: "selfdestruct/suicide opcode surface", description: "A self-destruct mechanism appears in source. Review reachability and authorization in the deployment context.", re: /\bselfdestruct\s*\(|\bsuicide\s*\(/g },
  { kind: "value_transfer_call", severity: "MEDIUM", title: "Low-level ETH value transfer", description: "A low-level value-bearing call appears. Review return-value handling and state-transition ordering.", re: /\.call\s*\{[^}]*\bvalue\s*:/g },
  { kind: "low_level_call", severity: "MEDIUM", title: "Low-level call surface", description: "A low-level call appears in source. Review target control, calldata construction, and return-value handling.", re: /\.call\s*(?:\{|\()/g },
  { kind: "inline_assembly", severity: "MEDIUM", title: "Inline assembly", description: "Inline assembly appears. Review memory/storage assumptions and externally influenced values around this block.", re: /\bassembly\s*\{/g },
  { kind: "privileged_access", severity: "MEDIUM", title: "Privileged/admin access surface", description: "Owner/admin/access-control patterns appear. Review privilege scope, transferability, multisig/timelock controls, and emergency powers.", re: /\bonlyOwner\b|\bDEFAULT_ADMIN_ROLE\b|\bonlyRole\s*\(|\bowner\s*\(|\badmin\b/g },
  { kind: "upgradeability_pattern", severity: "MEDIUM", title: "Upgradeability/proxy pattern", description: "Proxy or upgradeability identifiers appear. Review upgrade authorization, initializer protection, implementation storage layout, and governance controls.", re: /\bUUPSUpgradeable\b|\bTransparentUpgradeableProxy\b|\bERC1967\b|\bupgradeTo(?:AndCall)?\b|\b_proxy\b|\bimplementation\b/g },
  { kind: "initializer_pattern", severity: "LOW", title: "Initializer-based construction", description: "Initializer patterns appear, commonly used by upgradeable contracts. Confirm initialization is protected and cannot be replayed.", re: /\binitializer\b|\breinitializer\s*\(|\b__\w+_init\s*\(/g },
  { kind: "reentrancy_guard_present", severity: "INFO", title: "Reentrancy guard indicator present", description: "ReentrancyGuard/nonReentrant appears. This is a mitigating-control indicator, not a guarantee that all external-call paths are protected.", re: /\bReentrancyGuard\b|\bnonReentrant\b/g },
  { kind: "unchecked_block", severity: "LOW", title: "Unchecked arithmetic block", description: "An unchecked block appears. Review whether arithmetic assumptions remain valid for externally controlled values.", re: /\bunchecked\s*\{/g },
  { kind: "signature_recovery", severity: "LOW", title: "Signature recovery surface", description: "ecrecover/ECDSA recovery appears. Review domain separation, nonce/replay protection, signer validation, and signature malleability handling.", re: /\becrecover\s*\(|\bECDSA\.recover\s*\(/g },
  { kind: "oracle_price_surface", severity: "LOW", title: "Price/oracle dependency surface", description: "Price-feed/oracle identifiers appear. Review freshness checks, decimal normalization, fallback behavior, and manipulation resistance.", re: /\bAggregatorV3Interface\b|\blatestRoundData\s*\(|\boracle\b|\bpriceFeed\b/g },
  { kind: "token_accounting_surface", severity: "LOW", title: "Token accounting compatibility surface", description: "Token transfer and balance-accounting identifiers appear together. Review fee-on-transfer, rebasing, false-return and actual-received-amount assumptions. This is an audit-derived review signal, not proof of an issue.", re: /\b(?:safeTransferFrom|transferFrom)\s*\(|\bbalanceOf\s*\(/g },
  { kind: "permit_signature_surface", severity: "LOW", title: "Permit/signature nonce surface", description: "Permit or typed-signature identifiers appear. Review nonce consumption, expiry, domain separation and replay behavior across chains and upgrades.", re: /\bpermit\s*\(|\bnonces?\s*\(|\bDOMAIN_SEPARATOR\b|\bEIP712\b/g },
  { kind: "cross_chain_surface", severity: "MEDIUM", title: "Cross-chain message surface", description: "Cross-domain/bridge messaging identifiers appear. Review source-chain and sender binding, nonce/replay protection, finality assumptions and failure handling.", re: /\b(?:sendMessage|processMessage|xDomainMessageSender|messageNonce|anyExecute|anyFallback|bridge)\b/g },
  { kind: "liquidation_surface", severity: "LOW", title: "Liquidation/solvency surface", description: "Liquidation or collateral-accounting identifiers appear. Review price freshness, rounding direction, close factors, bad debt and solvency invariants.", re: /\b(?:liquidat\w*|collateral|healthFactor|badDebt|solvency)\b/g },
  { kind: "mev_slippage_surface", severity: "LOW", title: "MEV/slippage execution surface", description: "Swap/slippage/deadline identifiers appear. Review user-controlled minimum output, deadline enforcement, ordering assumptions and price-manipulation resistance.", re: /\b(?:amountOutMin|minAmountOut|slippage|deadline|swap)\b/g }
];

function parseSourceFiles(raw: string): SourceFile[] {
  const source = raw.trim();
  if (!source) return [];
  const attempts = [source];
  if (source.startsWith("{{") && source.endsWith("}}")) attempts.unshift(source.slice(1, -1));
  for (const attempt of attempts) {
    if (!(attempt.startsWith("{") && attempt.endsWith("}"))) continue;
    try {
      const parsed = JSON.parse(attempt) as { sources?: Record<string, string | { content?: string }> };
      if (parsed.sources && typeof parsed.sources === "object") {
        const files = Object.entries(parsed.sources).map(([name, value]) => ({ name, content: typeof value === "string" ? value : typeof value?.content === "string" ? value.content : "" })).filter(file => file.content.trim().length > 0);
        if (files.length) return files;
      }
    } catch {
      // Etherscan also returns ordinary Solidity source; fall through.
    }
  }
  return [{ name: "Contract.sol", content: source }];
}

function lineNumberAt(content: string, index: number) {
  let lines = 1;
  for (let i = 0; i < index; i++) if (content.charCodeAt(i) === 10) lines += 1;
  return lines;
}

function solidityVersionHints(files: SourceFile[]) {
  const versions = new Set<string>();
  const pragma = /pragma\s+solidity\s+([^;]+);/g;
  for (const file of files) for (const match of file.content.matchAll(pragma)) versions.add((match[1] ?? "").trim());
  return [...versions].slice(0, 20);
}

function legacyVersionFinding(files: SourceFile[]): SourceFinding[] {
  const out: SourceFinding[] = [];
  const re = /pragma\s+solidity\s+([^;]+);/g;
  for (const file of files) {
    for (const match of file.content.matchAll(re)) {
      const spec = (match[1] ?? "").trim();
      if (/0\.[0-7]\./.test(spec)) out.push({ kind: "legacy_solidity", severity: "MEDIUM", title: "Legacy Solidity compiler range", description: "The pragma references Solidity <0.8. Review arithmetic assumptions and legacy language/compiler behavior. This is a review signal, not proof of an issue.", file: file.name, line: lineNumberAt(file.content, match.index ?? 0) });
    }
  }
  return out;
}

function historicalSuffix(item: HistoricalAuditIntelligence["findings"][number] | undefined) {
  if (!item?.analogues.length) return "";
  const matches = item.analogues
    .slice(0, 3)
    .map(match => `${match.title.slice(0, 160)} [${match.severity}, ${Math.round(match.similarity * 100)}% similar]`)
    .join("; ");
  const remediationText = item.commonRemediations[0]?.slice(0, 400);
  const remediation = remediationText ? ` Common historical remediation: ${remediationText}` : "";
  return ` Historical Audit Intelligence: category ${item.predictedCategory} (${Math.round(item.categoryConfidence * 100)}% model confidence), historical review-priority context ${item.historicalRiskScore}/100, analogues: ${matches}.${remediation} This historical context supports review only and does not prove current exploitability.`;
}

export function inspectVerifiedSource(rawSource: string, opts?: { maxBytes?: number; maxFindings?: number }): SourceInspection {
  const maxBytes = Math.max(1, opts?.maxBytes ?? 2_000_000);
  const maxFindings = Math.max(1, opts?.maxFindings ?? 80);
  const raw = rawSource.slice(0, maxBytes);
  const files = parseSourceFiles(raw);
  const findings: SourceFinding[] = [];
  let totalFindings = 0;

  const legacy = legacyVersionFinding(files);
  totalFindings += legacy.length;
  findings.push(...legacy.slice(0, maxFindings));

  for (const file of files) {
    for (const rule of RULES) {
      const re = new RegExp(rule.re.source, rule.re.flags);
      for (const match of file.content.matchAll(re)) {
        totalFindings += 1;
        if (findings.length < maxFindings) findings.push({ kind: rule.kind, severity: rule.severity, title: rule.title, description: rule.description, file: file.name, line: lineNumberAt(file.content, match.index ?? 0) });
      }
    }
  }

  const deduped = findings.filter((finding, index, all) => all.findIndex(f => f.kind === finding.kind && f.file === finding.file && f.line === finding.line) === index);
  const advancedAnalysis = analyzeSoliditySources(files);
  const historicalEngine = tryGetDefaultAuditIntelligenceEngine();
  const baseContexts = deduped.map(finding => ({ id: `source:${finding.kind}:${finding.file}:${finding.line}`, title: finding.title, description: finding.description, kind: finding.kind, severity: finding.severity, file: finding.file, line: finding.line }));
  const advancedContexts = advancedAnalysis.findings.map(finding => ({ id: `advanced:${finding.id}`, title: finding.title, description: finding.description, kind: finding.kind, severity: finding.severity, file: finding.primaryLocation?.file, line: finding.primaryLocation?.line }));
  const historicalIntelligence = historicalEngine?.analyzeFindings([...baseContexts, ...advancedContexts], { maxFindings: 32, topK: 3 });
  const historicalById = new Map(historicalIntelligence?.findings.map(item => [item.findingId, item]) ?? []);

  const annotatedFindings = deduped.map(finding => ({ ...finding, description: `${finding.description}${historicalSuffix(historicalById.get(`source:${finding.kind}:${finding.file}:${finding.line}`))}` }));
  const annotatedAdvanced: NativeAnalysisReport = {
    ...advancedAnalysis,
    findings: advancedAnalysis.findings.map(finding => ({ ...finding, description: `${finding.description}${historicalSuffix(historicalById.get(`advanced:${finding.id}`))}` }))
  };

  const severityCounts: Record<SourceFindingSeverity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH_REVIEW: 0 };
  for (const finding of annotatedFindings) severityCounts[finding.severity] += 1;

  return {
    filesInspected: files.length,
    sourceBytesInspected: raw.length,
    solidityVersionHints: solidityVersionHints(files),
    findingCount: Math.min(annotatedFindings.length, maxFindings),
    totalFindingCount: totalFindings,
    truncatedFindingCount: Math.max(0, totalFindings - Math.min(annotatedFindings.length, maxFindings)),
    findingLimit: maxFindings,
    partial: totalFindings > maxFindings || rawSource.length > maxBytes,
    sourceTruncated: rawSource.length > maxBytes,
    truncatedSourceCharacters: Math.max(0, rawSource.length - maxBytes),
    severityCounts,
    findings: annotatedFindings.slice(0, maxFindings),
    advancedAnalysis: annotatedAdvanced,
    protocolModel: buildProtocolModel(files),
    historicalIntelligence
  };
}
