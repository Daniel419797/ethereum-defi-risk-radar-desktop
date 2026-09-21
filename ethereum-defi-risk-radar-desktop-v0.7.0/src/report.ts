import fs from "node:fs/promises";
import path from "node:path";
import type { AnalysisSeverity, EvidenceStrength } from "./analysis/model.js";
import type { Candidate } from "./types.js";

const EVM_ADDRESS_RE = /0x[a-f0-9]{40}/gi;
const SOURCE_REVIEW_ONLY_EXCLUSIONS = new Set(["reentrancy_guard_present"]);
const LEGACY_TO_ADVANCED_KIND: Record<string, string[]> = {
  tx_origin: ["authorization"],
  delegatecall: ["upgradeability", "cross_contract_calls"],
  low_level_call: ["cross_contract_calls", "reentrancy"],
  value_transfer_call: ["cross_contract_calls", "reentrancy"],
  privileged_access: ["authorization", "governance_risk"],
  upgradeability_pattern: ["upgradeability"],
  initializer_pattern: ["upgradeability"],
  unchecked_block: ["arithmetic_precision"],
  signature_recovery: ["signature_replay"],
  oracle_price_surface: ["oracle_risk"],
  permit_signature_surface: ["signature_replay"],
  cross_chain_surface: ["bridge_messaging"],
  liquidation_surface: ["oracle_risk"],
  mev_slippage_surface: ["mev_ordering"],
  token_accounting_surface: ["token_integration"]
};

type Inspection = Candidate["ethereum"]["sourceInspections"][number];
type EvidenceKey = "REPRODUCED_FORK" | "REPRODUCED_MODEL" | "EXECUTED" | "STRUCTURAL" | "HEURISTIC";

type ExportFinding = {
  candidateId: string;
  protocolLabel: string;
  hostname: string;
  classification: Candidate["classification"];
  researchScore: number;
  ethereumConfidence: number;
  contractRefId: string;
  contractName: string;
  sourceRole: string;
  compilerVersion: string;
  proxy: boolean;
  sourceLayer: "advanced" | "source-review";
  findingId: string;
  kind: string;
  engine: string;
  severity: AnalysisSeverity;
  confidence: string;
  evidenceStrength: EvidenceStrength;
  evidenceKey: EvidenceKey;
  evidenceScope?: string;
  exploitabilityVerdict: string;
  title: string;
  description: string;
  remediation?: string;
  file: string;
  line: number;
  column: number;
  reachableFromExternalEntry?: boolean;
  mitigations: string[];
  correlatedEngines: string[];
  limitations: string[];
  witnessPath: string[];
  counterexampleSequence: string[];
  observedViolation?: string;
  seed?: number;
  blockNumber?: number;
  historicalCategory?: string;
  historicalCategoryConfidence?: number;
  historicalRiskScore?: number;
  historicalAnalogueCount: number;
  historicalTopAnalogues: string[];
};

function redactAddresses(value: string) {
  return value.replace(EVM_ADDRESS_RE, "[contract-address]");
}

function reportSafeCandidates(candidates: Candidate[]): Candidate[] {
  return JSON.parse(redactAddresses(JSON.stringify(candidates))) as Candidate[];
}

function csvEscape(value: unknown) {
  const raw = String(value ?? "");
  const str = /^[=+\-@]/.test(raw) ? `'${raw}` : raw;
  return `"${str.replaceAll('"', '""')}"`;
}

function htmlEscape(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function legacySeverity(value: string): AnalysisSeverity {
  if (value === "HIGH_REVIEW") return "HIGH";
  if (value === "MEDIUM" || value === "LOW" || value === "INFO") return value;
  return "INFO";
}

function evidenceKey(strength: EvidenceStrength, scope?: string): EvidenceKey {
  if (strength === "REPRODUCED") return scope === "fork" ? "REPRODUCED_FORK" : "REPRODUCED_MODEL";
  if (strength === "EXECUTED") return "EXECUTED";
  if (strength === "STRUCTURAL") return "STRUCTURAL";
  return "HEURISTIC";
}

function sourceFindingShadowedByAdvanced(
  finding: Inspection["inspection"]["findings"][number],
  advanced: Inspection["inspection"]["advancedAnalysis"]["findings"]
) {
  const mappedKinds = LEGACY_TO_ADVANCED_KIND[finding.kind];
  if (!mappedKinds?.length) return false;
  return advanced.some(candidate => {
    const location = candidate.primaryLocation;
    return mappedKinds.includes(candidate.kind) &&
      location?.file === finding.file &&
      Math.abs(Number(location.line || 0) - Number(finding.line || 0)) <= 2;
  });
}

function historicalFor(inspection: Inspection, findingId: string) {
  return inspection.inspection.historicalIntelligence?.findings.find(item => item.findingId === findingId);
}

function historicalFields(item: ReturnType<typeof historicalFor>) {
  return {
    historicalCategory: item?.predictedCategory,
    historicalCategoryConfidence: item?.categoryConfidence,
    historicalRiskScore: item?.historicalRiskScore,
    historicalAnalogueCount: item?.analogues.length ?? 0,
    historicalTopAnalogues: item?.analogues.slice(0, 3).map(analogue =>
      `${analogue.title} [${analogue.severity}, ${Math.round(analogue.similarity * 100)}% similar]`
    ) ?? []
  };
}

function flattenSecurityFindings(candidate: Candidate): ExportFinding[] {
  const findings: ExportFinding[] = [];

  for (const inspection of candidate.ethereum.sourceInspections) {
    const contractName = inspection.contractName || inspection.contractRefId || "Verified contract";
    const contractRefId = inspection.contractRefId || "unknown";
    const advanced = inspection.inspection.advancedAnalysis.findings;

    for (const finding of advanced) {
      const scope = finding.evidenceScope || finding.counterexample?.scope;
      findings.push({
        candidateId: candidate.id,
        protocolLabel: candidate.label,
        hostname: candidate.hostname,
        classification: candidate.classification,
        researchScore: candidate.researchScore,
        ethereumConfidence: candidate.ethereumConfidence,
        contractRefId,
        contractName,
        sourceRole: inspection.sourceRole || (inspection.proxy ? "PROXY" : "DIRECT"),
        compilerVersion: inspection.compilerVersion || "",
        proxy: Boolean(inspection.proxy),
        sourceLayer: "advanced",
        findingId: finding.id,
        kind: finding.kind,
        engine: finding.engine,
        severity: finding.severity,
        confidence: finding.confidence,
        evidenceStrength: finding.evidenceStrength,
        evidenceKey: evidenceKey(finding.evidenceStrength, scope),
        evidenceScope: scope,
        exploitabilityVerdict: finding.exploitabilityVerdict ?? "UNKNOWN",
        title: finding.title,
        description: finding.description,
        remediation: finding.remediation,
        file: finding.primaryLocation?.file || "Structural analysis",
        line: Number(finding.primaryLocation?.line || 0),
        column: Number(finding.primaryLocation?.column || 0),
        reachableFromExternalEntry: finding.reachableFromExternalEntry,
        mitigations: finding.mitigations?.map(item => item.kind) ?? [],
        correlatedEngines: finding.correlatedEngines ?? [],
        limitations: finding.limitations,
        witnessPath: finding.witnessPath?.map(step =>
          `${step.role}:${step.symbol}@${step.location.file}:${step.location.line}`
        ) ?? [],
        counterexampleSequence: finding.counterexample?.sequence ?? [],
        observedViolation: finding.counterexample?.observedViolation,
        seed: finding.counterexample?.seed,
        blockNumber: finding.counterexample?.blockNumber,
        ...historicalFields(historicalFor(inspection, `advanced:${finding.id}`))
      });
    }

    for (const finding of inspection.inspection.findings) {
      if (SOURCE_REVIEW_ONLY_EXCLUSIONS.has(finding.kind)) continue;
      if (sourceFindingShadowedByAdvanced(finding, advanced)) continue;
      findings.push({
        candidateId: candidate.id,
        protocolLabel: candidate.label,
        hostname: candidate.hostname,
        classification: candidate.classification,
        researchScore: candidate.researchScore,
        ethereumConfidence: candidate.ethereumConfidence,
        contractRefId,
        contractName,
        sourceRole: inspection.sourceRole || (inspection.proxy ? "PROXY" : "DIRECT"),
        compilerVersion: inspection.compilerVersion || "",
        proxy: Boolean(inspection.proxy),
        sourceLayer: "source-review",
        findingId: `source:${contractRefId}:${finding.kind}:${finding.file}:${finding.line}`,
        kind: finding.kind,
        engine: "native",
        severity: legacySeverity(finding.severity),
        confidence: "LOW",
        evidenceStrength: "HEURISTIC",
        evidenceKey: "HEURISTIC",
        exploitabilityVerdict: "UNKNOWN",
        title: finding.title,
        description: finding.description,
        file: finding.file || "Verified source",
        line: Number(finding.line || 0),
        column: 0,
        mitigations: [],
        correlatedEngines: [],
        limitations: ["Pattern-level source review signal; presence alone does not establish exploitability."],
        witnessPath: [],
        counterexampleSequence: [],
        ...historicalFields(historicalFor(inspection, `source:${finding.kind}:${finding.file}:${finding.line}`))
      });
    }
  }

  const seen = new Set<string>();
  return findings.filter(finding => {
    const key = [
      finding.contractRefId,
      finding.kind,
      finding.file,
      finding.line,
      finding.title,
      finding.evidenceKey,
      finding.evidenceScope || ""
    ].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function analysisCompleteness(candidate: Candidate) {
  let advancedDropped = 0;
  let sourceReviewDropped = 0;
  let truncatedSourceCharacters = 0;
  let partial = false;

  for (const inspection of candidate.ethereum.sourceInspections) {
    const source = inspection.inspection;
    const dropped = (source.advancedAnalysis.truncations ?? []).reduce((sum, item) => sum + item.dropped, 0);
    advancedDropped += dropped;
    sourceReviewDropped += source.truncatedFindingCount;
    truncatedSourceCharacters += source.truncatedSourceCharacters;
    partial ||= Boolean(source.partial || source.advancedAnalysis.partial || dropped || source.truncatedFindingCount || source.sourceTruncated);
  }

  return { partial, advancedDropped, sourceReviewDropped, truncatedSourceCharacters };
}

function findingCounts(findings: ExportFinding[]) {
  const severity: Record<AnalysisSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const evidence: Record<EvidenceKey, number> = {
    REPRODUCED_FORK: 0,
    REPRODUCED_MODEL: 0,
    EXECUTED: 0,
    STRUCTURAL: 0,
    HEURISTIC: 0
  };
  for (const finding of findings) {
    severity[finding.severity] += 1;
    evidence[finding.evidenceKey] += 1;
  }
  return { severity, evidence };
}

function assessmentStatus(candidate: Candidate, findings: ExportFinding[]) {
  const completeness = analysisCompleteness(candidate);
  if (findings.some(finding => finding.exploitabilityVerdict === "CONFIRMED_AT_PINNED_BLOCK")) return "PINNED_FORK_EXPLOITABILITY_CONFIRMED_FOR_FINDING";
  if (findings.some(finding => (finding.severity === "CRITICAL" || finding.severity === "HIGH") &&
    (finding.evidenceKey === "EXECUTED" || finding.evidenceKey.startsWith("REPRODUCED_")))) {
    return "HIGH_SEVERITY_WITH_EXECUTION_EVIDENCE";
  }
  if (findings.some(finding => finding.severity === "CRITICAL" || finding.severity === "HIGH")) return "CRITICAL_OR_HIGH_REVIEW_REQUIRED";
  if (findings.length > 0) return "SECURITY_FINDINGS_REVIEW_REQUIRED";
  return completeness.partial ? "NO_FINDINGS_EMITTED_IN_PARTIAL_SCOPE" : "NO_FINDINGS_EMITTED_IN_ANALYZED_SCOPE";
}

function renderFindingHtml(finding: ExportFinding) {
  const location = finding.line > 0
    ? `${finding.file}:${finding.line}${finding.column ? `:${finding.column}` : ""}`
    : finding.file;
  const remediation = finding.remediation
    ? `<div class="guidance"><strong>Recommended remediation</strong><p>${htmlEscape(finding.remediation)}</p></div>`
    : "";
  const mitigations = finding.mitigations.length
    ? `<details><summary>Detected mitigations</summary><ul>${finding.mitigations.map(item => `<li>${htmlEscape(item)}</li>`).join("")}</ul></details>`
    : "";
  const witness = finding.witnessPath.length
    ? `<details><summary>Witness path</summary><ol>${finding.witnessPath.map(step => `<li><code>${htmlEscape(step)}</code></li>`).join("")}</ol></details>`
    : "";
  const counterexample = finding.observedViolation || finding.counterexampleSequence.length
    ? `<details><summary>Counterexample evidence</summary>${finding.observedViolation ? `<p><strong>Observed violation:</strong> ${htmlEscape(finding.observedViolation)}</p>` : ""}${finding.seed !== undefined ? `<p><strong>Seed:</strong> ${htmlEscape(finding.seed)}</p>` : ""}${finding.blockNumber !== undefined ? `<p><strong>Pinned block:</strong> ${htmlEscape(finding.blockNumber)}</p>` : ""}${finding.counterexampleSequence.length ? `<ol>${finding.counterexampleSequence.slice(0, 100).map(step => `<li>${htmlEscape(step)}</li>`).join("")}</ol>` : ""}</details>`
    : "";
  const limitations = finding.limitations.length
    ? `<details><summary>Limitations</summary><ul>${finding.limitations.map(item => `<li>${htmlEscape(item)}</li>`).join("")}</ul></details>`
    : "";
  const historical = finding.historicalAnalogueCount > 0
    ? `<div class="history"><strong>Historical Audit Intelligence</strong><p>${htmlEscape(finding.historicalCategory || "uncategorized")} · ${Math.round((finding.historicalCategoryConfidence || 0) * 100)}% category confidence · review-priority context ${htmlEscape(finding.historicalRiskScore ?? "n/a")}/100 · ${finding.historicalAnalogueCount} analogue(s). Supporting context only.</p></div>`
    : "";

  return `<article class="finding severity-${htmlEscape(finding.severity.toLowerCase())}">
    <div class="finding-head"><div><div class="badges"><span class="badge severity">${htmlEscape(finding.severity)}</span><span class="badge evidence">${htmlEscape(finding.evidenceKey.replaceAll("_", " "))}</span><span class="badge">${htmlEscape(finding.kind)}</span></div><h4>${htmlEscape(finding.title)}</h4></div><code>${htmlEscape(location)}</code></div>
    <p class="description">${htmlEscape(finding.description)}</p>
    <div class="meta-grid"><div class="meta"><span>Confidence</span><strong>${htmlEscape(finding.confidence)}</strong></div><div class="meta"><span>Engine</span><strong>${htmlEscape(finding.engine)}</strong></div><div class="meta"><span>Exploitability</span><strong>${htmlEscape(finding.exploitabilityVerdict)}</strong></div><div class="meta"><span>External reachability</span><strong>${finding.reachableFromExternalEntry === undefined ? "Unknown" : finding.reachableFromExternalEntry ? "Yes" : "No"}</strong></div></div>
    ${remediation}${historical}${mitigations}${witness}${counterexample}${limitations}
  </article>`;
}

function renderCandidateHtml(candidate: Candidate) {
  const findings = flattenSecurityFindings(candidate);
  const counts = findingCounts(findings);
  const completeness = analysisCompleteness(candidate);
  const groups = new Map<string, ExportFinding[]>();
  for (const finding of findings) {
    const key = `${finding.contractRefId}:${finding.contractName}`;
    const current = groups.get(key) ?? [];
    current.push(finding);
    groups.set(key, current);
  }

  const severityOrder: Record<AnalysisSeverity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const evidenceOrder: Record<EvidenceKey, number> = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 1, EXECUTED: 2, STRUCTURAL: 3, HEURISTIC: 4 };
  const groupHtml = [...groups.values()].map(group => {
    const first = group[0];
    const sorted = [...group].sort((a, b) =>
      evidenceOrder[a.evidenceKey] - evidenceOrder[b.evidenceKey] ||
      severityOrder[a.severity] - severityOrder[b.severity] ||
      a.line - b.line
    );
    return `<section class="contract"><div class="contract-head"><div><h3>${htmlEscape(first.contractName)}</h3><small>${htmlEscape(first.sourceRole)}${first.compilerVersion ? ` · ${htmlEscape(first.compilerVersion)}` : ""}</small></div><strong>${sorted.length} finding(s)</strong></div>${sorted.map(renderFindingHtml).join("")}</section>`;
  }).join("");

  const completenessHtml = completeness.partial
    ? `<div class="warning"><strong>Partial analysis</strong><p>${completeness.advancedDropped} advanced matches dropped, ${completeness.sourceReviewDropped} source-review signals dropped, and ${completeness.truncatedSourceCharacters} source characters outside configured budgets. Absence of a finding is not a clean pass.</p></div>`
    : "";

  return `<section class="candidate">
    <header class="candidate-head"><div><small>${htmlEscape(candidate.hostname)}</small><h2>${htmlEscape(candidate.label)}</h2><p>${htmlEscape(assessmentStatus(candidate, findings).replaceAll("_", " "))}</p></div><div class="score"><strong>${candidate.researchScore}</strong><span>research score</span></div></header>
    <div class="stats"><div><span>Critical</span><strong>${counts.severity.CRITICAL}</strong></div><div><span>High</span><strong>${counts.severity.HIGH}</strong></div><div><span>Reproduced</span><strong>${counts.evidence.REPRODUCED_MODEL + counts.evidence.REPRODUCED_FORK}</strong></div><div><span>Executed</span><strong>${counts.evidence.EXECUTED}</strong></div><div><span>Structural</span><strong>${counts.evidence.STRUCTURAL}</strong></div><div><span>Heuristic</span><strong>${counts.evidence.HEURISTIC}</strong></div></div>
    ${completenessHtml}
    ${groupHtml || `<div class="empty">No security findings were emitted in the analyzed scope. This does not prove the protocol is vulnerability-free.</div>`}
  </section>`;
}

function securityReviewHtml(candidates: Candidate[], generatedAt: string, startYear: number, endYear: number) {
  const allFindings = candidates.flatMap(flattenSecurityFindings);
  const counts = findingCounts(allFindings);
  const partialCandidates = candidates.filter(candidate => analysisCompleteness(candidate).partial).length;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ethereum DeFi Risk Radar · Security Review</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#e6edf5;background:#08131f}*{box-sizing:border-box}body{margin:0;background:#08131f}main{max-width:1180px;margin:0 auto;padding:36px 22px 80px}.report-head{margin-bottom:22px}.report-head h1{font-size:30px;margin:4px 0 8px}.report-head p{margin:0;color:#9badbf;max-width:820px;line-height:1.55}.method{padding:14px 16px;border:1px solid #34506b;background:#0b1c2c;border-radius:12px;margin:18px 0 24px;color:#b8c7d7}.overview,.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}.overview>div,.stats>div{background:#0b1a29;border:1px solid #26394d;border-radius:12px;padding:14px;display:grid;gap:5px}.overview span,.stats span,.meta span{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#8294a7}.overview strong,.stats strong{font-size:22px}.candidate{display:grid;gap:14px;margin-top:28px;padding-top:26px;border-top:2px solid #26394d}.candidate-head{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.candidate-head h2{font-size:24px;margin:3px 0 5px}.candidate-head p,.candidate-head small{color:#8fa1b3}.score{display:grid;text-align:right}.score strong{font-size:30px}.score span{font-size:11px;text-transform:uppercase;color:#8294a7}.contract{display:grid;gap:10px;margin-top:8px}.contract-head{display:flex;justify-content:space-between;align-items:end;padding:4px 2px}.contract-head h3{margin:0}.contract-head small{color:#8294a7}.finding{display:grid;gap:12px;padding:18px;background:#0b1a29;border:1px solid #26394d;border-left-width:4px;border-radius:12px}.severity-critical{border-left-color:#ff5c63}.severity-high{border-left-color:#ff8a66}.severity-medium{border-left-color:#e9ad49}.severity-low{border-left-color:#62c777}.severity-info{border-left-color:#4c91f7}.finding-head{display:flex;justify-content:space-between;gap:20px}.finding-head h4{font-size:17px;margin:7px 0 0}.finding-head>code{white-space:nowrap}.badges{display:flex;gap:7px;flex-wrap:wrap}.badge{display:inline-flex;padding:4px 8px;border-radius:999px;border:1px solid #3b5065;background:#091624;font-size:11px;font-weight:700}.badge.evidence{color:#d1afff;border-color:#69438d}.description{margin:0;color:#b0bfcd;line-height:1.6}.meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.meta{display:grid;gap:3px;padding:8px 10px;border:1px solid #203247;background:#081522;border-radius:8px}.meta strong{font-size:13px}.guidance,.history{padding:11px 13px;border:1px solid #2c435a;background:#091827;border-radius:9px}.guidance p,.history p{margin:5px 0 0;line-height:1.5}.history{border-color:#5f3d7d}details{border-top:1px solid #203247;padding-top:9px}summary{cursor:pointer;font-weight:700}.warning{padding:13px 15px;border:1px solid #805f28;background:#211b10;border-radius:10px;color:#eac06a}.empty{padding:28px;text-align:center;border:1px dashed #3b5065;border-radius:10px;color:#8fa1b3}@media(max-width:900px){.overview,.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){main{padding:24px 14px 60px}.candidate-head,.finding-head{flex-direction:column}.overview,.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.meta-grid{grid-template-columns:1fr}.score{text-align:left}.finding-head>code{white-space:normal;overflow-wrap:anywhere}}
</style></head><body><main>
<header class="report-head"><small>ETHEREUM MAINNET · DEFENSIVE RESEARCH</small><h1>Finding-first security review</h1><p>Generated ${htmlEscape(generatedAt)} for the ${startYear}–${endYear} discovery window. Severity and evidence strength are independent; a CRITICAL heuristic or structural signal is not automatically a reproduced exploit.</p></header>
<div class="method"><strong>Evidence policy:</strong> HEURISTIC and STRUCTURAL findings are review signals. EXECUTED requires a captured counterexample. REPRODUCED always states model or fork scope; only a pinned-fork confirmation is evidence about deployed bytecode at that block.</div>
<section class="overview"><div><span>Protocols</span><strong>${candidates.length}</strong></div><div><span>Findings</span><strong>${allFindings.length}</strong></div><div><span>Critical</span><strong>${counts.severity.CRITICAL}</strong></div><div><span>High</span><strong>${counts.severity.HIGH}</strong></div><div><span>Executed / reproduced</span><strong>${counts.evidence.EXECUTED + counts.evidence.REPRODUCED_MODEL + counts.evidence.REPRODUCED_FORK}</strong></div><div><span>Partial protocols</span><strong>${partialCandidates}</strong></div></section>
${candidates.map(renderCandidateHtml).join("\n")}
</main></body></html>`;
}

export async function writeReports(opts: {
  candidates: Candidate[];
  outputDir: string;
  startYear: number;
  endYear: number;
}) {
  await fs.mkdir(opts.outputDir, { recursive: true });
  const safeCandidates = reportSafeCandidates(opts.candidates);
  const generatedAt = new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, "-");
  const base = `ethereum-defi-risk-radar-${opts.startYear}-${opts.endYear}-${stamp}`;

  const jsonPath = path.join(opts.outputDir, `${base}.json`);
  const csvPath = path.join(opts.outputDir, `${base}.csv`);
  const summaryCsvPath = path.join(opts.outputDir, `${base}-summary.csv`);
  const findingsCsvPath = path.join(opts.outputDir, `${base}-findings.csv`);
  const securityReviewPath = path.join(opts.outputDir, `${base}-security-review.html`);

  const allFindings = safeCandidates.flatMap(flattenSecurityFindings);
  const payload = {
    generatedAt,
    chain: "ethereum",
    chainId: 1,
    network: "mainnet",
    methodology:
      "Public-web OSINT plus verified-source analysis. Severity and evidence strength are independent. EXECUTED requires a captured counterexample; REPRODUCED always states model or pinned-fork scope. Model reproduction is not evidence about deployed bytecode. Truncation records mark incomplete result sets. Full contract addresses and raw source are deliberately not written to reports.",
    guarantees: {
      guaranteesCurrentExploitabilityForEveryFinding: false,
      automaticallyDiscoversEveryPossibleDefiVulnerability: false,
      currentExploitabilityRule: "Only CONFIRMED_AT_PINNED_BLOCK establishes exploitability for that finding, against the recorded fork block and configuration.",
      exhaustiveDiscoveryReason: "Analysis is bounded and no finite analyzer can prove discovery of every possible vulnerability across arbitrary code, state, integrations, governance, ordering, and future environments."
    },
    candidates: safeCandidates,
    findingRows: allFindings
  };
  await fs.writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");

  const detailedColumns = ["candidateId", "candidateLabel", "hostname", "classification", "researchScore", "contractRefId", "contractName", "rowType", "findingId", "kind", "title", "severity", "confidence", "evidenceStrength", "evidenceKey", "evidenceScope", "exploitabilityVerdict", "file", "line", "reachableFromExternalEntry", "mitigations", "evidencePath", "counterexampleSequence", "observedViolation", "seed", "pinnedBlock", "limitations", "remediation", "historicalCategory", "historicalRiskScore", "historicalAnalogueCount", "truncated", "droppedCount", "findingLimit", "protocolContractCount", "protocolCallCount"];
  const detailedRows = [detailedColumns.map(csvEscape).join(",")];
  const pushDetailed = (candidate: Candidate, inspection: Inspection | undefined, row: Record<string, unknown>) => {
    const protocol = inspection?.inspection.protocolModel;
    const common: Record<string, unknown> = {
      candidateId: candidate.id,
      candidateLabel: candidate.label,
      hostname: candidate.hostname,
      classification: candidate.classification,
      researchScore: candidate.researchScore,
      contractRefId: inspection?.contractRefId ?? "",
      contractName: inspection?.contractName ?? "",
      protocolContractCount: protocol?.contracts.length ?? 0,
      protocolCallCount: protocol?.calls.length ?? 0
    };
    detailedRows.push(detailedColumns.map(column => csvEscape(row[column] ?? common[column] ?? "")).join(","));
  };

  for (const candidate of safeCandidates) {
    if (!candidate.ethereum.sourceInspections.length) pushDetailed(candidate, undefined, { rowType: "candidate_summary" });
    for (const inspection of candidate.ethereum.sourceInspections) {
      const advanced = inspection.inspection.advancedAnalysis.findings;
      for (const finding of inspection.inspection.findings) {
        if (SOURCE_REVIEW_ONLY_EXCLUSIONS.has(finding.kind) || sourceFindingShadowedByAdvanced(finding, advanced)) continue;
        const historical = historicalFor(inspection, `source:${finding.kind}:${finding.file}:${finding.line}`);
        pushDetailed(candidate, inspection, {
          rowType: "legacy_review_signal",
          kind: finding.kind,
          title: finding.title,
          severity: legacySeverity(finding.severity),
          confidence: "LOW",
          evidenceStrength: "HEURISTIC",
          evidenceKey: "HEURISTIC",
          exploitabilityVerdict: "UNKNOWN",
          file: finding.file,
          line: finding.line,
          limitations: "Pattern-level source review signal; exploitability unproven.",
          historicalCategory: historical?.predictedCategory,
          historicalRiskScore: historical?.historicalRiskScore,
          historicalAnalogueCount: historical?.analogues.length ?? 0
        });
      }
      for (const finding of advanced) {
        const scope = finding.evidenceScope || finding.counterexample?.scope;
        const historical = historicalFor(inspection, `advanced:${finding.id}`);
        pushDetailed(candidate, inspection, {
          rowType: "analysis_finding",
          findingId: finding.id,
          kind: finding.kind,
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          evidenceStrength: finding.evidenceStrength,
          evidenceKey: evidenceKey(finding.evidenceStrength, scope),
          evidenceScope: scope,
          exploitabilityVerdict: finding.exploitabilityVerdict ?? "UNKNOWN",
          file: finding.primaryLocation?.file,
          line: finding.primaryLocation?.line,
          reachableFromExternalEntry: finding.reachableFromExternalEntry,
          mitigations: finding.mitigations?.map(item => item.kind).join("|"),
          evidencePath: finding.evidencePath?.join(" -> "),
          counterexampleSequence: finding.counterexample?.sequence.join(" || "),
          observedViolation: finding.counterexample?.observedViolation,
          seed: finding.counterexample?.seed,
          pinnedBlock: finding.counterexample?.blockNumber,
          limitations: finding.limitations.join(" | "),
          remediation: finding.remediation,
          historicalCategory: historical?.predictedCategory,
          historicalRiskScore: historical?.historicalRiskScore,
          historicalAnalogueCount: historical?.analogues.length ?? 0
        });
      }
      for (const item of inspection.inspection.advancedAnalysis.truncations ?? []) {
        pushDetailed(candidate, inspection, { rowType: "truncation", kind: "analysis_truncation", title: `Results capped for ${item.ruleId}`, truncated: true, droppedCount: item.dropped, findingLimit: item.limit });
      }
      if (inspection.inspection.truncatedFindingCount > 0) {
        pushDetailed(candidate, inspection, { rowType: "truncation", kind: "legacy_truncation", title: "Source-review signals capped", truncated: true, droppedCount: inspection.inspection.truncatedFindingCount, findingLimit: inspection.inspection.findingLimit });
      }
    }
  }
  await fs.writeFile(csvPath, detailedRows.join("\n") + "\n", "utf8");

  const summaryColumns = ["candidateId", "protocolLabel", "hostname", "classification", "researchScore", "ethereumConfidence", "verifiedSourceContracts", "sourceContractsInspected", "securityFindingCount", "criticalFindingCount", "highFindingCount", "reproducedForkCount", "reproducedModelCount", "executedCount", "structuralCount", "heuristicCount", "assessmentStatus", "analysisPartial", "advancedDropped", "sourceReviewDropped", "truncatedSourceCharacters"];
  const summaryRows = [summaryColumns.map(csvEscape).join(",")];
  for (const candidate of safeCandidates) {
    const findings = flattenSecurityFindings(candidate);
    const counts = findingCounts(findings);
    const completeness = analysisCompleteness(candidate);
    const row: Record<string, unknown> = {
      candidateId: candidate.id,
      protocolLabel: candidate.label,
      hostname: candidate.hostname,
      classification: candidate.classification,
      researchScore: candidate.researchScore,
      ethereumConfidence: candidate.ethereumConfidence,
      verifiedSourceContracts: candidate.ethereum.verifiedSourceContracts,
      sourceContractsInspected: candidate.ethereum.sourceContractsInspected,
      securityFindingCount: findings.length,
      criticalFindingCount: counts.severity.CRITICAL,
      highFindingCount: counts.severity.HIGH,
      reproducedForkCount: counts.evidence.REPRODUCED_FORK,
      reproducedModelCount: counts.evidence.REPRODUCED_MODEL,
      executedCount: counts.evidence.EXECUTED,
      structuralCount: counts.evidence.STRUCTURAL,
      heuristicCount: counts.evidence.HEURISTIC,
      assessmentStatus: assessmentStatus(candidate, findings),
      analysisPartial: completeness.partial,
      advancedDropped: completeness.advancedDropped,
      sourceReviewDropped: completeness.sourceReviewDropped,
      truncatedSourceCharacters: completeness.truncatedSourceCharacters
    };
    summaryRows.push(summaryColumns.map(column => csvEscape(row[column])).join(","));
  }
  await fs.writeFile(summaryCsvPath, summaryRows.join("\n") + "\n", "utf8");

  const findingColumns: Array<[string, (finding: ExportFinding) => unknown]> = [
    ["candidateId", finding => finding.candidateId],
    ["protocolLabel", finding => finding.protocolLabel],
    ["hostname", finding => finding.hostname],
    ["classification", finding => finding.classification],
    ["researchScore", finding => finding.researchScore],
    ["ethereumConfidence", finding => finding.ethereumConfidence],
    ["contractRefId", finding => finding.contractRefId],
    ["contractName", finding => finding.contractName],
    ["sourceRole", finding => finding.sourceRole],
    ["compilerVersion", finding => finding.compilerVersion],
    ["proxy", finding => finding.proxy],
    ["sourceLayer", finding => finding.sourceLayer],
    ["findingId", finding => finding.findingId],
    ["kind", finding => finding.kind],
    ["engine", finding => finding.engine],
    ["severity", finding => finding.severity],
    ["confidence", finding => finding.confidence],
    ["evidenceStrength", finding => finding.evidenceStrength],
    ["evidenceKey", finding => finding.evidenceKey],
    ["evidenceScope", finding => finding.evidenceScope],
    ["exploitabilityVerdict", finding => finding.exploitabilityVerdict],
    ["title", finding => finding.title],
    ["description", finding => finding.description],
    ["remediation", finding => finding.remediation],
    ["file", finding => finding.file],
    ["line", finding => finding.line],
    ["column", finding => finding.column],
    ["reachableFromExternalEntry", finding => finding.reachableFromExternalEntry],
    ["mitigations", finding => finding.mitigations.join(" | ")],
    ["correlatedEngines", finding => finding.correlatedEngines.join(" | ")],
    ["limitations", finding => finding.limitations.join(" | ")],
    ["witnessPath", finding => finding.witnessPath.join(" -> ")],
    ["counterexampleSequence", finding => finding.counterexampleSequence.join(" || ")],
    ["observedViolation", finding => finding.observedViolation],
    ["seed", finding => finding.seed],
    ["blockNumber", finding => finding.blockNumber],
    ["historicalCategory", finding => finding.historicalCategory],
    ["historicalCategoryConfidence", finding => finding.historicalCategoryConfidence],
    ["historicalRiskScore", finding => finding.historicalRiskScore],
    ["historicalAnalogueCount", finding => finding.historicalAnalogueCount],
    ["historicalTopAnalogues", finding => finding.historicalTopAnalogues.join(" | ")]
  ];
  const findingRows = [findingColumns.map(([name]) => csvEscape(name)).join(",")];
  for (const finding of allFindings) {
    findingRows.push(findingColumns.map(([, getter]) => csvEscape(getter(finding))).join(","));
  }
  await fs.writeFile(findingsCsvPath, findingRows.join("\n") + "\n", "utf8");

  await fs.writeFile(securityReviewPath, securityReviewHtml(safeCandidates, generatedAt, opts.startYear, opts.endYear), "utf8");

  return { jsonPath, csvPath, summaryCsvPath, findingsCsvPath, securityReviewPath };
}
