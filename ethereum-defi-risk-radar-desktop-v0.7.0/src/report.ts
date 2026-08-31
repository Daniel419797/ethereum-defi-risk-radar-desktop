import fs from "node:fs/promises";
import path from "node:path";
import type {
  AnalysisConfidence,
  AnalysisFinding,
  AnalysisSeverity,
  EvidenceScope,
  EvidenceStrength
} from "./analysis/model.js";
import type { SourceFinding, SourceFindingSeverity } from "./sourceAnalyzer.js";
import type { Candidate, ContractInspectionSummary } from "./types.js";

const EVM_ADDRESS_RE = /0x[a-fA-F0-9]{40}/g;

function redactAddresses(value: string) {
  return value.replace(EVM_ADDRESS_RE, "[contract-address]");
}

function reportSafeCandidates(candidates: Candidate[]): Candidate[] {
  // Reports intentionally omit raw public contract addresses even when a search-result
  // URL, analyzer message, or counterexample contained one. Raw verified source is not
  // serialized into Candidate and is therefore not present in these reports either.
  return JSON.parse(redactAddresses(JSON.stringify(candidates))) as Candidate[];
}

function csvEscape(value: unknown) {
  const str = String(value ?? "");
  return `"${str.replaceAll('"', '""')}"`;
}

function htmlEscape(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function legacySeverity(value: SourceFindingSeverity): AnalysisSeverity {
  if (value === "HIGH_REVIEW") return "HIGH";
  return value;
}

type FindingSourceLayer = "advanced" | "source_review";

type ExportFinding = {
  candidateId: string;
  protocolLabel: string;
  hostname: string;
  classification: Candidate["classification"];
  researchScore: number;
  ethereumConfidence: number;
  contractRefId: string;
  contractName: string;
  compilerVersion: string;
  proxy: boolean;
  sourceLayer: FindingSourceLayer;
  findingId: string;
  kind: string;
  engine: string;
  severity: AnalysisSeverity;
  confidence: AnalysisConfidence;
  evidenceStrength: EvidenceStrength;
  evidenceScope?: EvidenceScope;
  title: string;
  description: string;
  remediation?: string;
  file: string;
  line: number;
  column?: number;
  reachableFromExternalEntry?: boolean;
  mitigations: string[];
  correlatedEngines: string[];
  limitations: string[];
  witnessPath: string[];
  counterexampleSequence: string[];
  observedViolation?: string;
  seed?: number;
  blockNumber?: number;
};

function advancedFinding(candidate: Candidate, inspection: ContractInspectionSummary, finding: AnalysisFinding): ExportFinding {
  return {
    candidateId: candidate.id,
    protocolLabel: candidate.label,
    hostname: candidate.hostname,
    classification: candidate.classification,
    researchScore: candidate.researchScore,
    ethereumConfidence: candidate.ethereumConfidence,
    contractRefId: inspection.contractRefId,
    contractName: inspection.contractName || inspection.contractRefId,
    compilerVersion: inspection.compilerVersion || "",
    proxy: inspection.proxy,
    sourceLayer: "advanced",
    findingId: finding.id,
    kind: finding.kind,
    engine: finding.engine,
    severity: finding.severity,
    confidence: finding.confidence,
    evidenceStrength: finding.evidenceStrength,
    evidenceScope: finding.evidenceScope || finding.counterexample?.scope,
    title: finding.title,
    description: finding.description,
    remediation: finding.remediation,
    file: finding.primaryLocation?.file || "Structural analysis",
    line: finding.primaryLocation?.line || 0,
    column: finding.primaryLocation?.column,
    reachableFromExternalEntry: finding.reachableFromExternalEntry,
    mitigations: (finding.mitigations || []).map(item => item.kind),
    correlatedEngines: finding.correlatedEngines || [],
    limitations: finding.limitations || [],
    witnessPath: (finding.witnessPath || []).map(step =>
      `${step.role}:${step.symbol}@${step.location.file}:${step.location.line}${step.detail ? `:${step.detail}` : ""}`
    ),
    counterexampleSequence: finding.counterexample?.sequence || [],
    observedViolation: finding.counterexample?.observedViolation,
    seed: finding.counterexample?.seed,
    blockNumber: finding.counterexample?.blockNumber
  };
}

function sourceReviewFinding(candidate: Candidate, inspection: ContractInspectionSummary, finding: SourceFinding): ExportFinding {
  return {
    candidateId: candidate.id,
    protocolLabel: candidate.label,
    hostname: candidate.hostname,
    classification: candidate.classification,
    researchScore: candidate.researchScore,
    ethereumConfidence: candidate.ethereumConfidence,
    contractRefId: inspection.contractRefId,
    contractName: inspection.contractName || inspection.contractRefId,
    compilerVersion: inspection.compilerVersion || "",
    proxy: inspection.proxy,
    sourceLayer: "source_review",
    findingId: `source:${inspection.contractRefId}:${finding.kind}:${finding.file}:${finding.line}`,
    kind: finding.kind,
    engine: "native",
    severity: legacySeverity(finding.severity),
    confidence: "LOW",
    evidenceStrength: "HEURISTIC",
    title: finding.title,
    description: finding.description,
    file: finding.file,
    line: finding.line,
    mitigations: [],
    correlatedEngines: [],
    limitations: ["Pattern-level source review signal; presence alone does not establish exploitability."],
    witnessPath: [],
    counterexampleSequence: []
  };
}

function flattenSecurityFindings(candidate: Candidate): ExportFinding[] {
  const rows: ExportFinding[] = [];
  for (const inspection of candidate.ethereum.sourceInspections) {
    rows.push(...inspection.inspection.advancedAnalysis.findings.map(finding => advancedFinding(candidate, inspection, finding)));
    rows.push(...inspection.inspection.findings.map(finding => sourceReviewFinding(candidate, inspection, finding)));
  }

  const seen = new Set<string>();
  return rows.filter(row => {
    const key = [row.contractRefId, row.sourceLayer, row.kind, row.file, row.line, row.title].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function evidenceKey(finding: ExportFinding) {
  if (finding.evidenceStrength === "REPRODUCED") {
    return finding.evidenceScope === "fork" ? "REPRODUCED_FORK" : "REPRODUCED_MODEL";
  }
  return finding.evidenceStrength;
}

function analysisCompleteness(candidate: Candidate) {
  const advancedDropped = candidate.ethereum.sourceInspections.reduce(
    (sum, inspection) => sum + (inspection.inspection.advancedAnalysis.truncations ?? []).reduce((dropped, item) => dropped + item.dropped, 0),
    0
  );
  const sourceReviewDropped = candidate.ethereum.sourceInspections.reduce(
    (sum, inspection) => sum + inspection.inspection.truncatedFindingCount,
    0
  );
  const truncatedSourceCharacters = candidate.ethereum.sourceInspections.reduce(
    (sum, inspection) => sum + inspection.inspection.truncatedSourceCharacters,
    0
  );
  const partial = candidate.ethereum.sourceInspections.some(
    inspection => inspection.inspection.partial || inspection.inspection.advancedAnalysis.partial || inspection.inspection.sourceTruncated
  );
  return { partial, advancedDropped, sourceReviewDropped, truncatedSourceCharacters };
}

function assessmentStatus(candidate: Candidate, findings: ExportFinding[]) {
  if (candidate.ethereum.sourceContractsInspected === 0) return "NO_VERIFIED_SOURCE_ANALYZED";
  if (findings.length === 0) return "NO_FINDINGS_IN_ANALYZED_SCOPE";
  const evidence = new Set(findings.map(evidenceKey));
  if (evidence.has("REPRODUCED_FORK")) return "REPRODUCED_ON_PINNED_FORK";
  if (evidence.has("REPRODUCED_MODEL")) return "REPRODUCED_IN_BOUNDED_MODEL";
  if (evidence.has("EXECUTED")) return "EXECUTED_COUNTEREXAMPLE_CAPTURED";
  if (evidence.has("STRUCTURAL")) return "STRUCTURAL_SECURITY_FINDINGS";
  return "HEURISTIC_REVIEW_SIGNALS";
}

function findingCounts(findings: ExportFinding[]) {
  const severity: Record<AnalysisSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const evidence = { REPRODUCED_FORK: 0, REPRODUCED_MODEL: 0, EXECUTED: 0, STRUCTURAL: 0, HEURISTIC: 0 };
  for (const finding of findings) {
    severity[finding.severity] += 1;
    const key = evidenceKey(finding);
    evidence[key as keyof typeof evidence] += 1;
  }
  return { severity, evidence };
}

function renderFindingHtml(finding: ExportFinding) {
  const location = finding.line > 0
    ? `${finding.file}:${finding.line}${finding.column ? `:${finding.column}` : ""}`
    : finding.file;
  const evidence = evidenceKey(finding);
  const metadata = [
    ["Evidence", evidence.replaceAll("_", " ")],
    ["Confidence", finding.confidence],
    ["Engine", finding.engine],
    ["Reachable externally", finding.reachableFromExternalEntry === undefined ? "Unknown" : finding.reachableFromExternalEntry ? "Yes" : "No"]
  ];
  const metaHtml = metadata.map(([label, value]) => `<div class="meta"><span>${htmlEscape(label)}</span><strong>${htmlEscape(value)}</strong></div>`).join("");
  const remediation = finding.remediation
    ? `<div class="guidance"><strong>Recommended remediation</strong><p>${htmlEscape(finding.remediation)}</p></div>`
    : "";
  const mitigations = finding.mitigations.length
    ? `<div class="inline"><strong>Detected mitigations</strong><span>${htmlEscape(finding.mitigations.join(", "))}</span></div>`
    : "";
  const witness = finding.witnessPath.length
    ? `<details><summary>Witness path · ${finding.witnessPath.length} step(s)</summary><ol>${finding.witnessPath.map(step => `<li><code>${htmlEscape(step)}</code></li>`).join("")}</ol></details>`
    : "";
  const counterexample = finding.observedViolation || finding.counterexampleSequence.length
    ? `<details><summary>Counterexample evidence</summary><div class="counterexample">${finding.observedViolation ? `<p><strong>Observed violation:</strong> ${htmlEscape(finding.observedViolation)}</p>` : ""}${finding.seed !== undefined ? `<p><strong>Seed:</strong> ${htmlEscape(finding.seed)}</p>` : ""}${finding.blockNumber !== undefined ? `<p><strong>Pinned block:</strong> ${htmlEscape(finding.blockNumber)}</p>` : ""}${finding.counterexampleSequence.length ? `<ol>${finding.counterexampleSequence.slice(0, 100).map(step => `<li>${htmlEscape(step)}</li>`).join("")}</ol>` : ""}</div></details>`
    : "";
  const limitations = finding.limitations.length
    ? `<details><summary>Limitations</summary><ul>${finding.limitations.map(item => `<li>${htmlEscape(item)}</li>`).join("")}</ul></details>`
    : "";

  return `<article class="finding severity-${htmlEscape(finding.severity.toLowerCase())}">
    <div class="finding-head"><div><div class="badges"><span class="badge severity ${htmlEscape(finding.severity.toLowerCase())}">${htmlEscape(finding.severity)}</span><span class="badge evidence">${htmlEscape(evidence.replaceAll("_", " "))}</span><span class="badge">${htmlEscape(finding.kind)}</span></div><h4>${htmlEscape(finding.title)}</h4></div><code>${htmlEscape(location)}</code></div>
    <p class="description">${htmlEscape(finding.description)}</p>
    <div class="meta-grid">${metaHtml}</div>
    ${remediation}${mitigations}${witness}${counterexample}${limitations}
  </article>`;
}

function renderCandidateHtml(candidate: Candidate) {
  const findings = flattenSecurityFindings(candidate);
  const counts = findingCounts(findings);
  const completeness = analysisCompleteness(candidate);
  const status = assessmentStatus(candidate, findings);
  const contractGroups = new Map<string, ExportFinding[]>();
  for (const finding of findings) {
    const key = `${finding.contractRefId}:${finding.contractName}`;
    const current = contractGroups.get(key) ?? [];
    current.push(finding);
    contractGroups.set(key, current);
  }

  const groupHtml = [...contractGroups.values()].map(group => {
    const first = group[0];
    const sorted = [...group].sort((a, b) => {
      const severityOrder: Record<AnalysisSeverity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity] || a.line - b.line;
    });
    return `<section class="contract"><div class="contract-head"><div><h3>${htmlEscape(first.contractName)}</h3><small>${htmlEscape(first.compilerVersion || "Compiler unknown")}${first.proxy ? " · proxy" : ""}</small></div><strong>${sorted.length} finding${sorted.length === 1 ? "" : "s"}</strong></div>${sorted.map(renderFindingHtml).join("")}</section>`;
  }).join("");

  const completenessHtml = completeness.partial
    ? `<div class="warning"><strong>Partial analysis</strong><p>Configured limits affected this candidate: ${completeness.advancedDropped} advanced findings dropped, ${completeness.sourceReviewDropped} source-review signals dropped, ${completeness.truncatedSourceCharacters} source characters outside the analysis budget. Absence of a finding must not be interpreted as a clean pass.</p></div>`
    : "";

  return `<section class="candidate">
    <header class="candidate-head"><div><small>${htmlEscape(candidate.hostname)}</small><h2>${htmlEscape(candidate.label)}</h2><p>${htmlEscape(status.replaceAll("_", " "))}</p></div><div class="score"><strong>${candidate.researchScore}</strong><span>research score</span></div></header>
    <div class="stats"><div><span>Critical</span><strong>${counts.severity.CRITICAL}</strong></div><div><span>High</span><strong>${counts.severity.HIGH}</strong></div><div><span>Executed / reproduced</span><strong>${counts.evidence.EXECUTED + counts.evidence.REPRODUCED_MODEL + counts.evidence.REPRODUCED_FORK}</strong></div><div><span>Structural</span><strong>${counts.evidence.STRUCTURAL}</strong></div><div><span>Heuristic</span><strong>${counts.evidence.HEURISTIC}</strong></div><div><span>Contracts inspected</span><strong>${candidate.ethereum.sourceContractsInspected}</strong></div></div>
    ${completenessHtml}
    ${groupHtml || `<div class="empty">No security findings were emitted in the analyzed scope.</div>`}
  </section>`;
}

function securityReviewHtml(candidates: Candidate[], generatedAt: string, startYear: number, endYear: number) {
  const allFindings = candidates.flatMap(flattenSecurityFindings);
  const counts = findingCounts(allFindings);
  const partialCandidates = candidates.filter(candidate => analysisCompleteness(candidate).partial).length;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ethereum DeFi Risk Radar · Security Review</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#101828;background:#f8fafc}*{box-sizing:border-box}body{margin:0}main{max-width:1180px;margin:0 auto;padding:36px 22px 80px}.report-head{display:flex;justify-content:space-between;gap:28px;align-items:flex-start;margin-bottom:22px}.report-head h1{font-size:30px;margin:4px 0 8px}.report-head p{margin:0;color:#667085;max-width:760px;line-height:1.55}.method{padding:14px 16px;border:1px solid #b2ddff;background:#eff8ff;border-radius:12px;margin:18px 0 24px;color:#175cd3}.overview,.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}.overview>div,.stats>div{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:14px;display:grid;gap:5px}.overview span,.stats span,.meta span{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#667085}.overview strong,.stats strong{font-size:22px}.candidate{display:grid;gap:14px;margin-top:28px;padding-top:26px;border-top:2px solid #e4e7ec}.candidate-head{display:flex;justify-content:space-between;gap:24px;align-items:flex-start}.candidate-head h2{font-size:24px;margin:3px 0 5px}.candidate-head p,.candidate-head small{color:#667085}.score{display:grid;text-align:right}.score strong{font-size:30px}.score span{font-size:11px;text-transform:uppercase;color:#667085}.contract{display:grid;gap:10px;margin-top:8px}.contract-head{display:flex;justify-content:space-between;align-items:end;padding:4px 2px}.contract-head h3{margin:0}.contract-head small{color:#667085}.finding{display:grid;gap:12px;padding:18px;background:#fff;border:1px solid #e4e7ec;border-left-width:4px;border-radius:12px}.severity-critical{border-left-color:#b42318}.severity-high{border-left-color:#d92d20}.severity-medium{border-left-color:#dc6803}.severity-low{border-left-color:#039855}.severity-info{border-left-color:#2e90fa}.finding-head{display:flex;justify-content:space-between;gap:20px}.finding-head h4{font-size:17px;margin:7px 0 0}.finding-head>code{white-space:nowrap}.badges{display:flex;gap:7px;flex-wrap:wrap}.badge{display:inline-flex;padding:4px 8px;border-radius:999px;border:1px solid #d0d5dd;background:#f9fafb;font-size:11px;font-weight:700}.badge.critical{background:#fef3f2;color:#912018;border-color:#fecdca}.badge.high{background:#fff4ed;color:#9c2a10;border-color:#ffd6ae}.badge.medium{background:#fffaeb;color:#93370d;border-color:#fedf89}.badge.low{background:#ecfdf3;color:#027a48;border-color:#abefc6}.badge.evidence{background:#f4f3ff;color:#5925dc;border-color:#d9d6fe}.description{margin:0;color:#475467;line-height:1.6}.meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.meta{display:grid;gap:3px;padding:8px 10px;border:1px solid #f2f4f7;background:#fcfcfd;border-radius:8px}.meta strong{font-size:13px}.guidance,.inline{padding:11px 13px;border:1px solid #e4e7ec;background:#f8fafc;border-radius:9px}.guidance p{margin:5px 0 0;line-height:1.5}.inline{display:flex;gap:10px;align-items:center}details{border-top:1px solid #f2f4f7;padding-top:9px}summary{cursor:pointer;font-weight:700}.counterexample{overflow-wrap:anywhere}.warning{padding:13px 15px;border:1px solid #fedf89;background:#fffaeb;border-radius:10px;color:#7a2e0e}.warning p{margin:5px 0 0;line-height:1.5}.empty{padding:28px;text-align:center;border:1px dashed #d0d5dd;border-radius:10px;color:#667085}@media(max-width:900px){.overview,.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:620px){main{padding:24px 14px 60px}.report-head,.candidate-head,.finding-head{flex-direction:column}.overview,.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.meta-grid{grid-template-columns:1fr}.score{text-align:left}.finding-head>code{white-space:normal;overflow-wrap:anywhere}}
</style></head><body><main>
<header class="report-head"><div><small>ETHEREUM MAINNET · DEFENSIVE RESEARCH</small><h1>Finding-first security review</h1><p>Generated ${htmlEscape(generatedAt)} for the ${startYear}–${endYear} discovery window. Severity and evidence strength are independent: a critical structural finding is not automatically a reproduced exploit.</p></div></header>
<div class="method"><strong>Evidence policy:</strong> HEURISTIC and STRUCTURAL findings are review signals. EXECUTED requires a captured ordered counterexample. REPRODUCED always states model or fork scope; only pinned-fork reproduction is evidence about deployed bytecode at that block.</div>
<section class="overview"><div><span>Candidates</span><strong>${candidates.length}</strong></div><div><span>Security findings</span><strong>${allFindings.length}</strong></div><div><span>Critical</span><strong>${counts.severity.CRITICAL}</strong></div><div><span>High</span><strong>${counts.severity.HIGH}</strong></div><div><span>Executed / reproduced</span><strong>${counts.evidence.EXECUTED + counts.evidence.REPRODUCED_MODEL + counts.evidence.REPRODUCED_FORK}</strong></div><div><span>Partial candidates</span><strong>${partialCandidates}</strong></div></section>
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
  const findingsCsvPath = path.join(opts.outputDir, `${base}-findings.csv`);
  const securityReviewPath = path.join(opts.outputDir, `${base}-security-review.html`);

  const payload = {
    generatedAt,
    chain: "ethereum",
    chainId: 1,
    network: "mainnet",
    methodology:
      "Public-web OSINT plus verified-source structural analysis. EXECUTED requires a captured counterexample; REPRODUCED always states model or pinned-fork scope. Model reproduction is not evidence about deployed bytecode. Truncation records mark incomplete result sets. Full contract addresses and raw source are deliberately not written to reports.",
    candidates: safeCandidates
  };

  await fs.writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");

  const summaryRows = [
    [
      "id", "label", "hostname", "chain", "network", "researchScore", "ethereumConfidence", "classification",
      "signalCount", "sourceDiversity", "kinds", "contractReferencesObserved", "verifiedSourceContracts", "proxyContracts",
      "sourceContractsInspected", "sourceFindingCount", "sourceHighReviewCount", "advancedFindingCount", "advancedDroppedFindingCount",
      "protocolContractCount", "protocolCallCount", "evidenceCount", "securityFindingCount", "criticalFindingCount", "highFindingCount",
      "executedFindingCount", "reproducedModelFindingCount", "reproducedForkFindingCount", "assessmentStatus", "analysisPartial"
    ].map(csvEscape).join(",")
  ];

  for (const candidate of safeCandidates) {
    const findings = flattenSecurityFindings(candidate);
    const counts = findingCounts(findings);
    const completeness = analysisCompleteness(candidate);
    summaryRows.push([
      candidate.id,
      candidate.label,
      candidate.hostname,
      candidate.chain,
      candidate.network,
      candidate.researchScore,
      candidate.ethereumConfidence,
      candidate.classification,
      candidate.signalCount,
      candidate.sourceDiversity,
      candidate.kinds.join("|"),
      candidate.ethereum.contractReferencesObserved,
      candidate.ethereum.verifiedSourceContracts,
      candidate.ethereum.proxyContracts,
      candidate.ethereum.sourceContractsInspected,
      candidate.ethereum.sourceFindingCount,
      candidate.ethereum.sourceHighReviewCount,
      candidate.ethereum.advancedFindingCount,
      completeness.advancedDropped,
      candidate.ethereum.sourceInspections.reduce((sum, inspection) => sum + (inspection.inspection.protocolModel?.contracts.length ?? 0), 0),
      candidate.ethereum.sourceInspections.reduce((sum, inspection) => sum + (inspection.inspection.protocolModel?.calls.length ?? 0), 0),
      candidate.evidence.length,
      findings.length,
      counts.severity.CRITICAL,
      counts.severity.HIGH,
      counts.evidence.EXECUTED,
      counts.evidence.REPRODUCED_MODEL,
      counts.evidence.REPRODUCED_FORK,
      assessmentStatus(candidate, findings),
      completeness.partial
    ].map(csvEscape).join(","));
  }
  await fs.writeFile(csvPath, summaryRows.join("\n") + "\n", "utf8");

  const findingHeaders: Array<keyof ExportFinding | "evidenceKey"> = [
    "candidateId", "protocolLabel", "hostname", "classification", "researchScore", "ethereumConfidence", "contractRefId",
    "contractName", "compilerVersion", "proxy", "sourceLayer", "findingId", "kind", "engine", "severity", "confidence",
    "evidenceStrength", "evidenceKey", "evidenceScope", "title", "description", "remediation", "file", "line", "column",
    "reachableFromExternalEntry", "mitigations", "correlatedEngines", "limitations", "witnessPath", "counterexampleSequence",
    "observedViolation", "seed", "blockNumber"
  ];
  const findingRows = [findingHeaders.map(csvEscape).join(",")];
  for (const candidate of safeCandidates) {
    for (const finding of flattenSecurityFindings(candidate)) {
      const values = findingHeaders.map(header => {
        if (header === "evidenceKey") return evidenceKey(finding);
        const value = finding[header as keyof ExportFinding];
        return Array.isArray(value) ? value.join(" | ") : value;
      });
      findingRows.push(values.map(csvEscape).join(","));
    }
  }
  await fs.writeFile(findingsCsvPath, findingRows.join("\n") + "\n", "utf8");
  await fs.writeFile(securityReviewPath, securityReviewHtml(safeCandidates, generatedAt, opts.startYear, opts.endYear), "utf8");

  return { jsonPath, csvPath, findingsCsvPath, securityReviewPath };
}
