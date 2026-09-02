import fs from "node:fs/promises";
import path from "node:path";
import type { Candidate } from "./types.js";

const EVM_ADDRESS_RE = /0x[a-f0-9]{40}/gi;

function redactAddresses(value: string) {
  return value.replace(EVM_ADDRESS_RE, "[contract-address]");
}

function reportSafeCandidates(candidates: Candidate[]): Candidate[] {
  // Reports intentionally omit raw public contract addresses even when a search-result
  // URL or title contained one. The in-memory desktop result can still open the original
  // public evidence URL during the current session.
  return JSON.parse(
    redactAddresses(JSON.stringify(candidates))
  ) as Candidate[];
}

function csvEscape(value: unknown) {
  const raw = String(value ?? "");
  const str = /^[=+\-@]/.test(raw) ? `'${raw}` : raw;
  return `"${str.replaceAll('"', '""')}"`;
}

export async function writeReports(opts: {
  candidates: Candidate[];
  outputDir: string;
  startYear: number;
  endYear: number;
}) {
  await fs.mkdir(opts.outputDir, { recursive: true });
  const safeCandidates = reportSafeCandidates(opts.candidates);

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = `ethereum-defi-risk-radar-${opts.startYear}-${opts.endYear}-${stamp}`;

  const jsonPath = path.join(opts.outputDir, `${base}.json`);
  const csvPath = path.join(opts.outputDir, `${base}.csv`);

  const findingRows = safeCandidates.flatMap(candidate => candidate.ethereum.sourceInspections.flatMap(inspection =>
    inspection.inspection.advancedAnalysis.findings.map(finding => ({
      candidateId: candidate.id,
      candidateLabel: candidate.label,
      contractRefId: inspection.contractRefId,
      contractName: inspection.contractName,
      ...finding
    }))
  ));

  const payload = {
    generatedAt: new Date().toISOString(),
    chain: "ethereum",
    chainId: 1,
    network: "mainnet",
    methodology:
      "Public-web OSINT plus verified-source structural analysis. EXECUTED requires a captured counterexample; REPRODUCED always states model or pinned-fork scope. Model reproduction is not evidence about deployed bytecode. Truncation records mark incomplete result sets. Full contract addresses and raw source are deliberately not written to reports.",
    guarantees: {
      guaranteesCurrentExploitabilityForEveryFinding: false,
      automaticallyDiscoversEveryPossibleDefiVulnerability: false,
      currentExploitabilityRule: "Only CONFIRMED_AT_PINNED_BLOCK establishes exploitability for that finding, against the recorded fork block and configuration.",
      exhaustiveDiscoveryReason: "Analysis is bounded and no finite analyzer can prove discovery of every possible vulnerability across arbitrary code, state, integrations, governance, ordering, and future environments."
    },
    candidates: safeCandidates,
    findingRows
  };

  await fs.writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");

  const columns = ["candidateId", "candidateLabel", "hostname", "classification", "researchScore", "contractRefId", "contractName", "rowType", "findingId", "kind", "title", "severity", "confidence", "evidenceStrength", "evidenceScope", "exploitabilityVerdict", "file", "line", "reachableFromExternalEntry", "mitigations", "evidencePath", "counterexampleSequence", "observedViolation", "seed", "pinnedBlock", "limitations", "remediation", "truncated", "droppedCount", "findingLimit", "protocolContractCount", "protocolCallCount"];
  const rows = [columns.map(csvEscape).join(",")];
  const push = (candidate: Candidate, inspection: Candidate["ethereum"]["sourceInspections"][number] | undefined, row: Record<string, unknown>) => {
    const protocol = inspection?.inspection.protocolModel;
    const common: Record<string, unknown> = { candidateId: candidate.id, candidateLabel: candidate.label, hostname: candidate.hostname, classification: candidate.classification, researchScore: candidate.researchScore, contractRefId: inspection?.contractRefId ?? "", contractName: inspection?.contractName ?? "", protocolContractCount: protocol?.contracts.length ?? 0, protocolCallCount: protocol?.calls.length ?? 0 };
    rows.push(columns.map(column => csvEscape(row[column] ?? common[column] ?? "")).join(","));
  };
  for (const candidate of safeCandidates) {
    if (!candidate.ethereum.sourceInspections.length) push(candidate, undefined, { rowType: "candidate_summary" });
    for (const inspection of candidate.ethereum.sourceInspections) {
      for (const finding of inspection.inspection.findings) push(candidate, inspection, { rowType: "legacy_review_signal", kind: finding.kind, title: finding.title, severity: finding.severity, confidence: "LOW", evidenceStrength: "STRUCTURAL", exploitabilityVerdict: "UNKNOWN", file: finding.file, line: finding.line, limitations: "Legacy structural review signal; exploitability unproven." });
      for (const finding of inspection.inspection.advancedAnalysis.findings) push(candidate, inspection, { rowType: "analysis_finding", findingId: finding.id, kind: finding.kind, title: finding.title, severity: finding.severity, confidence: finding.confidence, evidenceStrength: finding.evidenceStrength, evidenceScope: finding.evidenceScope, exploitabilityVerdict: finding.exploitabilityVerdict ?? "UNKNOWN", file: finding.primaryLocation?.file, line: finding.primaryLocation?.line, reachableFromExternalEntry: finding.reachableFromExternalEntry, mitigations: finding.mitigations?.map(item => item.kind).join("|"), evidencePath: finding.evidencePath?.join(" -> "), counterexampleSequence: finding.counterexample?.sequence.join(" || "), observedViolation: finding.counterexample?.observedViolation, seed: finding.counterexample?.seed, pinnedBlock: finding.counterexample?.blockNumber, limitations: finding.limitations.join(" | "), remediation: finding.remediation });
      for (const item of inspection.inspection.advancedAnalysis.truncations ?? []) push(candidate, inspection, { rowType: "truncation", kind: "analysis_truncation", title: `Results capped for ${item.ruleId}`, truncated: true, droppedCount: item.dropped, findingLimit: item.limit });
      if (inspection.inspection.truncatedFindingCount > 0) push(candidate, inspection, { rowType: "truncation", kind: "legacy_truncation", title: "Legacy review signals capped", truncated: true, droppedCount: inspection.inspection.truncatedFindingCount, findingLimit: inspection.inspection.findingLimit });
    }
  }

  await fs.writeFile(csvPath, rows.join("\n") + "\n", "utf8");

  return { jsonPath, csvPath };
}
