import fs from "node:fs/promises";
import path from "node:path";
import type { Candidate } from "./types.js";

const EVM_ADDRESS_RE = /0x[a-fA-F0-9]{40}/g;

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
  const str = String(value ?? "");
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

  const payload = {
    generatedAt: new Date().toISOString(),
    chain: "ethereum",
    chainId: 1,
    network: "mainnet",
    methodology:
      "Public-web OSINT plus verified-source structural analysis. EXECUTED requires a captured counterexample; REPRODUCED always states model or pinned-fork scope. Model reproduction is not evidence about deployed bytecode. Truncation records mark incomplete result sets. Full contract addresses and raw source are deliberately not written to reports.",
    candidates: safeCandidates
  };

  await fs.writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");

  const rows = [
    [
      "id",
      "label",
      "hostname",
      "chain",
      "network",
      "researchScore",
      "ethereumConfidence",
      "classification",
      "signalCount",
      "sourceDiversity",
      "kinds",
      "contractReferencesObserved",
      "verifiedSourceContracts",
      "proxyContracts",
      "sourceContractsInspected",
      "sourceFindingCount",
      "sourceHighReviewCount",
      "advancedFindingCount",
      "advancedDroppedFindingCount",
      "protocolContractCount",
      "protocolCallCount",
      "evidenceCount"
    ].map(csvEscape).join(",")
  ];

  for (const c of safeCandidates) {
    rows.push(
      [
        c.id,
        c.label,
        c.hostname,
        c.chain,
        c.network,
        c.researchScore,
        c.ethereumConfidence,
        c.classification,
        c.signalCount,
        c.sourceDiversity,
        c.kinds.join("|"),
        c.ethereum.contractReferencesObserved,
        c.ethereum.verifiedSourceContracts,
        c.ethereum.proxyContracts,
        c.ethereum.sourceContractsInspected,
        c.ethereum.sourceFindingCount,
        c.ethereum.sourceHighReviewCount,
        c.ethereum.advancedFindingCount,
        c.ethereum.sourceInspections.reduce((sum, inspection) => sum + (inspection.inspection.advancedAnalysis.truncations ?? []).reduce((dropped, item) => dropped + item.dropped, 0), 0),
        c.ethereum.sourceInspections.reduce((sum, inspection) => sum + (inspection.inspection.protocolModel?.contracts.length ?? 0), 0),
        c.ethereum.sourceInspections.reduce((sum, inspection) => sum + (inspection.inspection.protocolModel?.calls.length ?? 0), 0),
        c.evidence.length
      ].map(csvEscape).join(",")
    );
  }

  await fs.writeFile(csvPath, rows.join("\n") + "\n", "utf8");

  return { jsonPath, csvPath };
}
