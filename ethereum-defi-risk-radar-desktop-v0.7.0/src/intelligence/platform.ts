import type { Candidate } from "../types.js";
import type { VersionedProtocolFacts } from "./model.js";

export function candidateToVersionedProtocolFacts(candidate: Candidate): VersionedProtocolFacts {
  if (!candidate.intelligence?.graph) {
    throw new Error(`Candidate ${candidate.id} has no protocol knowledge graph.`);
  }
  return {
    snapshot: candidate.intelligence.snapshot,
    graph: candidate.intelligence.graph,
    findings: candidate.ethereum.sourceInspections.flatMap(
      inspection => inspection.inspection.advancedAnalysis.findings
    ),
    storage: candidate.ethereum.sourceInspections.flatMap(
      inspection => inspection.inspection.advancedAnalysis.storage
    ),
    protocolModels: candidate.ethereum.sourceInspections.map(
      inspection => inspection.inspection.protocolModel
    )
  };
}

export function selectCandidateFromReport(
  report: { candidates?: Candidate[] },
  selector?: string
): Candidate {
  const candidates = Array.isArray(report.candidates) ? report.candidates : [];
  if (!candidates.length) throw new Error("Risk Radar report contains no candidates.");

  if (selector) {
    const normalized = selector.toLowerCase();
    const matches = candidates.filter(candidate =>
      candidate.id.toLowerCase() === normalized ||
      candidate.label.toLowerCase() === normalized ||
      candidate.hostname.toLowerCase() === normalized
    );
    if (matches.length !== 1) {
      throw new Error(matches.length
        ? `Candidate selector is ambiguous: ${selector}`
        : `Candidate not found in report: ${selector}`);
    }
    return matches[0];
  }

  if (candidates.length === 1) return candidates[0];
  throw new Error("Report contains multiple candidates. Pass --candidate=<id|label|hostname>.");
}
