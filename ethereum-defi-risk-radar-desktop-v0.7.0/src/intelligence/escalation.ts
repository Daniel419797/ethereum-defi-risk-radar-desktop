import type { AnalysisFinding, EvidenceStrength } from "../analysis/model.js";
import type { EvidenceEscalationPlan, EvidenceEscalationStep, SelectedInvariant } from "./model.js";

const rank: Record<EvidenceStrength, number> = { HEURISTIC: 0, STRUCTURAL: 1, EXECUTED: 2, REPRODUCED: 3 };

function stageStatus(earned: boolean, blocked: boolean): EvidenceEscalationStep["status"] {
  if (earned) return "SATISFIED";
  return blocked ? "BLOCKED" : "PENDING";
}

function relatedInvariantIds(finding: AnalysisFinding, invariants: SelectedInvariant[]) {
  const kind = finding.kind;
  return invariants
    .filter(item => (item.invariant.requiredSignals ?? []).includes(kind) || (
      kind === "reentrancy" && item.invariant.id === "generic-external-call-effects"
    ) || (
      kind === "oracle_risk" && item.invariant.id === "oracle-freshness-consistency"
    ) || (
      kind === "upgradeability" && item.invariant.id === "upgrade-storage-continuity"
    ))
    .map(item => item.invariant.id);
}

export function buildEvidenceEscalationPlan(finding: AnalysisFinding, invariants: SelectedInvariant[]): EvidenceEscalationPlan {
  const current = rank[finding.evidenceStrength];
  const hasCounterexample = Boolean(finding.counterexample?.sequence.length);
  const forkReproduced = finding.evidenceStrength === "REPRODUCED" && finding.evidenceScope === "fork";
  const modelReproduced = finding.evidenceStrength === "REPRODUCED" && finding.evidenceScope === "model";
  const invariantIds = relatedInvariantIds(finding, invariants);
  const executable = Boolean(finding.reachableFromExternalEntry !== false);
  const steps: EvidenceEscalationStep[] = [
    { stage: "STRUCTURAL_REVIEW", required: true, status: stageStatus(current >= 1, false), engine: "native", reason: current >= 1 ? "Structural evidence already exists." : "Build a source-linked reachability/data-flow witness before attempting execution." },
    { stage: "STATE_VALIDATION", required: ["oracle_risk","upgradeability","governance_risk","storage_state"].includes(finding.kind), status: ["oracle_risk","upgradeability","governance_risk","storage_state"].includes(finding.kind) ? "PENDING" : "NOT_APPLICABLE", reason: "Pin relevant deployment state, proxy slots and read-only protocol observations at a canonical block." },
    { stage: "FUZZ_OR_SYMBOLIC", required: executable, status: stageStatus(hasCounterexample, !executable), engine: "foundry/echidna/mythril", reason: executable ? "Search for a concrete counterexample satisfying the selected invariant." : "The current source model says the sink is not externally reachable." },
    { stage: "MODEL_REPRODUCTION", required: hasCounterexample, status: modelReproduced || forkReproduced ? "SATISFIED" : hasCounterexample ? "PENDING" : "BLOCKED", reason: "Replay the exact counterexample deterministically in the protocol/economic model." },
    { stage: "PINNED_FORK_REPRODUCTION", required: finding.severity === "CRITICAL" || finding.severity === "HIGH", status: forkReproduced ? "SATISFIED" : hasCounterexample ? "PENDING" : "BLOCKED", engine: "anvil", reason: "Only authenticated pinned-fork reproduction can support a deployed-bytecode exploitability claim." },
    { stage: "ECONOMIC_IMPACT", required: ["oracle_risk","reentrancy","arithmetic_precision","token_integration","mev_ordering"].includes(finding.kind), status: "PENDING", reason: "Quantify loss/precondition bounds from the pinned state instead of inferring impact from code severity." }
  ];

  const targetEvidence = forkReproduced ? "REPRODUCED_FORK" : hasCounterexample ? "REPRODUCED_MODEL" : current >= 1 ? "EXECUTED" : "STRUCTURAL";
  return { findingId: finding.id, findingKind: finding.kind, currentEvidence: finding.evidenceStrength, targetEvidence, invariantIds, steps };
}

export function buildAutomaticEscalationQueue(findings: AnalysisFinding[], invariants: SelectedInvariant[]) {
  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;
  return findings
    .map(finding => buildEvidenceEscalationPlan(finding, invariants))
    .sort((a, b) => {
      const left = findings.find(item => item.id === a.findingId)!;
      const right = findings.find(item => item.id === b.findingId)!;
      return severityRank[left.severity] - severityRank[right.severity] || rank[left.evidenceStrength] - rank[right.evidenceStrength];
    });
}
