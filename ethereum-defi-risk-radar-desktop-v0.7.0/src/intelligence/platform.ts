import { createHash } from "node:crypto";
import type { ProtocolIntelligenceBundle, ProtocolIntelligenceInput } from "./model.js";
import { buildProtocolKnowledgeGraph } from "./knowledgeGraph.js";
import { selectDefiInvariants } from "./invariants.js";
import { buildAutomaticEscalationQueue } from "./escalation.js";
import { buildAttackPaths } from "./attackPaths.js";

export function buildProtocolIntelligence(input: ProtocolIntelligenceInput): ProtocolIntelligenceBundle {
  const graph = buildProtocolKnowledgeGraph(input);
  const findings = input.contractInspections.flatMap(item => item.findings);
  const combinedModel = {
    contracts: input.contractInspections.flatMap(item => item.protocolModel.contracts),
    calls: input.contractInspections.flatMap(item => item.protocolModel.calls),
    assets: [...new Set(input.contractInspections.flatMap(item => item.protocolModel.assets))],
    categories: [...new Set(input.contractInspections.flatMap(item => item.protocolModel.categories))],
    unresolvedCallCount: input.contractInspections.reduce((sum, item) => sum + item.protocolModel.unresolvedCallCount, 0),
    assumptions: [...new Set(input.contractInspections.flatMap(item => item.protocolModel.assumptions))]
  };
  const invariants = selectDefiInvariants(combinedModel, findings);
  const escalationPlans = buildAutomaticEscalationQueue(findings, invariants);
  const attackPaths = buildAttackPaths(findings);
  const protocolModelDigest = "sha256:" + createHash("sha256").update(JSON.stringify(combinedModel)).digest("hex");
  return { version: 1, generatedAt: new Date().toISOString(), graph, invariants, escalationPlans, attackPaths, protocolModelDigest };
}
