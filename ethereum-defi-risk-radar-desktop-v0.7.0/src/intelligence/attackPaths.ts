import { createHash } from "node:crypto";
import type { AnalysisFinding } from "../analysis/model.js";
import type { AttackPath, AttackPathEdge, AttackPathNode } from "./model.js";

function id(value: string) { return createHash("sha256").update(value).digest("hex").slice(0, 14); }

export function attackPathForFinding(finding: AnalysisFinding): AttackPath | null {
  const witness = finding.witnessPath ?? [];
  const evidence = finding.evidencePath ?? [];
  if (!witness.length && !evidence.length && !finding.primaryLocation) return null;

  const nodes: AttackPathNode[] = [];
  const edges: AttackPathEdge[] = [];
  const addNode = (node: AttackPathNode) => { if (!nodes.some(item => item.id === node.id)) nodes.push(node); };

  let previous: string | undefined;
  if (witness.length) {
    for (const step of witness) {
      const nodeId = "path:" + id(finding.id + "|" + step.role + "|" + step.symbol + "|" + step.location.file + ":" + step.location.line);
      const kind: AttackPathNode["kind"] = step.role === "source" ? "ENTRY" : step.role === "sink" ? "CALL" : "FUNCTION";
      addNode({ id: nodeId, kind, label: step.symbol, sourceLocation: step.location });
      if (previous) edges.push({ from: previous, to: nodeId, label: step.role });
      previous = nodeId;
    }
  } else {
    for (const [index, label] of evidence.entries()) {
      const nodeId = "path:" + id(finding.id + "|" + index + "|" + label);
      addNode({ id: nodeId, kind: index === 0 ? "ENTRY" : "STATE", label });
      if (previous) edges.push({ from: previous, to: nodeId });
      previous = nodeId;
    }
  }

  const findingId = "path-finding:" + finding.id;
  addNode({ id: findingId, kind: "FINDING", label: finding.title, sourceLocation: finding.primaryLocation });
  if (previous) edges.push({ from: previous, to: findingId, label: "observed risk" });

  if (finding.counterexample) {
    const impactId = "impact:" + id(finding.id + "|" + finding.counterexample.observedViolation);
    addNode({ id: impactId, kind: "IMPACT", label: finding.counterexample.observedViolation });
    edges.push({ from: findingId, to: impactId, label: finding.counterexample.scope === "fork" ? "reproduced on fork" : "reproduced in model" });
  }

  return {
    id: "attack:" + id(finding.id),
    findingId: finding.id,
    severity: finding.severity,
    evidenceStrength: finding.evidenceStrength,
    title: finding.title,
    nodes,
    edges,
    limitations: [...finding.limitations]
  };
}

export function buildAttackPaths(findings: AnalysisFinding[]) {
  return findings.map(attackPathForFinding).filter((item): item is AttackPath => Boolean(item));
}
