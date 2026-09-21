import type { AnalysisSeverity } from "../analysis/model.js";
import type {
  ProtocolIntelligenceBundle,
  PinnedStateSnapshot,
  UpgradeChange,
  UpgradeComparison
} from "./model.js";
import { diffPinnedSnapshots } from "./monitor.js";

function severityCounts(changes: UpgradeChange[]) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const change of changes) {
    const key = change.severity.toLowerCase() as keyof typeof out;
    out[key] += 1;
  }
  return out;
}

function monitorSeverity(kind: string): AnalysisSeverity {
  if (kind === "CODE_CHANGED") return "CRITICAL";
  if (
    kind === "IMPLEMENTATION_CHANGED" ||
    kind === "ADMIN_CHANGED" ||
    kind === "BEACON_CHANGED"
  ) {
    return "HIGH";
  }
  return "MEDIUM";
}

function graphSet(bundle: ProtocolIntelligenceBundle, kind: "nodes" | "edges") {
  return new Set(bundle.graph[kind].map(item => item.id));
}

export function compareProtocolUpgrade(opts: {
  previousSnapshot: PinnedStateSnapshot;
  currentSnapshot: PinnedStateSnapshot;
  previousIntelligence?: ProtocolIntelligenceBundle;
  currentIntelligence?: ProtocolIntelligenceBundle;
}): UpgradeComparison {
  const changes: UpgradeChange[] = [];
  const snapshotDiff = diffPinnedSnapshots(opts.previousSnapshot, opts.currentSnapshot);

  for (const change of snapshotDiff.changes) {
    changes.push({
      kind:
        change.kind === "CODE_CHANGED"
          ? "RUNTIME_BYTECODE"
          : change.kind === "IMPLEMENTATION_CHANGED"
            ? "IMPLEMENTATION"
            : change.kind === "ADMIN_CHANGED"
              ? "ADMIN"
              : change.kind === "BEACON_CHANGED"
                ? "BEACON"
                : "PRIVILEGED_SURFACE",
      severity: monitorSeverity(change.kind),
      title: change.kind.replaceAll("_", " ").toLowerCase(),
      before: change.before || undefined,
      after: change.after || undefined,
      evidence: [
        "pinned-state:" + opts.previousSnapshot.blockNumber,
        "pinned-state:" + opts.currentSnapshot.blockNumber
      ]
    });
  }

  if (opts.previousIntelligence && opts.currentIntelligence) {
    const oldNodes = graphSet(opts.previousIntelligence, "nodes");
    const newNodes = graphSet(opts.currentIntelligence, "nodes");
    const oldEdges = graphSet(opts.previousIntelligence, "edges");
    const newEdges = graphSet(opts.currentIntelligence, "edges");

    const addedNodes = [...newNodes].filter(value => !oldNodes.has(value));
    const removedNodes = [...oldNodes].filter(value => !newNodes.has(value));
    const addedEdges = [...newEdges].filter(value => !oldEdges.has(value));
    const removedEdges = [...oldEdges].filter(value => !newEdges.has(value));

    if (addedNodes.length || removedNodes.length || addedEdges.length || removedEdges.length) {
      changes.push({
        kind: "CALL_GRAPH",
        severity: addedEdges.length || removedEdges.length ? "MEDIUM" : "LOW",
        title: "Protocol knowledge graph changed",
        before: oldNodes.size + " nodes / " + oldEdges.size + " edges",
        after: newNodes.size + " nodes / " + newEdges.size + " edges",
        evidence: [
          "added-nodes:" + addedNodes.length,
          "removed-nodes:" + removedNodes.length,
          "added-edges:" + addedEdges.length,
          "removed-edges:" + removedEdges.length
        ]
      });
    }

    const previousFindings = new Set(
      opts.previousIntelligence.graph.nodes
        .filter(node => node.kind === "FINDING")
        .map(node => (node.category || "") + "|" + node.label)
    );
    const currentFindings = new Set(
      opts.currentIntelligence.graph.nodes
        .filter(node => node.kind === "FINDING")
        .map(node => (node.category || "") + "|" + node.label)
    );
    const newFindings = [...currentFindings].filter(value => !previousFindings.has(value));
    if (newFindings.length) {
      changes.push({
        kind: "FINDING",
        severity: "HIGH",
        title: "New security findings introduced after upgrade",
        after: String(newFindings.length),
        evidence: newFindings.slice(0, 20)
      });
    }

    const oldInvariants = new Set(
      opts.previousIntelligence.invariants.map(item => item.invariant.id)
    );
    const currentInvariants = new Set(
      opts.currentIntelligence.invariants.map(item => item.invariant.id)
    );
    const newInvariants = [...currentInvariants].filter(value => !oldInvariants.has(value));
    if (newInvariants.length) {
      changes.push({
        kind: "INVARIANT",
        severity: "MEDIUM",
        title: "New protocol invariants became applicable",
        after: String(newInvariants.length),
        evidence: newInvariants
      });
    }
  }

  const counts = severityCounts(changes);
  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    previousDigest: opts.previousSnapshot.digest,
    currentDigest: opts.currentSnapshot.digest,
    changed: changes.length > 0,
    changes,
    ...counts
  };
}
