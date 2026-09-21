import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { AnalysisFinding, StorageSurface } from "../analysis/model.js";
import { proxySlotObservation } from "./rpc.js";
import type {
  MonitorState,
  ProtocolGraphEdge,
  UpgradeChange,
  UpgradeComparison,
  VersionedProtocolFacts
} from "./model.js";

function changeId(...parts: Array<string | number | undefined>) {
  return createHash("sha256").update(parts.map(part => String(part ?? "")).join("|")).digest("hex").slice(0, 20);
}

function pushChange(changes: UpgradeChange[], value: Omit<UpgradeChange, "id">) {
  changes.push({
    ...value,
    id: changeId(value.kind, value.contractRefId, value.summary, value.before, value.after)
  });
}

function snapshotContractMap(facts: VersionedProtocolFacts) {
  return new Map((facts.snapshot?.contracts ?? []).map(contract => [contract.contractRefId, contract]));
}

function comparePinnedState(before: VersionedProtocolFacts, after: VersionedProtocolFacts, changes: UpgradeChange[]) {
  if (!before.snapshot || !after.snapshot) return;
  const beforeContracts = snapshotContractMap(before);
  const afterContracts = snapshotContractMap(after);

  for (const [refId, current] of afterContracts) {
    const previous = beforeContracts.get(refId);
    if (!previous) continue;

    if (previous.codeSha256 !== current.codeSha256) {
      pushChange(changes, {
        kind: "RUNTIME_CODE_CHANGED",
        severity: "HIGH",
        contractRefId: refId,
        summary: "Deployed runtime bytecode changed between pinned snapshots.",
        before: previous.codeSha256,
        after: current.codeSha256,
        evidence: [
          `from block ${before.snapshot.blockNumber} (${before.snapshot.blockHash})`,
          `to block ${after.snapshot.blockNumber} (${after.snapshot.blockHash})`
        ]
      });
    }

    const slots = [
      ["eip1967.implementation", "IMPLEMENTATION_CHANGED", "CRITICAL"],
      ["eip1967.admin", "ADMIN_CHANGED", "HIGH"],
      ["eip1967.beacon", "BEACON_CHANGED", "HIGH"]
    ] as const;

    for (const [slot, kind, severity] of slots) {
      const oldWord = proxySlotObservation(before.snapshot, refId, slot);
      const newWord = proxySlotObservation(after.snapshot, refId, slot);
      if (!oldWord || !newWord || oldWord.valueSha256 === newWord.valueSha256) continue;
      pushChange(changes, {
        kind,
        severity,
        contractRefId: refId,
        summary: `${slot} changed between pinned snapshots.`,
        before: oldWord.decodedAddressRef ?? oldWord.valueSha256,
        after: newWord.decodedAddressRef ?? newWord.valueSha256,
        evidence: [
          "Pinned eth_getStorageAt observation",
          `from block ${before.snapshot.blockNumber}`,
          `to block ${after.snapshot.blockNumber}`
        ]
      });
    }
  }
}

function storageKey(item: StorageSurface) {
  const slot = Number.isFinite(item.approximateSlot) ? item.approximateSlot : -1;
  return [item.declaringContract ?? "", slot, item.byteOffset ?? 0, item.variable].join("|");
}

function storageSlotKey(item: StorageSurface) {
  return [item.declaringContract ?? "", item.approximateSlot, item.byteOffset ?? 0].join("|");
}

function compareStorage(before: StorageSurface[], after: StorageSurface[], changes: UpgradeChange[]) {
  const beforeByKey = new Map(before.filter(item => item.occupiesSlot !== false).map(item => [storageKey(item), item]));
  const afterByKey = new Map(after.filter(item => item.occupiesSlot !== false).map(item => [storageKey(item), item]));
  const beforeBySlot = new Map(before.filter(item => item.occupiesSlot !== false).map(item => [storageSlotKey(item), item]));
  const afterBySlot = new Map(after.filter(item => item.occupiesSlot !== false).map(item => [storageSlotKey(item), item]));

  for (const [key, item] of afterByKey) {
    if (beforeByKey.has(key)) continue;
    const priorAtSlot = beforeBySlot.get(storageSlotKey(item));
    if (priorAtSlot && priorAtSlot.typeHint !== item.typeHint) {
      pushChange(changes, {
        kind: "STORAGE_TYPE_CHANGED",
        severity: "CRITICAL",
        summary: `Storage slot ${item.approximateSlot} changed type/meaning from ${priorAtSlot.variable} to ${item.variable}.`,
        before: `${priorAtSlot.typeHint} ${priorAtSlot.variable}`,
        after: `${item.typeHint} ${item.variable}`,
        location: item.declaredAt,
        evidence: ["Source-derived storage layout comparison", "Occupied slot semantics changed"]
      });
    } else {
      pushChange(changes, {
        kind: "STORAGE_ADDED",
        severity: "INFO",
        summary: `Storage variable added: ${item.variable} at approximate slot ${item.approximateSlot}.`,
        after: item.typeHint,
        location: item.declaredAt,
        evidence: ["Source-derived storage layout comparison"]
      });
    }
  }

  for (const [key, item] of beforeByKey) {
    if (afterByKey.has(key)) continue;
    const successor = afterBySlot.get(storageSlotKey(item));
    if (successor) continue;
    pushChange(changes, {
      kind: "STORAGE_REMOVED",
      severity: "HIGH",
      summary: `Previously occupied storage variable is absent: ${item.variable} at approximate slot ${item.approximateSlot}.`,
      before: item.typeHint,
      location: item.declaredAt,
      evidence: ["Source-derived storage layout comparison", "Removal/reordering requires manual compatibility review"]
    });
  }
}

function edgeKey(edge: ProtocolGraphEdge) {
  return [edge.from, edge.kind, edge.to, edge.location?.file ?? "", edge.location?.line ?? 0].join("|");
}

function compareGraph(before: VersionedProtocolFacts, after: VersionedProtocolFacts, changes: UpgradeChange[]) {
  const beforeEdges = new Map(before.graph.edges.map(edge => [edgeKey(edge), edge]));
  const afterEdges = new Map(after.graph.edges.map(edge => [edgeKey(edge), edge]));

  for (const [key, edge] of afterEdges) {
    if (beforeEdges.has(key)) continue;
    const severity =
      edge.kind === "DELEGATECALLS" ? "HIGH" :
      edge.kind === "CONTROLS" || edge.kind === "UPGRADES" ? "HIGH" :
      edge.kind === "CALLS" || edge.kind === "STATICCALLS" ? "MEDIUM" : "INFO";
    const specializedKind =
      edge.kind === "DELEGATECALLS" ? "DELEGATECALL_ADDED" :
      edge.kind === "CALLS" || edge.kind === "STATICCALLS" ? "EXTERNAL_CALL_ADDED" :
      edge.kind === "CONTROLS" || edge.kind === "UPGRADES" ? "PRIVILEGE_SURFACE_ADDED" :
      "GRAPH_EDGE_ADDED";
    pushChange(changes, {
      kind: specializedKind,
      severity,
      summary: `Knowledge-graph edge added: ${edge.kind} ${edge.from} → ${edge.to}.`,
      location: edge.location,
      evidence: edge.provenance.map(item => item.detail).slice(0, 4)
    });
  }

  for (const [key, edge] of beforeEdges) {
    if (afterEdges.has(key)) continue;
    pushChange(changes, {
      kind: "GRAPH_EDGE_REMOVED",
      severity: "INFO",
      summary: `Knowledge-graph edge removed: ${edge.kind} ${edge.from} → ${edge.to}.`,
      location: edge.location,
      evidence: ["Versioned protocol knowledge-graph comparison"]
    });
  }
}

function findingKey(finding: AnalysisFinding) {
  return [
    finding.kind,
    finding.primaryLocation?.file ?? "",
    finding.primaryLocation?.line ?? 0,
    finding.title
  ].join("|");
}

function compareFindings(before: AnalysisFinding[], after: AnalysisFinding[], changes: UpgradeChange[]) {
  const oldMap = new Map(before.map(finding => [findingKey(finding), finding]));
  const newMap = new Map(after.map(finding => [findingKey(finding), finding]));

  for (const [key, finding] of newMap) {
    if (oldMap.has(key)) continue;
    pushChange(changes, {
      kind: "NEW_FINDING",
      severity: finding.severity,
      summary: `New security finding after version change: ${finding.title}.`,
      location: finding.primaryLocation,
      evidence: [
        `evidence=${finding.evidenceStrength}`,
        `engine=${finding.engine}`,
        ...(finding.limitations ?? []).slice(0, 2)
      ]
    });
  }

  for (const [key, finding] of oldMap) {
    if (newMap.has(key)) continue;
    pushChange(changes, {
      kind: "FINDING_RESOLVED",
      severity: "INFO",
      summary: `Previously observed finding is no longer emitted: ${finding.title}.`,
      location: finding.primaryLocation,
      evidence: ["Absence after upgrade is not proof of remediation; review source/coverage changes and analysis completeness."]
    });
  }
}

function storageCompatibility(changes: UpgradeChange[]): UpgradeComparison["storageCompatibility"] {
  if (changes.some(change => change.kind === "STORAGE_TYPE_CHANGED" || change.kind === "STORAGE_REMOVED")) return "REVIEW_REQUIRED";
  if (changes.some(change => change.kind === "STORAGE_ADDED")) return "ADDITIVE";
  if (changes.some(change => change.kind.startsWith("STORAGE_"))) return "UNKNOWN";
  return "UNCHANGED";
}

export function compareProtocolVersions(
  before: VersionedProtocolFacts,
  after: VersionedProtocolFacts
): UpgradeComparison {
  const changes: UpgradeChange[] = [];
  comparePinnedState(before, after, changes);
  compareStorage(before.storage, after.storage, changes);
  compareGraph(before, after, changes);
  compareFindings(before.findings, after.findings, changes);

  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;
  changes.sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || a.kind.localeCompare(b.kind));

  return {
    generatedAt: new Date().toISOString(),
    fromBlock: before.snapshot?.blockNumber,
    toBlock: after.snapshot?.blockNumber,
    changes,
    highImpactChanges: changes.filter(change => change.severity === "CRITICAL" || change.severity === "HIGH").length,
    storageCompatibility: storageCompatibility(changes),
    implementationChanged: changes.some(change => change.kind === "IMPLEMENTATION_CHANGED"),
    assumptions: [
      "Storage positions are authoritative only when compiler-derived layouts are available; token-parser layouts remain approximate.",
      "A removed finding is not proof that the underlying weakness was fixed.",
      "Upgrade Intelligence reports concrete differences and does not label an upgrade safe or unsafe overall."
    ]
  };
}

function validateHistoryPath(filePath: string) {
  const resolved = path.resolve(filePath);
  if (!resolved.endsWith(".json")) throw new Error("Upgrade history path must be a JSON file.");
  return resolved;
}

export async function readMonitorState(filePath: string): Promise<MonitorState | undefined> {
  const resolved = validateHistoryPath(filePath);
  try {
    const stat = await fs.stat(resolved);
    if (!stat.isFile() || stat.size > 20_000_000) throw new Error("Monitor state file is invalid or exceeds 20 MB.");
    const parsed = JSON.parse(await fs.readFile(resolved, "utf8")) as MonitorState;
    if (parsed.schemaVersion !== 1 || !parsed.target?.id || !Array.isArray(parsed.events)) {
      throw new Error("Monitor state schema is unsupported.");
    }
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

export async function writeMonitorState(filePath: string, state: MonitorState) {
  const resolved = validateHistoryPath(filePath);
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  const bounded: MonitorState = {
    ...state,
    events: state.events.slice(-5_000),
    updatedAt: new Date().toISOString()
  };
  const tmp = `${resolved}.tmp-${process.pid}`;
  await fs.writeFile(tmp, JSON.stringify(bounded, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(tmp, resolved);
  return resolved;
}
