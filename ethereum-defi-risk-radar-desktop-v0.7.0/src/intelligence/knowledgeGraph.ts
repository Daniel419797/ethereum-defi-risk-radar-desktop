import { createHash } from "node:crypto";
import type { AnalysisFinding } from "../analysis/model.js";
import type { KnowledgeEdge, KnowledgeNode, ProtocolIntelligenceInput, ProtocolKnowledgeGraph, ProvenanceRecord } from "./model.js";

function shortHash(value: string) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
function provenance(kind: ProvenanceRecord["kind"], sourceRef: string, note?: string): ProvenanceRecord {
  const observedAt = new Date().toISOString();
  return { id: shortHash(kind + "|" + sourceRef + "|" + note), kind, observedAt, sourceRef, note };
}
function findingNodeId(contractRefId: string, finding: AnalysisFinding) {
  return "finding:" + shortHash(contractRefId + "|" + finding.id);
}
function contractNodeId(ref: string) { return "contract:" + ref; }
function assetNodeId(asset: string) { return "asset:" + shortHash(asset.toLowerCase()); }
function edgeId(kind: string, from: string, to: string, detail = "") { return "edge:" + shortHash(kind + "|" + from + "|" + to + "|" + detail); }

export function buildProtocolKnowledgeGraph(input: ProtocolIntelligenceInput): ProtocolKnowledgeGraph {
  const provenanceRecords: ProvenanceRecord[] = [];
  const nodes = new Map<string, KnowledgeNode>();
  const edges = new Map<string, KnowledgeEdge>();
  const rootId = "protocol:" + input.protocolId;
  const protocolProv = provenance("VERIFIED_SOURCE", input.protocolId, "Protocol identity resolved to verified-source contracts.");
  provenanceRecords.push(protocolProv);
  nodes.set(rootId, { id: rootId, kind: "PROTOCOL", label: input.label, provenance: [protocolProv.id] });

  const nameToContract = new Map<string, string>();
  for (const inspection of input.contractInspections) {
    const nodeId = contractNodeId(inspection.contractRefId);
    const sourceProv = provenance("STATIC_ANALYSIS", inspection.contractRefId, inspection.sourceRole || "DIRECT");
    provenanceRecords.push(sourceProv);
    const kind = inspection.sourceRole === "PROXY" || inspection.proxy ? "PROXY" : inspection.sourceRole === "IMPLEMENTATION" ? "IMPLEMENTATION" : "CONTRACT";
    nodes.set(nodeId, {
      id: nodeId,
      kind,
      label: inspection.contractName || inspection.contractRefId,
      contractRefId: inspection.contractRefId,
      category: inspection.protocolModel.categories[0],
      metadata: { sourceRole: inspection.sourceRole || "DIRECT", proxy: inspection.proxy },
      provenance: [sourceProv.id]
    });
    if (inspection.contractName) nameToContract.set(inspection.contractName, nodeId);
    const contains: KnowledgeEdge = { id: edgeId("CONTAINS", rootId, nodeId), kind: "CONTAINS", from: rootId, to: nodeId, confidence: "HIGH", provenance: [sourceProv.id] };
    edges.set(contains.id, contains);
  }

  for (const inspection of input.contractInspections) {
    const fromContract = contractNodeId(inspection.contractRefId);
    if (inspection.sourceRole === "IMPLEMENTATION" && inspection.rootContractRefId && inspection.rootContractRefId !== inspection.contractRefId) {
      const proxyId = contractNodeId(inspection.rootContractRefId);
      if (nodes.has(proxyId)) {
        const e: KnowledgeEdge = { id: edgeId("UPGRADES_TO", proxyId, fromContract), kind: "UPGRADES_TO", from: proxyId, to: fromContract, label: "resolved implementation", confidence: "HIGH", provenance: nodes.get(fromContract)?.provenance ?? [] };
        edges.set(e.id, e);
      }
    }

    for (const modelContract of inspection.protocolModel.contracts) {
      if (!nameToContract.has(modelContract.name)) nameToContract.set(modelContract.name, fromContract);
    }

    for (const asset of inspection.protocolModel.assets) {
      const assetId = assetNodeId(asset);
      if (!nodes.has(assetId)) nodes.set(assetId, { id: assetId, kind: "ASSET", label: asset, provenance: nodes.get(fromContract)?.provenance ?? [] });
      const e: KnowledgeEdge = { id: edgeId("USES_ASSET", fromContract, assetId), kind: "USES_ASSET", from: fromContract, to: assetId, confidence: "MEDIUM", provenance: nodes.get(fromContract)?.provenance ?? [] };
      edges.set(e.id, e);
    }

    for (const finding of inspection.findings) {
      const id = findingNodeId(inspection.contractRefId, finding);
      nodes.set(id, {
        id,
        kind: "FINDING",
        label: finding.title,
        contractRefId: inspection.contractRefId,
        sourceLocation: finding.primaryLocation,
        category: finding.kind,
        metadata: { severity: finding.severity, evidenceStrength: finding.evidenceStrength, exploitability: finding.exploitabilityVerdict || "UNKNOWN" },
        provenance: nodes.get(fromContract)?.provenance ?? []
      });
      const e: KnowledgeEdge = { id: edgeId("HAS_FINDING", fromContract, id), kind: "HAS_FINDING", from: fromContract, to: id, confidence: finding.confidence, provenance: nodes.get(fromContract)?.provenance ?? [] };
      edges.set(e.id, e);

      for (const step of finding.witnessPath ?? []) {
        const functionId = "function:" + shortHash(inspection.contractRefId + "|" + step.symbol + "|" + (step.location.file || ""));
        if (!nodes.has(functionId)) {
          nodes.set(functionId, { id: functionId, kind: "FUNCTION", label: step.symbol, contractRefId: inspection.contractRefId, sourceLocation: step.location, provenance: nodes.get(fromContract)?.provenance ?? [] });
          const fe: KnowledgeEdge = { id: edgeId("CONTAINS", fromContract, functionId), kind: "CONTAINS", from: fromContract, to: functionId, confidence: "HIGH", provenance: nodes.get(fromContract)?.provenance ?? [] };
          edges.set(fe.id, fe);
        }
      }
    }
  }

  let unresolvedEdges = 0;
  for (const inspection of input.contractInspections) {
    for (const call of inspection.protocolModel.calls) {
      const from = nameToContract.get(call.from) || contractNodeId(inspection.contractRefId);
      const to = call.to ? nameToContract.get(call.to) : undefined;
      if (!to) { unresolvedEdges += 1; continue; }
      const kind = call.operation === "delegatecall" ? "DELEGATECALLS" : "CALLS";
      const e: KnowledgeEdge = {
        id: edgeId(kind, from, to, call.location.file + ":" + call.location.line),
        kind,
        from,
        to,
        label: call.operation,
        sourceLocation: call.location,
        confidence: call.resolved ? "HIGH" : "LOW",
        provenance: nodes.get(from)?.provenance ?? []
      };
      edges.set(e.id, e);
    }
  }

  const nodeRows = [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id));
  const edgeRows = [...edges.values()].sort((a, b) => a.id.localeCompare(b.id));
  const canonical = { version: 1, protocolId: input.protocolId, nodes: nodeRows, edges: edgeRows, unresolvedEdges };
  return {
    ...canonical,
    generatedAt: new Date().toISOString(),
    provenance: provenanceRecords,
    digest: "sha256:" + createHash("sha256").update(JSON.stringify(canonical)).digest("hex")
  };
}
