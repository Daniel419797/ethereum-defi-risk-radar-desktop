import { createHash } from "node:crypto";
import type { Candidate, ContractInspectionSummary } from "../types.js";
import type { AnalysisFinding, ProtocolCallEdge } from "../analysis/model.js";
import type {
  AttackPath,
  AttackPathStep,
  ProtocolGraphEdge,
  ProtocolGraphNode,
  ProtocolKnowledgeGraph,
  ProvenanceRecord
} from "./model.js";

function id(...parts: Array<string | number | undefined>) {
  return createHash("sha256")
    .update(parts.map(part => String(part ?? "")).join("|"))
    .digest("hex")
    .slice(0, 20);
}

function provenance(
  source: ProvenanceRecord["source"],
  detail: string,
  confidence: ProvenanceRecord["confidence"] = "HIGH"
): ProvenanceRecord {
  return { source, detail, confidence, observedAt: new Date().toISOString() };
}

function node(
  graph: Map<string, ProtocolGraphNode>,
  value: ProtocolGraphNode
) {
  const existing = graph.get(value.id);
  if (!existing) {
    graph.set(value.id, value);
    return;
  }
  existing.provenance.push(...value.provenance);
  existing.attributes = { ...existing.attributes, ...value.attributes };
}

function edge(
  graph: Map<string, ProtocolGraphEdge>,
  value: Omit<ProtocolGraphEdge, "id">
) {
  const edgeId = id(value.from, value.kind, value.to, value.location?.file, value.location?.line);
  if (!graph.has(edgeId)) graph.set(edgeId, { ...value, id: edgeId });
}

function contractNodeId(contractRefId: string) {
  return `contract:${contractRefId}`;
}

function sourceContractNodeId(contractRefId: string, localId: string) {
  return `source:${contractRefId}:${id(localId)}`;
}

function findingNodeId(contractRefId: string, findingId: string) {
  return `finding:${contractRefId}:${findingId}`;
}

function graphEdgeKind(call: ProtocolCallEdge): ProtocolGraphEdge["kind"] {
  if (call.operation === "delegatecall") return "DELEGATECALLS";
  if (call.operation === "staticcall") return "STATICCALLS";
  return "CALLS";
}

function flattenAdvancedFindings(inspection: ContractInspectionSummary) {
  return inspection.inspection.advancedAnalysis.findings;
}

function addInspection(
  protocolNodeId: string,
  inspection: ContractInspectionSummary,
  nodes: Map<string, ProtocolGraphNode>,
  edges: Map<string, ProtocolGraphEdge>
) {
  const contractId = contractNodeId(inspection.contractRefId);
  const role = inspection.sourceRole ?? (inspection.proxy ? "PROXY" : "DIRECT");
  node(nodes, {
    id: contractId,
    kind: role === "PROXY" ? "proxy" : role === "IMPLEMENTATION" ? "implementation" : "contract",
    label: inspection.contractName || inspection.contractRefId,
    contractRefId: inspection.contractRefId,
    sourceRole: role,
    attributes: {
      compilerVersion: inspection.compilerVersion ?? null,
      proxy: inspection.proxy,
      sourceFiles: inspection.inspection.filesInspected,
      sourceBytes: inspection.inspection.sourceBytesInspected,
      findingCount:
        inspection.inspection.advancedAnalysis.findings.length +
        inspection.inspection.findings.length
    },
    provenance: [
      provenance("etherscan", "Contract identity and verified-source metadata returned by Etherscan."),
      provenance("verified_source", "Contract was inspected from verified Solidity source.")
    ]
  });
  edge(edges, {
    from: protocolNodeId,
    to: contractId,
    kind: "CONTAINS",
    confidence: "HIGH",
    provenance: [provenance("verified_source", "Verified contract belongs to the resolved protocol candidate.")]
  });

  for (const local of inspection.inspection.protocolModel.contracts.slice(0, 256)) {
    const localId = sourceContractNodeId(inspection.contractRefId, local.id);
    node(nodes, {
      id: localId,
      kind: "contract",
      label: local.name,
      contractRefId: inspection.contractRefId,
      category: local.category,
      file: local.file,
      attributes: {
        solidityKind: local.kind,
        storageVariableCount: local.storageVariables.length
      },
      provenance: [provenance("native_analysis", "Source-linked contract node produced by the native protocol model.")]
    });
    edge(edges, {
      from: contractId,
      to: localId,
      kind: "CONTAINS",
      confidence: "HIGH",
      provenance: [provenance("native_analysis", "Local source contract is contained in the verified contract source bundle.")]
    });
  }

  for (const asset of inspection.inspection.protocolModel.assets.slice(0, 128)) {
    const assetId = `asset:${id(asset.toLowerCase())}`;
    node(nodes, {
      id: assetId,
      kind: "asset",
      label: asset,
      attributes: {},
      provenance: [provenance("native_analysis", "Asset surface inferred from verified source identifiers.", "MEDIUM")]
    });
    edge(edges, {
      from: contractId,
      to: assetId,
      kind: "USES_ASSET",
      confidence: "MEDIUM",
      provenance: [provenance("native_analysis", "Verified source references this asset surface.", "MEDIUM")]
    });
  }

  for (const call of inspection.inspection.protocolModel.calls.slice(0, 512)) {
    const fromLocal = sourceContractNodeId(inspection.contractRefId, call.from);
    const targetLocal = call.to
      ? sourceContractNodeId(inspection.contractRefId, call.to)
      : `external:${inspection.contractRefId}:${id(call.targetExpression)}`;

    if (!nodes.has(fromLocal)) {
      node(nodes, {
        id: fromLocal,
        kind: "contract",
        label: call.from,
        contractRefId: inspection.contractRefId,
        attributes: {},
        provenance: [provenance("native_analysis", "Call-graph source node inferred from verified source.", "MEDIUM")]
      });
    }

    if (!nodes.has(targetLocal)) {
      node(nodes, {
        id: targetLocal,
        kind: call.to ? "contract" : "external_protocol",
        label: call.to || call.targetExpression,
        contractRefId: call.to ? inspection.contractRefId : undefined,
        attributes: { resolved: call.resolved },
        provenance: [
          provenance(
            "native_analysis",
            call.resolved ? "Call target resolved from source type information." : "Unresolved external call target.",
            call.resolved ? "HIGH" : "LOW"
          )
        ]
      });
    }

    edge(edges, {
      from: fromLocal,
      to: targetLocal,
      kind: graphEdgeKind(call),
      label: call.targetExpression,
      location: call.location,
      confidence: call.resolved ? "HIGH" : "LOW",
      provenance: [provenance("native_analysis", "Cross-contract call edge derived from verified source.")]
    });
  }

  for (const finding of flattenAdvancedFindings(inspection).slice(0, 512)) {
    const findingId = findingNodeId(inspection.contractRefId, finding.id);
    node(nodes, {
      id: findingId,
      kind: "finding",
      label: finding.title,
      contractRefId: inspection.contractRefId,
      location: finding.primaryLocation,
      attributes: {
        kind: finding.kind,
        severity: finding.severity,
        confidence: finding.confidence,
        evidenceStrength: finding.evidenceStrength,
        exploitabilityVerdict: finding.exploitabilityVerdict ?? "UNKNOWN"
      },
      provenance: [provenance("native_analysis", "Security finding emitted by verified-source analysis.")]
    });
    edge(edges, {
      from: contractId,
      to: findingId,
      kind: "EXPOSES",
      location: finding.primaryLocation,
      confidence: finding.confidence,
      provenance: [provenance("native_analysis", "Finding is associated with this verified contract.")]
    });

    if (finding.kind === "oracle_risk") {
      const oracleId = `oracle:${inspection.contractRefId}:${id(finding.id)}`;
      node(nodes, {
        id: oracleId,
        kind: "oracle",
        label: "Oracle / price dependency",
        contractRefId: inspection.contractRefId,
        attributes: {},
        provenance: [provenance("native_analysis", "Oracle surface inferred from a source-linked finding.", "MEDIUM")]
      });
      edge(edges, {
        from: contractId,
        to: oracleId,
        kind: "READS_PRICE_FROM",
        confidence: "MEDIUM",
        provenance: [provenance("native_analysis", "Oracle relationship inferred from source-linked security analysis.", "MEDIUM")]
      });
    }

    if (finding.kind === "governance_risk" || finding.kind === "authorization" || finding.kind === "upgradeability") {
      const governanceId = `governance:${inspection.contractRefId}`;
      node(nodes, {
        id: governanceId,
        kind: "governance",
        label: "Privilege / governance control",
        contractRefId: inspection.contractRefId,
        attributes: {},
        provenance: [provenance("native_analysis", "Governance or privilege surface inferred from verified source.", "MEDIUM")]
      });
      edge(edges, {
        from: governanceId,
        to: contractId,
        kind: finding.kind === "upgradeability" ? "UPGRADES" : "CONTROLS",
        confidence: "MEDIUM",
        provenance: [provenance("native_analysis", "Control relationship inferred from source-linked security analysis.", "MEDIUM")]
      });
    }
  }
}

function linkProxyImplementations(
  inspections: ContractInspectionSummary[],
  edges: Map<string, ProtocolGraphEdge>
) {
  const byRoot = new Map<string, ContractInspectionSummary[]>();
  for (const inspection of inspections) {
    const root = inspection.rootContractRefId ?? inspection.contractRefId;
    const group = byRoot.get(root) ?? [];
    group.push(inspection);
    byRoot.set(root, group);
  }

  for (const group of byRoot.values()) {
    const proxy = group.find(item => item.sourceRole === "PROXY" || item.proxy);
    const implementations = group.filter(item => item.sourceRole === "IMPLEMENTATION");
    if (!proxy) continue;
    for (const implementation of implementations) {
      edge(edges, {
        from: contractNodeId(proxy.contractRefId),
        to: contractNodeId(implementation.contractRefId),
        kind: "IMPLEMENTS",
        confidence: "HIGH",
        provenance: [provenance("etherscan", "Proxy implementation relationship resolved through verified explorer metadata.")]
      });
    }
  }
}

export function buildProtocolKnowledgeGraph(candidate: Candidate): ProtocolKnowledgeGraph {
  const nodes = new Map<string, ProtocolGraphNode>();
  const edges = new Map<string, ProtocolGraphEdge>();
  const protocolNodeId = `protocol:${candidate.id}`;

  node(nodes, {
    id: protocolNodeId,
    kind: "protocol",
    label: candidate.label,
    attributes: {
      chainId: 1,
      network: "ethereum-mainnet",
      researchScore: candidate.researchScore,
      ethereumConfidence: candidate.ethereumConfidence,
      classification: candidate.classification
    },
    provenance: [
      provenance("etherscan", "Protocol candidate was promoted only after verified Ethereum Mainnet source resolution."),
      provenance("verified_source", "Knowledge graph is anchored to verified source inspections.")
    ]
  });

  for (const inspection of candidate.ethereum.sourceInspections.slice(0, 128)) {
    addInspection(protocolNodeId, inspection, nodes, edges);
  }
  linkProxyImplementations(candidate.ethereum.sourceInspections, edges);

  const categories = new Set<string>();
  const assets = new Set<string>();
  let unresolvedEdges = 0;
  for (const inspection of candidate.ethereum.sourceInspections) {
    for (const category of inspection.inspection.protocolModel.categories) categories.add(category);
    for (const asset of inspection.inspection.protocolModel.assets) assets.add(asset);
    unresolvedEdges += inspection.inspection.protocolModel.unresolvedCallCount;
  }

  const sortedNodes = [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id));
  const sortedEdges = [...edges.values()].sort((a, b) => a.id.localeCompare(b.id));
  const graphHash = createHash("sha256").update(JSON.stringify({
    protocolId: candidate.id,
    nodes: sortedNodes.map(({ provenance: _provenance, ...rest }) => rest),
    edges: sortedEdges.map(({ provenance: _provenance, ...rest }) => rest),
    unresolvedEdges,
    categories: [...categories].sort(),
    assets: [...assets].sort()
  })).digest("hex");

  return {
    schemaVersion: 1,
    protocolId: candidate.id,
    protocolLabel: candidate.label,
    generatedAt: new Date().toISOString(),
    nodes: sortedNodes,
    edges: sortedEdges,
    unresolvedEdges,
    categories: [...categories].sort(),
    assets: [...assets].sort(),
    graphHash
  };
}

function findingById(candidate: Candidate, findingId: string) {
  for (const inspection of candidate.ethereum.sourceInspections) {
    const finding = inspection.inspection.advancedAnalysis.findings.find(item => item.id === findingId);
    if (finding) return { inspection, finding };
  }
  return undefined;
}

function uniqueSteps(steps: AttackPathStep[]) {
  const seen = new Set<string>();
  return steps.filter(step => {
    const key = [step.kind, step.label, step.contractRefId, step.location?.file, step.location?.line].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function buildAttackPath(candidate: Candidate, finding: AnalysisFinding): AttackPath {
  const resolved = findingById(candidate, finding.id);
  const contractRefId = resolved?.inspection.contractRefId;
  const steps: AttackPathStep[] = [];

  if (finding.reachableFromExternalEntry !== false) {
    steps.push({
      id: id(finding.id, "entry"),
      kind: "ENTRY",
      label: finding.reachableFromExternalEntry ? "Externally reachable entry point" : "External reachability not disproven",
      contractRefId,
      location: finding.witnessPath?.[0]?.location ?? finding.primaryLocation,
      evidence: finding.reachableFromExternalEntry ? "Native reachability analysis" : "Reachability remains unknown"
    });
  }

  for (const witness of finding.witnessPath ?? []) {
    steps.push({
      id: id(finding.id, witness.role, witness.symbol, witness.location.file, witness.location.line),
      kind: witness.role === "sink" ? "STATE" : "CALL",
      label: witness.symbol,
      contractRefId,
      location: witness.location,
      evidence: witness.detail || `Witness ${witness.role}`
    });
  }

  if (finding.kind === "oracle_risk") {
    steps.push({
      id: id(finding.id, "oracle"),
      kind: "ORACLE",
      label: "Oracle / price dependency",
      contractRefId,
      location: finding.primaryLocation,
      evidence: "Source-linked oracle-risk finding"
    });
  }

  if (["authorization", "upgradeability", "governance_risk"].includes(finding.kind)) {
    steps.push({
      id: id(finding.id, "privilege"),
      kind: "PRIVILEGE",
      label: "Privilege / governance boundary",
      contractRefId,
      location: finding.primaryLocation,
      evidence: "Source-linked privilege or upgradeability finding"
    });
  }

  if (finding.counterexample?.invariantId) {
    steps.push({
      id: id(finding.id, "invariant", finding.counterexample.invariantId),
      kind: "INVARIANT",
      label: finding.counterexample.invariantId,
      contractRefId,
      evidence: finding.counterexample.observedViolation
    });
  }

  if (finding.counterexample?.observedViolation) {
    steps.push({
      id: id(finding.id, "impact"),
      kind: "IMPACT",
      label: finding.counterexample.observedViolation.slice(0, 220),
      contractRefId,
      evidence: finding.exploitabilityVerdict ?? finding.evidenceStrength
    });
  }

  if (!steps.length) {
    steps.push({
      id: id(finding.id, "finding"),
      kind: "STATE",
      label: finding.title,
      contractRefId,
      location: finding.primaryLocation,
      evidence: finding.description
    });
  }

  return {
    id: id(candidate.id, finding.id, "attack-path"),
    findingId: finding.id,
    severity: finding.severity,
    title: finding.title,
    evidenceStrength: finding.evidenceStrength,
    exploitabilityVerdict: finding.exploitabilityVerdict,
    steps: uniqueSteps(steps).slice(0, 64)
  };
}

export function buildAttackPaths(candidate: Candidate) {
  const findings = candidate.ethereum.sourceInspections.flatMap(inspection =>
    inspection.inspection.advancedAnalysis.findings
  );
  return findings
    .filter(finding =>
      finding.severity === "CRITICAL" ||
      finding.severity === "HIGH" ||
      finding.evidenceStrength === "EXECUTED" ||
      finding.evidenceStrength === "REPRODUCED"
    )
    .map(finding => buildAttackPath(candidate, finding))
    .slice(0, 128);
}
