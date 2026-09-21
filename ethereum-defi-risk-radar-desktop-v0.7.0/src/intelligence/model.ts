import type {
  AnalysisEngineId,
  AnalysisFinding,
  AnalysisSeverity,
  EvidenceStrength,
  ProtocolModel,
  SourceLocation,
  StorageSurface
} from "../analysis/model.js";

export type ProtocolNodeKind =
  | "protocol"
  | "contract"
  | "proxy"
  | "implementation"
  | "asset"
  | "oracle"
  | "governance"
  | "role"
  | "external_protocol"
  | "finding"
  | "invariant";

export type ProtocolEdgeKind =
  | "CONTAINS"
  | "IMPLEMENTS"
  | "CALLS"
  | "DELEGATECALLS"
  | "STATICCALLS"
  | "TRANSFERS_TO"
  | "READS_PRICE_FROM"
  | "GOVERNS"
  | "CONTROLS"
  | "UPGRADES"
  | "USES_ASSET"
  | "EXPOSES"
  | "VIOLATES"
  | "DEPENDS_ON";

export type ProvenanceRecord = {
  source: "etherscan" | "rpc" | "verified_source" | "native_analysis" | "historical_audit" | "benchmark" | "local_artifact";
  observedAt: string;
  detail: string;
  blockNumber?: number;
  blockHash?: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
};

export type ProtocolGraphNode = {
  id: string;
  kind: ProtocolNodeKind;
  label: string;
  contractRefId?: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  category?: string;
  file?: string;
  location?: SourceLocation;
  attributes?: Record<string, string | number | boolean | null>;
  provenance: ProvenanceRecord[];
};

export type ProtocolGraphEdge = {
  id: string;
  from: string;
  to: string;
  kind: ProtocolEdgeKind;
  label?: string;
  location?: SourceLocation;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  provenance: ProvenanceRecord[];
};

export type ProtocolKnowledgeGraph = {
  schemaVersion: 1;
  protocolId: string;
  protocolLabel: string;
  generatedAt: string;
  nodes: ProtocolGraphNode[];
  edges: ProtocolGraphEdge[];
  unresolvedEdges: number;
  categories: string[];
  assets: string[];
  graphHash: string;
};

export type BytecodeAttestationStatus =
  | "EXACT"
  | "METADATA_ONLY_DIFFERENCE"
  | "EXPLORER_VERIFIED_RUNTIME_OBSERVED"
  | "MISMATCH"
  | "NO_CODE"
  | "UNAVAILABLE";

export type BytecodeAttestation = {
  contractRefId: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  status: BytecodeAttestationStatus;
  observedAt: string;
  blockNumber: number;
  blockHash: string;
  observedCodeSha256?: string;
  expectedCodeSha256?: string;
  observedRuntimeBytes: number;
  expectedRuntimeBytes?: number;
  compilerVersion?: string;
  sourceSha256?: string;
  explorerVerified: boolean;
  locallyCompiled: boolean;
  metadataStrippedMatch: boolean;
  limitations: string[];
};

export type SnapshotStorageObservation = {
  slot: string;
  label: string;
  value: string;
};

export type SnapshotCallObservation = {
  id: string;
  toRefId: string;
  data: string;
  result?: string;
  error?: string;
};

export type ContractStateSnapshot = {
  contractRefId: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  codeSha256: string;
  codeBytes: number;
  storage: SnapshotStorageObservation[];
  calls: SnapshotCallObservation[];
};

export type PinnedStateSnapshot = {
  schemaVersion: 1;
  chainId: 1;
  network: "ethereum-mainnet";
  capturedAt: string;
  blockNumber: number;
  blockHash: string;
  parentHash?: string;
  timestamp?: number;
  confirmationsFromHead: number;
  contracts: ContractStateSnapshot[];
  snapshotHash: string;
};

export type ProtocolIntelligenceBundle = {
  graph: ProtocolKnowledgeGraph;
  snapshot?: PinnedStateSnapshot;
  attestations: BytecodeAttestation[];
  generatedAt: string;
};

export type InvariantCategory =
  | "vault"
  | "lending"
  | "amm"
  | "dex"
  | "staking"
  | "bridge"
  | "governance"
  | "stablecoin"
  | "derivatives"
  | "yield_aggregator"
  | "token_wrapper"
  | "liquidation"
  | "generic";

export type InvariantCheckKind =
  | "STRUCTURAL"
  | "STATE"
  | "ECONOMIC"
  | "FUZZ"
  | "SYMBOLIC"
  | "FORK_REPLAY";

export type InvariantDefinition = {
  id: string;
  title: string;
  description: string;
  categories: InvariantCategory[];
  severity: AnalysisSeverity;
  checks: InvariantCheckKind[];
  rationale: string;
  remediationHint: string;
  sourceKinds: string[];
  requiredGraphKinds?: ProtocolNodeKind[];
  generatedProperty: string;
};

export type InvariantApplicability = {
  invariantId: string;
  state: "APPLICABLE" | "NOT_APPLICABLE";
  reasons: string[];
  contractRefIds: string[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
};

export type EvidenceEscalationStep = {
  order: number;
  stage: "STRUCTURAL" | "FUZZ" | "SYMBOLIC" | "MODEL_REPLAY" | "FORK_REPLAY" | "ECONOMIC_IMPACT";
  engine?: AnalysisEngineId;
  automatic: boolean;
  requiresTrust: boolean;
  requiresRpc: boolean;
  description: string;
  successEvidence: EvidenceStrength | "CONFIRMED_AT_PINNED_BLOCK";
};

export type EvidenceEscalationPlan = {
  findingId: string;
  invariantIds: string[];
  currentEvidence: EvidenceStrength;
  strongestEvidence: EvidenceStrength;
  correlatedEngines: AnalysisEngineId[];
  steps: EvidenceEscalationStep[];
  stoppedReason?: string;
};

export type UpgradeChangeKind =
  | "IMPLEMENTATION_CHANGED"
  | "ADMIN_CHANGED"
  | "BEACON_CHANGED"
  | "RUNTIME_CODE_CHANGED"
  | "STORAGE_ADDED"
  | "STORAGE_REMOVED"
  | "STORAGE_TYPE_CHANGED"
  | "EXTERNAL_CALL_ADDED"
  | "DELEGATECALL_ADDED"
  | "PRIVILEGE_SURFACE_ADDED"
  | "MITIGATION_REMOVED"
  | "NEW_FINDING"
  | "FINDING_RESOLVED"
  | "GRAPH_EDGE_ADDED"
  | "GRAPH_EDGE_REMOVED";

export type UpgradeChange = {
  id: string;
  kind: UpgradeChangeKind;
  severity: AnalysisSeverity;
  contractRefId?: string;
  summary: string;
  before?: string;
  after?: string;
  location?: SourceLocation;
  evidence: string[];
};

export type UpgradeComparison = {
  generatedAt: string;
  fromBlock?: number;
  toBlock?: number;
  changes: UpgradeChange[];
  highImpactChanges: number;
  storageCompatibility: "UNCHANGED" | "ADDITIVE" | "REVIEW_REQUIRED" | "UNKNOWN";
  implementationChanged: boolean;
  assumptions: string[];
};

export type BenchmarkDataset = "SMARTBUGS_CURATED" | "CVE_SMART_CONTRACTS" | "DEFIHACKLABS";

export type BenchmarkCase = {
  id: string;
  dataset: BenchmarkDataset;
  sourcePath: string;
  sourceText?: string;
  expectedKinds: string[];
  vulnerableLines: number[];
  negative: boolean;
  reproduction?: {
    command: string;
    args: string[];
    workingDirectory: string;
  };
  metadata: Record<string, string | number | boolean | null>;
};

export type BenchmarkCaseResult = {
  id: string;
  dataset: BenchmarkDataset;
  expectedKinds: string[];
  observedKinds: string[];
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegative: boolean;
  locationHits: number;
  locationExpected: number;
  reproductionAttempted: boolean;
  reproductionPassed?: boolean;
  durationMs: number;
  errors: string[];
};

export type BenchmarkMetrics = {
  generatedAt: string;
  datasets: BenchmarkDataset[];
  cases: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  falsePositiveRate: number | null;
  locationRecall: number | null;
  reproductionRate: number | null;
  totalDurationMs: number;
  results: BenchmarkCaseResult[];
  provenance: Array<{ dataset: BenchmarkDataset; revision?: string; licenseNote: string }>;
};

export type MonitorTarget = {
  id: string;
  protocolId: string;
  label: string;
  rpcUrl: string;
  confirmations: number;
  contracts: Array<{
    address: string;
    contractRefId: string;
    sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
    compilerVersion?: string;
    explorerVerified?: boolean;
    sourceSha256?: string;
  }>;
};

export type MonitorEventKind =
  | "IMPLEMENTATION_CHANGED"
  | "ADMIN_CHANGED"
  | "BEACON_CHANGED"
  | "RUNTIME_CODE_CHANGED"
  | "STATE_CHANGED"
  | "NEW_BLOCK_BASELINE"
  | "MONITOR_ERROR";

export type MonitorEvent = {
  id: string;
  targetId: string;
  kind: MonitorEventKind;
  observedAt: string;
  severity: AnalysisSeverity;
  summary: string;
  blockNumber?: number;
  blockHash?: string;
  contractRefId?: string;
  before?: string;
  after?: string;
};

export type MonitorState = {
  schemaVersion: 1;
  target: Omit<MonitorTarget, "rpcUrl">;
  latestSnapshot?: PinnedStateSnapshot;
  events: MonitorEvent[];
  updatedAt: string;
};

export type AttackPathStep = {
  id: string;
  kind: "ENTRY" | "CALL" | "STATE" | "ORACLE" | "PRIVILEGE" | "INVARIANT" | "IMPACT";
  label: string;
  contractRefId?: string;
  location?: SourceLocation;
  evidence: string;
};

export type AttackPath = {
  id: string;
  findingId: string;
  severity: AnalysisSeverity;
  title: string;
  evidenceStrength: EvidenceStrength;
  exploitabilityVerdict?: AnalysisFinding["exploitabilityVerdict"];
  steps: AttackPathStep[];
};

export type VersionedProtocolFacts = {
  snapshot?: PinnedStateSnapshot;
  graph: ProtocolKnowledgeGraph;
  findings: AnalysisFinding[];
  storage: StorageSurface[];
  protocolModels: ProtocolModel[];
};
