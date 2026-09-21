import type { AnalysisConfidence, AnalysisFinding, AnalysisSeverity, EvidenceStrength, NativeAnalysisReport, ProtocolModel, SourceLocation } from "../analysis/model.js";
import type { SynthesizedInvariant } from "./invariantSynthesis.js";

export type ProvenanceKind =
  | "VERIFIED_SOURCE"
  | "DEPLOYED_BYTECODE"
  | "PINNED_STATE"
  | "STATIC_ANALYSIS"
  | "EXECUTION"
  | "HISTORICAL_AUDIT"
  | "BENCHMARK"
  | "MONITOR";

export type ProvenanceRecord = {
  id: string;
  kind: ProvenanceKind;
  observedAt: string;
  chainId?: number;
  blockNumber?: number;
  blockHash?: string;
  sourceRef?: string;
  digest?: string;
  note?: string;
};

export type KnowledgeNodeKind =
  | "PROTOCOL"
  | "CONTRACT"
  | "PROXY"
  | "IMPLEMENTATION"
  | "LIBRARY"
  | "ASSET"
  | "FUNCTION"
  | "ROLE"
  | "ORACLE"
  | "GOVERNANCE"
  | "TIMELOCK"
  | "FINDING"
  | "INVARIANT";

export type KnowledgeEdgeKind =
  | "CONTAINS"
  | "CALLS"
  | "DELEGATECALLS"
  | "UPGRADES_TO"
  | "USES_ASSET"
  | "READS_PRICE_FROM"
  | "CONTROLLED_BY"
  | "GOVERNS"
  | "HAS_FINDING"
  | "PROTECTED_BY"
  | "VIOLATES"
  | "DEPENDS_ON";

export type KnowledgeNode = {
  id: string;
  kind: KnowledgeNodeKind;
  label: string;
  contractRefId?: string;
  sourceLocation?: SourceLocation;
  category?: string;
  metadata?: Record<string, string | number | boolean | null>;
  provenance: string[];
};

export type KnowledgeEdge = {
  id: string;
  kind: KnowledgeEdgeKind;
  from: string;
  to: string;
  label?: string;
  sourceLocation?: SourceLocation;
  confidence: AnalysisConfidence;
  provenance: string[];
};

export type ProtocolKnowledgeGraph = {
  version: 1;
  protocolId: string;
  generatedAt: string;
  nodes: KnowledgeNode[];
  edges: KnowledgeEdge[];
  unresolvedEdges: number;
  provenance: ProvenanceRecord[];
  digest: string;
};

export type BytecodeAttestationStatus =
  | "SOURCE_RECOMPILED_EXACT"
  | "SOURCE_RECOMPILED_METADATA_EQUIVALENT"
  | "DEPLOYED_BYTECODE_OBSERVED"
  | "RECOMPILE_MISMATCH"
  | "NO_RUNTIME_CODE"
  | "UNAVAILABLE";

export type BytecodeAttestation = {
  version: 1;
  status: BytecodeAttestationStatus;
  observedRuntimeHash?: string;
  observedRuntimeBytes: number;
  compiledRuntimeHash?: string;
  compiledRuntimeBytes?: number;
  compilerVersion?: string;
  metadataStripped: boolean;
  comparedAt: string;
  limitations: string[];
};

export type SnapshotProbe = {
  id: string;
  kind: "STORAGE" | "CALL";
  value: string | null;
  success: boolean;
  error?: string;
};

export type ContractStateSnapshot = {
  contractRefId: string;
  codeHash: string;
  codeBytes: number;
  implementationSlot: string | null;
  adminSlot: string | null;
  beaconSlot: string | null;
  probes: SnapshotProbe[];
};

export type PinnedStateSnapshot = {
  version: 1;
  chainId: 1;
  blockNumber: number;
  blockHash: string;
  timestamp: number;
  capturedAt: string;
  contracts: ContractStateSnapshot[];
  digest: string;
  partial: boolean;
  limitations: string[];
};

export type InvariantCategory =
  | "GENERIC"
  | "VAULT"
  | "LENDING"
  | "AMM"
  | "DEX"
  | "BRIDGE"
  | "GOVERNANCE"
  | "STAKING"
  | "STABLECOIN"
  | "LIQUIDATION"
  | "UPGRADEABILITY";

export type InvariantExecutionKind =
  | "STRUCTURAL"
  | "STATE_SNAPSHOT"
  | "ECONOMIC_MODEL"
  | "FUZZ"
  | "SYMBOLIC"
  | "PINNED_FORK";

export type DefiInvariant = {
  id: string;
  title: string;
  category: InvariantCategory;
  statement: string;
  severityIfViolated: AnalysisSeverity;
  executionKinds: InvariantExecutionKind[];
  applicableCategories: string[];
  requiredSignals?: string[];
  rationale: string;
  source: "BUILT_IN";
};

export type SelectedInvariant = {
  invariant: DefiInvariant;
  confidence: AnalysisConfidence;
  rationale: string[];
};

export type EvidenceEscalationStage =
  | "STRUCTURAL_REVIEW"
  | "STATE_VALIDATION"
  | "FUZZ_OR_SYMBOLIC"
  | "MODEL_REPRODUCTION"
  | "PINNED_FORK_REPRODUCTION"
  | "ECONOMIC_IMPACT";

export type EvidenceEscalationStep = {
  stage: EvidenceEscalationStage;
  required: boolean;
  status: "PENDING" | "SATISFIED" | "BLOCKED" | "NOT_APPLICABLE";
  engine?: string;
  reason: string;
};

export type EvidenceEscalationPlan = {
  findingId: string;
  findingKind: string;
  currentEvidence: EvidenceStrength;
  targetEvidence: "STRUCTURAL" | "EXECUTED" | "REPRODUCED_MODEL" | "REPRODUCED_FORK";
  invariantIds: string[];
  steps: EvidenceEscalationStep[];
};

export type UpgradeChangeKind =
  | "RUNTIME_BYTECODE"
  | "IMPLEMENTATION"
  | "ADMIN"
  | "BEACON"
  | "STORAGE_LAYOUT"
  | "CALL_GRAPH"
  | "PRIVILEGED_SURFACE"
  | "ORACLE_DEPENDENCY"
  | "FINDING"
  | "INVARIANT";

export type UpgradeChange = {
  kind: UpgradeChangeKind;
  severity: AnalysisSeverity;
  title: string;
  before?: string;
  after?: string;
  evidence: string[];
};

export type UpgradeComparison = {
  version: 1;
  generatedAt: string;
  previousDigest: string;
  currentDigest: string;
  changed: boolean;
  changes: UpgradeChange[];
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type BenchmarkCorpus = "SMARTBUGS_CURATED" | "CVE_SMART_CONTRACTS" | "DEFIHACKLABS";

export type BenchmarkLabel = {
  category: string;
  lines?: number[];
  function?: string;
};

export type BenchmarkCase = {
  id: string;
  corpus: BenchmarkCorpus;
  sourcePath: string;
  labels: BenchmarkLabel[];
  reproducibleExploit?: boolean;
  metadata?: Record<string, string | number | boolean>;
};

export type BenchmarkPrediction = {
  caseId: string;
  findings: Array<{
    category: string;
    line?: number;
    severity?: AnalysisSeverity;
    evidenceStrength?: EvidenceStrength;
    reproduced?: boolean;
  }>;
  durationMs?: number;
};

export type BenchmarkMetrics = {
  corpus: BenchmarkCorpus | "MIXED";
  corpusCommits: Record<string, string>;
  generatedAt: string;
  caseCount: number;
  labeledPositiveCount: number;
  predictedPositiveCount: number;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegative: number;
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number | null;
  lineLocationAccuracy: number | null;
  reproductionRate: number | null;
  averageDurationMs: number | null;
};

export type MonitorChangeKind =
  | "CODE_CHANGED"
  | "IMPLEMENTATION_CHANGED"
  | "ADMIN_CHANGED"
  | "BEACON_CHANGED"
  | "PROBE_CHANGED";

export type MonitorChange = {
  kind: MonitorChangeKind;
  contractRefId: string;
  probeId?: string;
  before: string | null;
  after: string | null;
  severity: AnalysisSeverity;
};

export type MonitorDiff = {
  previousBlock: number;
  currentBlock: number;
  changed: boolean;
  changes: MonitorChange[];
};

export type AttackPathNode = {
  id: string;
  kind: "ENTRY" | "FUNCTION" | "CALL" | "STATE" | "ORACLE" | "ASSET" | "FINDING" | "IMPACT";
  label: string;
  sourceLocation?: SourceLocation;
};

export type AttackPathEdge = {
  from: string;
  to: string;
  label?: string;
};

export type AttackPath = {
  id: string;
  findingId: string;
  severity: AnalysisSeverity;
  evidenceStrength: EvidenceStrength;
  title: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  limitations: string[];
};

export type ProtocolIntelligenceBundle = {
  version: 1;
  generatedAt: string;
  graph: ProtocolKnowledgeGraph;
  invariants: SelectedInvariant[];
  synthesizedInvariants: SynthesizedInvariant[];
  escalationPlans: EvidenceEscalationPlan[];
  attackPaths: AttackPath[];
  protocolModelDigest: string;
};

export type ProtocolIntelligenceInput = {
  protocolId: string;
  label: string;
  contractInspections: Array<{
    contractRefId: string;
    rootContractRefId?: string;
    sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
    contractName?: string;
    proxy: boolean;
    protocolModel: ProtocolModel;
    findings: AnalysisFinding[];
    nativeAnalysis?: NativeAnalysisReport;
  }>;
};
