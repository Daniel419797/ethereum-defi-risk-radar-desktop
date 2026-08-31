export type AnalysisEngineId =
  | "native"
  | "slither"
  | "mythril"
  | "foundry"
  | "anvil"
  | "echidna";

export type AnalysisKind =
  | "control_flow"
  | "data_flow"
  | "taint"
  | "symbolic_execution"
  | "fuzzing"
  | "invariant_testing"
  | "storage_state"
  | "cross_contract_calls"
  | "economic_simulation"
  | "authorization"
  | "reentrancy"
  | "oracle_risk"
  | "signature_replay"
  | "arithmetic_precision"
  | "denial_of_service"
  | "upgradeability"
  | "mev_ordering"
  | "governance_risk"
  | "bridge_messaging"
  | "token_integration";

export type EvidenceStrength = "HEURISTIC" | "STRUCTURAL" | "EXECUTED" | "REPRODUCED";
export type AnalysisConfidence = "LOW" | "MEDIUM" | "HIGH";
export type AnalysisSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * Scope of a REPRODUCED claim. `model` means a counterexample replayed deterministically
 * against this project's own model; it says nothing about deployed bytecode. `fork` means it
 * replayed against forked chain state and is the only scope that is evidence about deployed
 * code. A REPRODUCED finding must always carry one, so that the rendered label can never be
 * a bare "reproduced".
 */
export type EvidenceScope = "model" | "fork";

/**
 * A concrete artifact that justifies an EXECUTED or REPRODUCED claim. Holding one is the
 * only way to earn those rungs; engine identity never grants them.
 */
export type Counterexample = {
  engine: AnalysisEngineId;
  scope: EvidenceScope;
  /** Ordered calls/transactions that drive the system into the violating state. */
  sequence: string[];
  /** What was observed to break, in the model's or the chain's own terms. */
  observedViolation: string;
  inputs?: Record<string, string>;
  invariantId?: string;
  /** Seed that makes a fuzzed sequence replayable. */
  seed?: number;
  /** Fork block height; only meaningful for `scope: "fork"`. */
  blockNumber?: number;
  /**
   * Opaque handle for a reproduction artifact written to a separate, explicitly requested
   * file. Never the artifact itself: reports are address-redacted and must stay that way.
   */
  artifactRef?: string;
};

export type MitigationKind =
  | "access_control"
  | "reentrancy_guard"
  | "checked_arithmetic"
  | "deadline_check"
  | "slippage_check"
  | "staleness_check"
  | "return_value_check";

/**
 * A guard observed to dominate the risky operation on every path reaching it. Presence
 * downgrades or suppresses a rule rather than being ignored.
 */
export type Mitigation = {
  kind: MitigationKind;
  evidence: string;
  location?: SourceLocation;
};

/** One hop of a source-to-sink witness, so a STRUCTURAL claim stays auditable. */
export type WitnessStep = {
  symbol: string;
  role: "source" | "propagation" | "sink";
  location: SourceLocation;
  detail?: string;
};

/**
 * Records findings a cap suppressed. Suppression is reported rather than silent, because
 * "absence of evidence is never presented as a pass".
 */
export type TruncationRecord = {
  ruleId: string;
  dropped: number;
  limit: number;
};
export type EngineRunState =
  | "queued"
  | "running"
  | "complete"
  | "partial"
  | "failed"
  | "timed_out"
  | "cancelled"
  | "unavailable";

export type SourceLocation = { file: string; line: number; column?: number };

export type AnalysisFinding = {
  id: string;
  kind: AnalysisKind;
  engine: AnalysisEngineId;
  severity: AnalysisSeverity;
  confidence: AnalysisConfidence;
  evidenceStrength: EvidenceStrength;
  title: string;
  description: string;
  remediation?: string;
  primaryLocation?: SourceLocation;
  relatedLocations?: SourceLocation[];
  evidencePath?: string[];
  limitations: string[];
  /** Required for EXECUTED and REPRODUCED; absent means the rung was not earned. */
  counterexample?: Counterexample;
  /** Required whenever `evidenceStrength` is REPRODUCED. */
  evidenceScope?: EvidenceScope;
  /** Guards observed to dominate the risky operation. */
  mitigations?: Mitigation[];
  /** Source-to-sink hops backing a taint or reachability claim. */
  witnessPath?: WitnessStep[];
  /**
   * Whether an externally callable function can reach this location. `false` is a strong
   * severity downgrade; `undefined` means the question was not decided.
   */
  reachableFromExternalEntry?: boolean;
  /** Engines that independently reported the same kind at the same location. */
  correlatedEngines?: AnalysisEngineId[];
};

export type GraphNode = {
  id: string;
  kind:
    | "function"
    | "entry"
    | "statement"
    | "branch"
    | "loop"
    | "call"
    | "return"
    | "join"
    | "loop_exit"
    | "revert"
    | "catch"
    | "exit";
  label: string;
  location?: SourceLocation;
  /** False when no path from the graph entry reaches this node (FR-1 unreachable signal). */
  reachable?: boolean;
};

export type GraphEdge = {
  from: string;
  to: string;
  kind:
    | "next"
    | "true"
    | "false"
    | "loop"
    | "internal_call"
    | "external_call"
    | "delegate_call"
    | "back_edge"
    | "loop_exit"
    | "exception"
    | "abrupt";
};

export type AnalysisGraph = {
  id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  entryId?: string;
  /** Immediate dominator per node id; `null` for the entry. Backs "guard dominates sink". */
  immediateDominators?: Record<string, string | null>;
  unreachableNodeIds?: string[];
};

export type DataDependency = {
  variable: string;
  definedAt: SourceLocation;
  usedAt: SourceLocation[];
  dependsOn: string[];
  stateVariable: boolean;
  /** CFG block holding the definition, for dominance queries. */
  blockId?: string;
  /** True when `dependsOn` is a transitive closure rather than direct operands only. */
  transitive?: boolean;
};

export type StorageSurface = {
  variable: string;
  declaredAt: SourceLocation;
  typeHint: string;
  visibility?: string;
  /**
   * Best-effort slot index. Named "approximate" deliberately: only a solc-provided layout is
   * authoritative (see `NativeAnalysisReport.layoutAuthoritative`).
   */
  approximateSlot: number;
  dynamic: boolean;
  writtenBy: string[];
  /** Byte offset within the 32-byte word, for packed variables. */
  byteOffset?: number;
  /** Size in bytes, or `undefined` when the type could not be sized. */
  byteSize?: number;
  /** Constants and immutables occupy no storage slot at all. */
  occupiesSlot?: boolean;
  declaringContract?: string;
  /** Set when the declaration matches a standardized proxy slot. */
  proxySlotStandard?: "eip1967_implementation" | "eip1967_admin" | "eip1967_beacon" | "eip1822";
};

export type StorageCollision = {
  slot: number;
  left: { contract: string; variable: string; typeHint: string };
  right: { contract: string; variable: string; typeHint: string };
  reason: "type_mismatch" | "proxy_overlap" | "reordered_inheritance";
};

export type CrossContractCall = {
  caller: string;
  targetExpression: string;
  operation: "call" | "staticcall" | "delegatecall" | "send" | "transfer";
  valueBearing: boolean;
  location: SourceLocation;
  returnValueChecked: boolean;
  /** Enclosing function, for interprocedural reasoning. */
  functionName?: string;
  /** Guards that dominate this call site. */
  guardedBy?: Mitigation[];
  /** State variables written after this call on some path — the reentrancy precondition. */
  stateWritesAfter?: string[];
  /** Resolved callee when the target's type could be determined. */
  resolvedInterface?: string;
};

export type NativeAnalysisReport = {
  engine: "native";
  analyzedAt: string;
  filesAnalyzed: number;
  functionsAnalyzed: number;
  graphs: AnalysisGraph[];
  dependencies: DataDependency[];
  storage: StorageSurface[];
  calls: CrossContractCall[];
  findings: AnalysisFinding[];
  limitations: string[];
  /** Findings a cap suppressed, reported instead of dropped silently. */
  truncations?: TruncationRecord[];
  /** Which front end produced these facts. */
  parseBasis?: "tokens" | "solc";
  /**
   * True only when the storage layout came from solc. The token front end cannot resolve
   * inline-assembly slot targets, foreign library structs, or diamond C3 order with
   * certainty, so it always reports false.
   */
  layoutAuthoritative?: boolean;
  /** True when a budget, cap, or cancellation stopped the analysis early. */
  partial?: boolean;
  storageCollisions?: StorageCollision[];
  notes?: string[];
};

export type ToolCapability = {
  id: AnalysisEngineId | "python" | "docker";
  available: boolean;
  executable?: string;
  version?: string;
  reason?: string;
};

export type AnalysisBudget = {
  timeoutMs: number;
  maxOutputBytes: number;
  maxFindings: number;
  maxPaths: number;
  maxSimulationSteps: number;
  /** Upper bound on concurrently spawned analyzer processes (NFR-5). */
  maxProcessConcurrency?: number;
  /** Seed passed to fuzzers and the economic PRNG so runs are replayable. */
  seed?: number;
};

export type AnalysisTarget =
  | { type: "verified_source"; chainId: 1; addressRef: string; sources: Array<{ name: string; content: string }>; trustedForExecution?: boolean }
  | { type: "local_project"; path: string; framework: "foundry" | "hardhat" | "unknown"; trusted: boolean };

export type EngineRunResult = {
  engine: AnalysisEngineId;
  state: EngineRunState;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  version?: string;
  findings: AnalysisFinding[];
  diagnostics: string[];
  exitCode?: number | null;
  truncated: boolean;
  /** Why an engine was skipped, so an unavailable engine is visible rather than absent. */
  unavailableReason?: string;
  /** True when output was produced but could not be parsed into findings. */
  outputUnparsed?: boolean;
  /** Normalized rows omitted because a configured finding cap was reached. */
  truncations?: TruncationRecord[];
};

export type AnalysisPlan = {
  target: AnalysisTarget;
  engines: AnalysisEngineId[];
  budget: AnalysisBudget;
  signal?: AbortSignal;
};

export type ProtocolContractNode = { id: string; name: string; file: string; category: string; kind: "contract" | "interface" | "library"; storageVariables: string[] };
export type ProtocolCallEdge = { from: string; to?: string; targetExpression: string; operation: string; location: SourceLocation; resolved: boolean };
export type ProtocolModel = { contracts: ProtocolContractNode[]; calls: ProtocolCallEdge[]; assets: string[]; categories: string[]; unresolvedCallCount: number; assumptions: string[] };

export type AnalysisRunReport = {
  targetType: AnalysisTarget["type"];
  capabilities: ToolCapability[];
  native?: NativeAnalysisReport;
  engines: EngineRunResult[];
  findings: AnalysisFinding[];
  /** Overall outcome, so a partially completed run is never read as a clean pass. */
  state?: Extract<EngineRunState, "complete" | "partial" | "cancelled" | "failed">;
  notes?: string[];
  protocol?: ProtocolModel;
};

export const DEFAULT_ANALYSIS_BUDGET: AnalysisBudget = {
  timeoutMs: 120_000,
  maxOutputBytes: 5_000_000,
  maxFindings: 500,
  maxPaths: 10_000,
  maxSimulationSteps: 10_000,
  maxProcessConcurrency: 2,
  seed: 1
};
