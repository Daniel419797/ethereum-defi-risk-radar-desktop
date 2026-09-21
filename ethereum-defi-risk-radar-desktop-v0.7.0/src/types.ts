import type { SourceInspection } from "./sourceAnalyzer.js";
import type { BytecodeAnalysisReport } from "./analysis/bytecode/analyzer.js";
import type { SourceLanguageProfile } from "./intelligence/sourceLanguage.js";
import type { BytecodeAttestation, PinnedStateSnapshot, ProtocolIntelligenceBundle } from "./intelligence/model.js";

export type TinyFishResult = {
  title?: string;
  url?: string;
  snippet?: string;
  date?: string | null;
  published_date?: string | null;
  site_name?: string;
};

export type TinyFishSearchResponse = {
  query?: string;
  results?: TinyFishResult[];
  total_results?: number;
  page?: number;
};

export type SignalKind =
  | "deprecated"
  | "dormant"
  | "migration"
  | "public_audit_finding"
  | "historical_incident"
  | "admin_governance_risk"
  | "archived_code"
  | "upgradeability_surface";

export type SourceTrust = "HIGH" | "MEDIUM" | "GENERAL";

export type Evidence = {
  kind: SignalKind;
  weight: number;
  sourceUrl: string;
  sourceTitle: string;
  sourceHost: string;
  sourceTrust: SourceTrust;
  snippet: string;
  year: number;
  query: string;
  ethereumTerms: string[];
  contractReferenceCount: number;
};

export type ProtocolResolutionEvidence = {
  sourceUrl: string;
  sourceTitle: string;
  sourceHost: string;
  sourceTrust: SourceTrust;
  query: string;
  contractReferenceCount: number;
};

export type ContractInspectionSummary = {
  contractRefId: string;
  rootContractRefId?: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  contractName?: string;
  compilerVersion?: string;
  proxy: boolean;
  /** Raw address is kept only in-memory/local state; generated reports redact it. */
  address?: string;
  bytecodeAttestation?: BytecodeAttestation;
  bytecodeAnalysis?: BytecodeAnalysisReport;
  sourceLanguageProfile?: SourceLanguageProfile;
  inspection: SourceInspection;
};

export type BytecodeInspectionSummary = {
  contractRefId: string;
  rootContractRefId?: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  contractName?: string;
  compilerVersion?: string;
  proxy: boolean;
  sourceVerified: boolean;
  /** Raw address stays local/in-memory; report serialization redacts EVM addresses. */
  address?: string;
  bytecodeAttestation?: BytecodeAttestation;
  bytecodeAnalysis: BytecodeAnalysisReport;
  sourceLanguageProfile?: SourceLanguageProfile;
};

export type EthereumMetadata = {
  chainId: 1;
  network: "ethereum-mainnet";
  contractReferencesObserved: number;
  etherscanLookupsAttempted: number;
  verifiedSourceContracts: number;
  proxyContracts: number;
  proxyImplementationsResolved: number;
  sourceContractsInspected: number;
  sourceFindingCount: number;
  sourceHighReviewCount: number;
  advancedFindingCount: number;
  bytecodeContractsAnalyzed: number;
  bytecodeFindingCount: number;
  sourceInspections: ContractInspectionSummary[];
  bytecodeInspections: BytecodeInspectionSummary[];
  pinnedStateSnapshot?: PinnedStateSnapshot;
  intelligence?: ProtocolIntelligenceBundle;
};

export type Candidate = {
  id: string;
  entityKind: "PROTOCOL";
  resolutionStatus: "BYTECODE_ANALYZED" | "CONTRACTS_VERIFIED" | "SOURCE_ANALYZED";
  label: string;
  hostname: string;
  chain: "ethereum";
  network: "mainnet";
  researchScore: number;
  ethereumConfidence: number;
  signalCount: number;
  sourceDiversity: number;
  kinds: SignalKind[];
  evidence: Evidence[];
  resolutionEvidence: ProtocolResolutionEvidence[];
  ethereum: EthereumMetadata;
  classification:
    | "LOW_PUBLIC_SIGNAL"
    | "REVIEW"
    | "HIGH_RESEARCH_PRIORITY";
};
