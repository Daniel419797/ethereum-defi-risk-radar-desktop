export const AUDIT_CATEGORIES = [
  "reentrancy",
  "access_control",
  "oracle_price",
  "accounting_state",
  "precision_rounding",
  "token_integration",
  "signature_replay",
  "upgradeability",
  "denial_of_service",
  "mev_front_running",
  "governance",
  "bridge_cross_chain",
  "liquidation",
  "flash_liquidity",
  "input_validation",
  "gas_economic",
  "business_logic",
  "other"
] as const;

export type AuditCategory = (typeof AUDIT_CATEGORIES)[number];

export type AuditSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFORMATIONAL"
  | "GAS"
  | "OTHER"
  | "UNKNOWN";

export type CleanAuditRecord = {
  id: string;
  sourceHash: string;
  title: string;
  description: string;
  recommendation?: string;
  severity: AuditSeverity;
  severityRaw?: string;
  category: AuditCategory;
  tags: string[];
  qualityScore: number;
  sourceWeight?: number;
  hasPoc: boolean;
  split: "train" | "benchmark";
};

export type AuditCorpusMetadata = {
  schemaVersion: 1;
  sourceName: string;
  sourceUrl?: string;
  generatedAt: string;
  buildId: string;
  recordCount: number;
  trainCount: number;
  benchmarkCount: number;
  duplicateRowsDropped: number;
  malformedRowsDropped: number;
  placeholderPocRows: number;
  placeholderRecommendationRows: number;
  licenseStatus: "UNVERIFIED_THIRD_PARTY";
  redistributionAllowed: false;
  notes: string[];
};

export type AuditFindingContext = {
  id: string;
  title: string;
  description: string;
  kind?: string;
  severity?: string;
  file?: string;
  line?: number;
};

export type HistoricalAnalogue = {
  recordId: string;
  title: string;
  descriptionExcerpt: string;
  recommendation?: string;
  severity: AuditSeverity;
  category: AuditCategory;
  similarity: number;
  qualityScore: number;
  hasPoc: boolean;
};

export type HistoricalSeverityDistribution = Record<AuditSeverity, number>;

export type FindingAuditIntelligence = {
  findingId: string;
  findingTitle: string;
  predictedCategory: AuditCategory;
  categoryConfidence: number;
  historicalRiskScore: number;
  historicalSeverityDistribution: HistoricalSeverityDistribution;
  analogues: HistoricalAnalogue[];
  commonRemediations: string[];
};

export type HistoricalAuditIntelligence = {
  schemaVersion: 1;
  status: "AVAILABLE";
  corpus: Pick<
    AuditCorpusMetadata,
    | "sourceName"
    | "generatedAt"
    | "buildId"
    | "recordCount"
    | "licenseStatus"
    | "redistributionAllowed"
  >;
  totalFindings: number;
  matchedFindings: number;
  totalHistoricalMatches: number;
  findings: FindingAuditIntelligence[];
  limitations: string[];
};

export type AuditCategoryPrediction = {
  category: AuditCategory;
  confidence: number;
  scores: Partial<Record<AuditCategory, number>>;
};

export type AuditEvaluationReport = {
  schemaVersion: 1;
  trainRecords: number;
  benchmarkRecords: number;
  categoryAccuracy: number;
  categoryMacroF1: number;
  retrievalTop5CategoryHitRate: number;
  meanPredictionConfidence: number;
  benchmarkCoverage: number;
  perCategory: Partial<Record<AuditCategory, { support: number; precision: number; recall: number; f1: number }>>;
  limitations: string[];
};
