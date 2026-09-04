import crypto from "node:crypto";
import {
  AUDIT_CATEGORIES,
  type AuditCategory,
  type AuditCategoryPrediction,
  type AuditCorpusMetadata,
  type AuditFindingContext,
  type AuditSeverity,
  type CleanAuditRecord,
  type FindingAuditIntelligence,
  type HistoricalAnalogue,
  type HistoricalAuditIntelligence,
  type HistoricalSeverityDistribution
} from "./model.js";

const STOP_WORDS = new Set([
  "a", "an", "and", "are", "as", "at", "be", "been", "by", "can", "contract", "could",
  "for", "from", "function", "has", "have", "if", "in", "into", "is", "it", "may", "of",
  "on", "or", "should", "smart", "solidity", "that", "the", "their", "this", "to", "use",
  "using", "was", "were", "when", "which", "with", "would"
]);

const SEVERITY_WEIGHT: Record<AuditSeverity, number> = {
  CRITICAL: 1,
  HIGH: 0.85,
  MEDIUM: 0.58,
  LOW: 0.3,
  INFORMATIONAL: 0.12,
  GAS: 0.08,
  OTHER: 0.2,
  UNKNOWN: 0.18
};

function clamp01(value: number) {
  return Math.max(0, Math.min(1, value));
}

function tokenize(value: string) {
  return value
    .toLowerCase()
    .replace(/0x[a-f0-9]{40}/g, " address ")
    .replace(/[^a-z0-9_]+/g, " ")
    .split(/\s+/)
    .map(token => token.trim())
    .filter(token => token.length >= 2 && token.length <= 48 && !STOP_WORDS.has(token));
}

function termFrequency(tokens: string[]) {
  const counts = new Map<string, number>();
  for (const token of tokens) counts.set(token, (counts.get(token) ?? 0) + 1);
  return counts;
}

function normalizeMetadata(metadata: Partial<AuditCorpusMetadata> | undefined, recordCount: number): AuditCorpusMetadata {
  const generatedAt = metadata?.generatedAt && Number.isFinite(Date.parse(metadata.generatedAt)) ? metadata.generatedAt : new Date(0).toISOString();
  const buildId = metadata?.buildId || crypto.createHash("sha256").update(`${recordCount}|${generatedAt}`).digest("hex").slice(0, 16);
  return {
    schemaVersion: 1,
    sourceName: metadata?.sourceName || "Local cleaned smart-contract audit corpus",
    sourceUrl: metadata?.sourceUrl,
    generatedAt,
    buildId,
    recordCount,
    trainCount: metadata?.trainCount ?? recordCount,
    benchmarkCount: metadata?.benchmarkCount ?? 0,
    duplicateRowsDropped: metadata?.duplicateRowsDropped ?? 0,
    malformedRowsDropped: metadata?.malformedRowsDropped ?? 0,
    placeholderPocRows: metadata?.placeholderPocRows ?? 0,
    placeholderRecommendationRows: metadata?.placeholderRecommendationRows ?? 0,
    licenseStatus: "UNVERIFIED_THIRD_PARTY",
    redistributionAllowed: false,
    notes: metadata?.notes ?? ["Historical matches support defensive review and do not establish exploitability."]
  };
}

function emptySeverityDistribution(): HistoricalSeverityDistribution {
  return {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFORMATIONAL: 0,
    GAS: 0,
    OTHER: 0,
    UNKNOWN: 0
  };
}

type IndexedDocument = {
  record: CleanAuditRecord;
  tf: Map<string, number>;
  norm: number;
};

type CategoryModel = {
  documentCount: number;
  tokenCount: number;
  tokens: Map<string, number>;
};

export class AuditIntelligenceEngine {
  readonly metadata: AuditCorpusMetadata;
  private readonly documents: IndexedDocument[];
  private readonly documentFrequency = new Map<string, number>();
  private readonly inverted = new Map<string, Array<{ index: number; tf: number }>>();
  private readonly categoryModels = new Map<AuditCategory, CategoryModel>();
  private readonly vocabulary = new Set<string>();

  constructor(records: CleanAuditRecord[], metadata?: Partial<AuditCorpusMetadata>) {
    const bounded = records.slice(0, 100_000);
    this.metadata = normalizeMetadata(metadata, bounded.length);

    for (const category of AUDIT_CATEGORIES) {
      this.categoryModels.set(category, { documentCount: 0, tokenCount: 0, tokens: new Map() });
    }

    const rawDocs = bounded.map(record => {
      const tokens = tokenize(`${record.title}\n${record.description}\n${record.recommendation ?? ""}\n${record.tags.join(" ")}`);
      const tf = termFrequency(tokens);
      for (const token of tf.keys()) this.documentFrequency.set(token, (this.documentFrequency.get(token) ?? 0) + 1);
      const model = this.categoryModels.get(record.category)!;
      model.documentCount += 1;
      for (const [token, count] of tf) {
        this.vocabulary.add(token);
        model.tokens.set(token, (model.tokens.get(token) ?? 0) + count);
        model.tokenCount += count;
      }
      return { record, tf };
    });

    this.documents = rawDocs.map((doc, index) => {
      let normSquared = 0;
      for (const [token, count] of doc.tf) {
        const weight = this.tfidf(token, count);
        normSquared += weight * weight;
        const rows = this.inverted.get(token) ?? [];
        rows.push({ index, tf: count });
        this.inverted.set(token, rows);
      }
      return { ...doc, norm: Math.sqrt(normSquared) || 1 };
    });
  }

  static fromJsonl(jsonl: string, metadata?: Partial<AuditCorpusMetadata>) {
    const rows: CleanAuditRecord[] = [];
    for (const line of jsonl.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const row = JSON.parse(trimmed) as CleanAuditRecord;
        if (!row?.sourceHash || !row?.title || !row?.description || !AUDIT_CATEGORIES.includes(row.category)) continue;
        rows.push(row);
      } catch {
        // Malformed rows are ignored here. Dataset preparation reports them separately.
      }
    }
    return new AuditIntelligenceEngine(rows, metadata);
  }

  get recordCount() {
    return this.documents.length;
  }

  private idf(token: string) {
    const df = this.documentFrequency.get(token) ?? 0;
    return Math.log(1 + (this.documents.length + 1) / (df + 1));
  }

  private tfidf(token: string, count: number) {
    return (1 + Math.log(Math.max(1, count))) * this.idf(token);
  }

  predictCategory(text: string): AuditCategoryPrediction {
    const tokens = tokenize(text);
    if (!tokens.length || this.documents.length === 0) return { category: "other", confidence: 0, scores: { other: 0 } };
    const vocabularySize = Math.max(1, this.vocabulary.size);
    const categoriesWithData = AUDIT_CATEGORIES.filter(category => (this.categoryModels.get(category)?.documentCount ?? 0) > 0);
    if (!categoriesWithData.length) return { category: "other", confidence: 0, scores: { other: 0 } };

    const logScores = categoriesWithData.map(category => {
      const model = this.categoryModels.get(category)!;
      let score = Math.log((model.documentCount + 1) / (this.documents.length + categoriesWithData.length));
      const denominator = model.tokenCount + vocabularySize;
      for (const token of tokens) score += Math.log(((model.tokens.get(token) ?? 0) + 1) / denominator);
      return { category, score };
    }).sort((a, b) => b.score - a.score);

    const max = logScores[0]?.score ?? 0;
    const expScores = logScores.map(item => ({ ...item, exp: Math.exp(Math.max(-50, item.score - max)) }));
    const total = expScores.reduce((sum, item) => sum + item.exp, 0) || 1;
    const scores: Partial<Record<AuditCategory, number>> = {};
    for (const item of expScores) scores[item.category] = item.exp / total;
    const winner = expScores[0];
    return { category: winner?.category ?? "other", confidence: clamp01((winner?.exp ?? 0) / total), scores };
  }

  search(text: string, opts: { topK?: number; category?: AuditCategory; minSimilarity?: number } = {}): HistoricalAnalogue[] {
    if (!this.documents.length) return [];
    const topK = Math.max(1, Math.min(opts.topK ?? 5, 20));
    const minSimilarity = clamp01(opts.minSimilarity ?? 0.08);
    const queryTf = termFrequency(tokenize(text));
    if (!queryTf.size) return [];

    let queryNormSquared = 0;
    const queryWeights = new Map<string, number>();
    for (const [token, count] of queryTf) {
      const weight = this.tfidf(token, count);
      queryWeights.set(token, weight);
      queryNormSquared += weight * weight;
    }
    const queryNorm = Math.sqrt(queryNormSquared) || 1;
    const dot = new Map<number, number>();
    for (const [token, queryWeight] of queryWeights) {
      for (const posting of this.inverted.get(token) ?? []) {
        dot.set(posting.index, (dot.get(posting.index) ?? 0) + queryWeight * this.tfidf(token, posting.tf));
      }
    }

    return [...dot.entries()]
      .map(([index, score]) => {
        const doc = this.documents[index];
        const cosine = score / (queryNorm * doc.norm);
        const categoryBoost = opts.category && doc.record.category === opts.category ? 0.08 : 0;
        const qualityBoost = 0.04 * doc.record.qualityScore;
        return { doc, similarity: clamp01(cosine + categoryBoost + qualityBoost) };
      })
      .filter(item => item.similarity >= minSimilarity)
      .sort((a, b) => b.similarity - a.similarity || b.doc.record.qualityScore - a.doc.record.qualityScore)
      .slice(0, topK)
      .map(({ doc, similarity }) => ({
        recordId: doc.record.id,
        title: doc.record.title,
        descriptionExcerpt: doc.record.description.slice(0, 420),
        recommendation: doc.record.recommendation?.slice(0, 500),
        severity: doc.record.severity,
        category: doc.record.category,
        similarity: Number(similarity.toFixed(4)),
        qualityScore: doc.record.qualityScore,
        hasPoc: doc.record.hasPoc
      }));
  }

  analyzeFinding(finding: AuditFindingContext, opts: { topK?: number } = {}): FindingAuditIntelligence | undefined {
    const query = `${finding.title}\n${finding.description}\n${finding.kind ?? ""}`;
    const prediction = this.predictCategory(query);
    const analogues = this.search(query, { topK: opts.topK ?? 3, category: prediction.category });
    if (!analogues.length) return undefined;

    const severity = emptySeverityDistribution();
    let weightedRisk = 0;
    let weightTotal = 0;
    for (const analogue of analogues) {
      const weight = Math.max(0.05, analogue.similarity) * (0.5 + 0.5 * analogue.qualityScore);
      severity[analogue.severity] += weight;
      weightedRisk += SEVERITY_WEIGHT[analogue.severity] * weight;
      weightTotal += weight;
    }
    for (const key of Object.keys(severity) as AuditSeverity[]) severity[key] = Number((severity[key] / Math.max(weightTotal, 1e-9)).toFixed(4));

    const similaritySignal = analogues.reduce((sum, item) => sum + item.similarity, 0) / analogues.length;
    const severitySignal = weightedRisk / Math.max(weightTotal, 1e-9);
    const historicalRiskScore = Math.round(100 * clamp01(0.55 * severitySignal + 0.3 * similaritySignal + 0.15 * prediction.confidence));
    const commonRemediations = [...new Set(analogues.map(item => item.recommendation?.trim()).filter((value): value is string => Boolean(value)))]
      .sort((a, b) => b.length - a.length)
      .slice(0, 3);

    return {
      findingId: finding.id,
      findingTitle: finding.title,
      predictedCategory: prediction.category,
      categoryConfidence: Number(prediction.confidence.toFixed(4)),
      historicalRiskScore,
      historicalSeverityDistribution: severity,
      analogues,
      commonRemediations
    };
  }

  analyzeFindings(findings: AuditFindingContext[], opts: { maxFindings?: number; topK?: number } = {}): HistoricalAuditIntelligence {
    const selected = findings.slice(0, Math.max(1, Math.min(opts.maxFindings ?? 24, 100)));
    const enriched = selected.map(finding => this.analyzeFinding(finding, { topK: opts.topK ?? 3 })).filter((value): value is FindingAuditIntelligence => Boolean(value));
    return {
      schemaVersion: 1,
      status: "AVAILABLE",
      corpus: {
        sourceName: this.metadata.sourceName,
        generatedAt: this.metadata.generatedAt,
        buildId: this.metadata.buildId,
        recordCount: this.metadata.recordCount,
        licenseStatus: this.metadata.licenseStatus,
        redistributionAllowed: false
      },
      totalFindings: selected.length,
      matchedFindings: enriched.length,
      totalHistoricalMatches: enriched.reduce((sum, item) => sum + item.analogues.length, 0),
      findings: enriched,
      limitations: [
        "Historical similarity is supporting context, not proof that the current contract is vulnerable or exploitable.",
        "Category labels are derived from a deterministic audit taxonomy and local statistical model; they are not independent human ground truth.",
        "The third-party audit corpus has unverified redistribution/commercial-use rights and is intentionally not bundled with Risk Radar.",
        "Historical risk score is a review-prioritization signal based on analogue severity, similarity and corpus quality; it is not an exploitability percentage."
      ]
    };
  }

  recordsForEvaluation() {
    return this.documents.map(item => item.record);
  }
}
