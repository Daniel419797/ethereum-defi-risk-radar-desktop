import type { AuditCategory, AuditEvaluationReport, CleanAuditRecord } from "./model.js";
import { AuditIntelligenceEngine } from "./engine.js";

function safeRatio(numerator: number, denominator: number) {
  return denominator > 0 ? numerator / denominator : 0;
}

export function evaluateAuditCorpus(records: CleanAuditRecord[]): AuditEvaluationReport {
  const train = records.filter(record => record.split === "train");
  const benchmark = records.filter(record => record.split === "benchmark");
  const engine = new AuditIntelligenceEngine(train, {
    sourceName: "Evaluation train split",
    trainCount: train.length,
    benchmarkCount: benchmark.length
  });

  const matrix = new Map<AuditCategory, Map<AuditCategory, number>>();
  let correct = 0;
  let confidenceTotal = 0;
  let covered = 0;
  let retrievalHits = 0;

  for (const record of benchmark) {
    const query = `${record.title}\n${record.description}\n${record.recommendation ?? ""}`;
    const prediction = engine.predictCategory(query);
    confidenceTotal += prediction.confidence;
    if (prediction.category === record.category) correct += 1;
    const row = matrix.get(record.category) ?? new Map<AuditCategory, number>();
    row.set(prediction.category, (row.get(prediction.category) ?? 0) + 1);
    matrix.set(record.category, row);

    const matches = engine.search(query, { topK: 5, category: prediction.category, minSimilarity: 0.05 });
    if (matches.length) covered += 1;
    if (matches.some(match => match.category === record.category)) retrievalHits += 1;
  }

  const categories = [...new Set(benchmark.map(record => record.category))];
  const perCategory: AuditEvaluationReport["perCategory"] = {};
  let macroF1 = 0;
  for (const category of categories) {
    const support = benchmark.filter(record => record.category === category).length;
    const truePositive = matrix.get(category)?.get(category) ?? 0;
    let predictedAsCategory = 0;
    for (const row of matrix.values()) predictedAsCategory += row.get(category) ?? 0;
    const precision = safeRatio(truePositive, predictedAsCategory);
    const recall = safeRatio(truePositive, support);
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    perCategory[category] = {
      support,
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
      f1: Number(f1.toFixed(4))
    };
    macroF1 += f1;
  }

  return {
    schemaVersion: 1,
    trainRecords: train.length,
    benchmarkRecords: benchmark.length,
    categoryAccuracy: Number(safeRatio(correct, benchmark.length).toFixed(4)),
    categoryMacroF1: Number(safeRatio(macroF1, categories.length).toFixed(4)),
    retrievalTop5CategoryHitRate: Number(safeRatio(retrievalHits, benchmark.length).toFixed(4)),
    meanPredictionConfidence: Number(safeRatio(confidenceTotal, benchmark.length).toFixed(4)),
    benchmarkCoverage: Number(safeRatio(covered, benchmark.length).toFixed(4)),
    perCategory,
    limitations: [
      "Benchmark labels are deterministic taxonomy labels generated during cleaning, not independently adjudicated ground truth.",
      "This evaluation measures internal consistency and retrieval utility; it must not be reported as vulnerability-detection accuracy.",
      "A production security benchmark should add independently labelled vulnerable and non-vulnerable contract fixtures."
    ]
  };
}
