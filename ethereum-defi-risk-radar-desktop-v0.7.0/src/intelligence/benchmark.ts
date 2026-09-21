import fs from "node:fs/promises";
import path from "node:path";
import type {
  BenchmarkCase,
  BenchmarkMetrics,
  BenchmarkPrediction
} from "./model.js";

export const BENCHMARK_CORPUS_COMMITS = {
  SMARTBUGS_CURATED: "230e649123477eff332742a59a1c7cc6dc286cab",
  CVE_SMART_CONTRACTS: "1128b7aae666df541a5ffcf56782df17113c3d36",
  DEFIHACKLABS: "cb457812eacd4dad09bbd1b62a1fe2fcff1a8669"
} as const;

function safeJoin(root: string, relative: string) {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(root, relative);
  if (
    resolved !== resolvedRoot &&
    !resolved.startsWith(resolvedRoot + path.sep)
  ) {
    throw new Error("Benchmark path escaped corpus root.");
  }
  return resolved;
}

export async function loadSmartBugsCurated(
  root: string
): Promise<BenchmarkCase[]> {
  const raw = JSON.parse(
    await fs.readFile(safeJoin(root, "vulnerabilities.json"), "utf8")
  ) as Array<{
    name?: string;
    path?: string;
    vulnerabilities?: Array<{ lines?: number[]; category?: string }>;
  }>;

  return raw
    .slice(0, 10_000)
    .filter(item => item.path)
    .map(item => ({
      id: "smartbugs:" + item.path,
      corpus: "SMARTBUGS_CURATED",
      sourcePath: item.path!,
      labels: (item.vulnerabilities || []).map(vulnerability => ({
        category: vulnerability.category || "unknown",
        lines: vulnerability.lines || []
      }))
    }));
}

export async function loadCveSmartContracts(
  root: string
): Promise<BenchmarkCase[]> {
  const catalog = JSON.parse(
    await fs.readFile(safeJoin(root, "cve.json"), "utf8")
  ) as {
    records?: Record<
      string,
      {
        artifacts?: {
          source?: {
            path?: string;
            chain?: string;
          };
        };
        labels?: Record<
          string,
          {
            primary?: { id?: string; name?: string } | null;
            secondary?: Array<{ id?: string; name?: string }>;
          }
        >;
        localization?: {
          locations?: Array<{
            function?: {
              start_line?: number;
              end_line?: number;
              signature?: string;
            };
          }>;
        };
      }
    >;
  };

  const cases: BenchmarkCase[] = [];
  for (const [cve, record] of Object.entries(catalog.records || {})) {
    if (
      record.artifacts?.source?.chain !== "ethereum" ||
      !record.artifacts.source.path
    ) {
      continue;
    }

    const taxonomy =
      record.labels?.IulianoDiNucci2026 ||
      record.labels?.SWC ||
      record.labels?.CWE;
    const labelRows = [
      taxonomy?.primary,
      ...(taxonomy?.secondary || [])
    ].filter(Boolean) as Array<{ id?: string; name?: string }>;
    const locations = record.localization?.locations || [];

    cases.push({
      id: "cve:" + cve,
      corpus: "CVE_SMART_CONTRACTS",
      sourcePath: record.artifacts.source.path,
      labels: labelRows.map(label => ({
        category: label.name || label.id || "unknown",
        lines: locations.flatMap(location => {
          const start = location.function?.start_line;
          const end = location.function?.end_line;
          if (!start) return [];
          return end && end >= start ? [start, end] : [start];
        }),
        function: locations[0]?.function?.signature
      })),
      metadata: { cve }
    });
  }

  return cases.slice(0, 10_000);
}

async function walkExploitFiles(
  root: string,
  directory: string,
  out: string[],
  limit: number
) {
  if (out.length >= limit) return;

  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (out.length >= limit) break;
    if (
      entry.name === ".git" ||
      entry.name === "node_modules" ||
      entry.name === "lib"
    ) {
      continue;
    }

    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await walkExploitFiles(root, target, out, limit);
    } else if (entry.isFile() && /_exp\.sol$/i.test(entry.name)) {
      out.push(path.relative(root, target).replaceAll("\\", "/"));
    }
  }
}

export async function loadDefiHackLabs(
  root: string
): Promise<BenchmarkCase[]> {
  const sourceRoot = safeJoin(root, "src/test");
  const files: string[] = [];
  await walkExploitFiles(root, sourceRoot, files, 5_000);

  return files.map(file => ({
    id: "defihacklabs:" + file,
    corpus: "DEFIHACKLABS",
    sourcePath: file,
    labels: [{ category: "historical_exploit" }],
    reproducibleExploit: true
  }));
}

function normalizedCategory(value: string) {
  const text = value.toLowerCase().replace(/[^a-z0-9]+/g, "_");
  const mappings: Array<[RegExp, string]> = [
    [/access|authori[sz]|owner|permission/, "access_control"],
    [/reentran/, "reentrancy"],
    [/arith|overflow|underflow|calculation|precision|round/, "arithmetic"],
    [/oracle|price/, "oracle_risk"],
    [/signature|replay/, "signature_replay"],
    [/delegate|proxy|upgrade|initializ/, "upgradeability"],
    [/bridge|cross_chain|message/, "bridge_messaging"],
    [/denial|dos|gas/, "denial_of_service"],
    [/front.?run|mev|ordering|slippage/, "mev_ordering"],
    [/token|transfer/, "token_integration"],
    [/historical_exploit|exploit/, "historical_exploit"]
  ];
  return mappings.find(([pattern]) => pattern.test(text))?.[1] || text;
}

function closeLine(expected: number[], actual?: number) {
  if (!expected.length || actual === undefined) return false;
  return expected.some(line => Math.abs(line - actual) <= 2);
}

export function evaluateBenchmark(
  cases: BenchmarkCase[],
  predictions: BenchmarkPrediction[]
): BenchmarkMetrics {
  const byPrediction = new Map(
    predictions.map(prediction => [prediction.caseId, prediction])
  );

  const categoryUniverse = new Set<string>();
  for (const item of cases) {
    for (const label of item.labels) {
      categoryUniverse.add(normalizedCategory(label.category));
    }
    for (const finding of byPrediction.get(item.id)?.findings || []) {
      categoryUniverse.add(normalizedCategory(finding.category));
    }
  }

  let truePositive = 0;
  let falsePositive = 0;
  let falseNegative = 0;
  let trueNegative = 0;
  let located = 0;
  let locationEligible = 0;
  let reproductionEligible = 0;
  let reproduced = 0;
  let duration = 0;
  let durationCount = 0;

  for (const item of cases) {
    const prediction = byPrediction.get(item.id);
    const expected = new Set(
      item.labels.map(label => normalizedCategory(label.category))
    );
    const predicted = new Set(
      (prediction?.findings || []).map(finding =>
        normalizedCategory(finding.category)
      )
    );

    for (const category of categoryUniverse) {
      const expectedPositive = expected.has(category);
      const predictedPositive = predicted.has(category);
      if (expectedPositive && predictedPositive) truePositive += 1;
      else if (!expectedPositive && predictedPositive) falsePositive += 1;
      else if (expectedPositive && !predictedPositive) falseNegative += 1;
      else trueNegative += 1;
    }

    for (const label of item.labels) {
      if (!label.lines?.length) continue;
      locationEligible += 1;
      if (
        prediction?.findings.some(
          finding =>
            normalizedCategory(finding.category) ===
              normalizedCategory(label.category) &&
            closeLine(label.lines || [], finding.line)
        )
      ) {
        located += 1;
      }
    }

    if (item.reproducibleExploit) {
      reproductionEligible += 1;
      if (prediction?.findings.some(finding => finding.reproduced)) {
        reproduced += 1;
      }
    }

    if (prediction?.durationMs !== undefined) {
      duration += prediction.durationMs;
      durationCount += 1;
    }
  }

  const precision =
    truePositive + falsePositive
      ? truePositive / (truePositive + falsePositive)
      : 0;
  const recall =
    truePositive + falseNegative
      ? truePositive / (truePositive + falseNegative)
      : 0;
  const f1 =
    precision + recall
      ? (2 * precision * recall) / (precision + recall)
      : 0;
  const negativeCount = falsePositive + trueNegative;

  return {
    corpus:
      cases.length &&
      cases.every(item => item.corpus === cases[0].corpus)
        ? cases[0].corpus
        : "MIXED",
    corpusCommits: BENCHMARK_CORPUS_COMMITS,
    generatedAt: new Date().toISOString(),
    caseCount: cases.length,
    labeledPositiveCount: cases.reduce(
      (sum, item) => sum + item.labels.length,
      0
    ),
    predictedPositiveCount: cases.reduce(
      (sum, item) => sum + (byPrediction.get(item.id)?.findings.length || 0),
      0
    ),
    truePositive,
    falsePositive,
    falseNegative,
    trueNegative,
    precision,
    recall,
    f1,
    falsePositiveRate: negativeCount
      ? falsePositive / negativeCount
      : null,
    lineLocationAccuracy: locationEligible
      ? located / locationEligible
      : null,
    reproductionRate: reproductionEligible
      ? reproduced / reproductionEligible
      : null,
    averageDurationMs: durationCount
      ? duration / durationCount
      : null
  };
}

export function benchmarkMarkdown(metrics: BenchmarkMetrics) {
  const percent = (value: number | null) =>
    value === null ? "n/a" : (value * 100).toFixed(2) + "%";

  return [
    "# Risk Radar benchmark result",
    "",
    "Generated: " + metrics.generatedAt,
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    "| Cases | " + metrics.caseCount + " |",
    "| True positives | " + metrics.truePositive + " |",
    "| False positives | " + metrics.falsePositive + " |",
    "| False negatives | " + metrics.falseNegative + " |",
    "| True negatives | " + metrics.trueNegative + " |",
    "| Precision | " + percent(metrics.precision) + " |",
    "| Recall | " + percent(metrics.recall) + " |",
    "| F1 | " + percent(metrics.f1) + " |",
    "| False-positive rate | " + percent(metrics.falsePositiveRate) + " |",
    "| Line-location accuracy | " +
      percent(metrics.lineLocationAccuracy) +
      " |",
    "| Reproduction rate | " + percent(metrics.reproductionRate) + " |",
    "",
    "Corpus commits:",
    ...Object.entries(metrics.corpusCommits).map(
      ([name, commit]) => "- " + name + ": " + commit
    ),
    "",
    metrics.falsePositiveRate === null
      ? "> False-positive rate is n/a because the executed corpus contained no labeled-negative cases."
      : ""
  ].join("\n");
}
