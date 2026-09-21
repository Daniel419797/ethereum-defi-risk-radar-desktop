import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { analyzeSoliditySources } from "../analysis/native/analyzer.js";
import type { AnalysisFinding } from "../analysis/model.js";
import type {
  BenchmarkCase,
  BenchmarkCaseResult,
  BenchmarkDataset,
  BenchmarkMetrics
} from "./model.js";

const MAX_SOURCE_BYTES = 4_000_000;
const MAX_CASES_DEFAULT = 5_000;

const EXTERNAL_KIND_MAP: Array<[RegExp, string]> = [
  [/reentr/i, "reentrancy"],
  [/access.?control|authorization|tx.?origin|swc[-_ ]?105|cwe[-_ ]?284/i, "authorization"],
  [/integer|arithmetic|overflow|underflow|precision|round/i, "arithmetic_precision"],
  [/unchecked.?low|unchecked.?call|low.?level.?call/i, "cross_contract_calls"],
  [/denial.?of.?service|dos|swc[-_ ]?113/i, "denial_of_service"],
  [/front.?run|mev|transaction.?order|swc[-_ ]?114/i, "mev_ordering"],
  [/oracle|price.?manip/i, "oracle_risk"],
  [/signature|replay|ecrecover/i, "signature_replay"],
  [/upgrade|proxy|storage.?collision/i, "upgradeability"],
  [/govern|vote|quorum|timelock/i, "governance_risk"],
  [/bridge|cross.?chain|cross.?domain|message.?replay/i, "bridge_messaging"],
  [/token|fee.?on.?transfer|rebasing/i, "token_integration"],
  [/liquidat|bad.?debt|solvency/i, "economic_simulation"]
];

function normalizeExpectedKind(value: string) {
  return EXTERNAL_KIND_MAP.find(([pattern]) => pattern.test(value))?.[1];
}

async function walkFiles(root: string, predicate: (file: string) => boolean, maxFiles = 20_000) {
  const resolved = path.resolve(root);
  const files: string[] = [];
  async function visit(directory: string, depth: number) {
    if (depth > 32) throw new Error("Benchmark corpus directory depth exceeds 32.");
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "cache" || entry.name === "out") continue;
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) await visit(target, depth + 1);
      else if (entry.isFile() && predicate(target)) files.push(target);
    }
  }
  await visit(resolved, 0);
  return files;
}

async function readBoundedText(filePath: string, maxBytes = MAX_SOURCE_BYTES) {
  const stat = await fs.stat(filePath);
  if (!stat.isFile() || stat.size > maxBytes) {
    throw new Error(`Benchmark input exceeds ${maxBytes} bytes or is not a file: ${filePath}`);
  }
  return fs.readFile(filePath, "utf8");
}

async function readBoundedJson<T>(filePath: string, maxBytes = 32_000_000): Promise<T> {
  const text = await readBoundedText(filePath, maxBytes);
  return JSON.parse(text) as T;
}

type SmartBugsManifestItem = {
  name?: string;
  path?: string;
  vulnerabilities?: Array<{ lines?: number[]; category?: string }>;
};

export async function prepareSmartBugsCases(
  root: string,
  opts: { maxCases?: number } = {}
): Promise<BenchmarkCase[]> {
  const manifestPath = path.join(path.resolve(root), "vulnerabilities.json");
  const manifest = await readBoundedJson<SmartBugsManifestItem[]>(manifestPath);
  if (!Array.isArray(manifest)) throw new Error("SmartBugs vulnerabilities.json must contain an array.");

  const maxCases = Math.max(1, Math.min(opts.maxCases ?? MAX_CASES_DEFAULT, MAX_CASES_DEFAULT));
  const cases: BenchmarkCase[] = [];

  for (const item of manifest) {
    if (cases.length >= maxCases) break;
    if (!item.path || !Array.isArray(item.vulnerabilities)) continue;
    const sourcePath = await resolveCorpusSource(root, item.path);
    if (!sourcePath) continue;
    const sourceText = await readBoundedText(sourcePath);
    const expectedKinds = new Set<string>();
    const vulnerableLines = new Set<number>();
    const rawCategories = new Set<string>();

    for (const vulnerability of item.vulnerabilities) {
      if (vulnerability.category) {
        rawCategories.add(vulnerability.category);
        const normalized = normalizeExpectedKind(vulnerability.category);
        if (normalized) expectedKinds.add(normalized);
      }
      for (const line of vulnerability.lines ?? []) {
        if (Number.isInteger(line) && line > 0) vulnerableLines.add(line);
      }
    }

    if (!expectedKinds.size) continue;
    cases.push({
      id: `smartbugs:${item.path.replaceAll("\\", "/")}`,
      dataset: "SMARTBUGS_CURATED",
      sourcePath,
      sourceText,
      expectedKinds: [...expectedKinds].sort(),
      vulnerableLines: [...vulnerableLines].sort((a, b) => a - b),
      negative: false,
      metadata: {
        relativePath: item.path.replaceAll("\\", "/"),
        sourceName: item.name ?? path.basename(sourcePath),
        categories: [...rawCategories].sort().join("|")
      }
    });
  }
  return cases;
}

type CveTaxonomyLabel = {
  primary?: { id?: string; name?: string };
  secondary?: Array<{ id?: string; name?: string }>;
};

type CveCatalogRecord = {
  artifacts?: {
    source?: { path?: string; contract?: string; chain?: string; address?: string };
    runtime?: { path?: string; chain?: string; address?: string };
  };
  labels?: Record<string, CveTaxonomyLabel>;
  localization?: {
    summary?: string;
    locations?: Array<{
      source_path?: string;
      contract?: string;
      function?: {
        start_line?: number;
        end_line?: number;
        signature?: string;
        visibility?: string;
      };
      entry_points?: Array<{ exposed_by_contract?: string; path?: string[] }>;
    }>;
  };
};

type CveCatalog = {
  schema_version?: string;
  records?: Record<string, CveCatalogRecord>;
};

function cveExpectedKinds(record: CveCatalogRecord) {
  const kinds = new Set<string>();
  const rawLabels: string[] = [];
  for (const taxonomy of Object.values(record.labels ?? {})) {
    for (const label of [taxonomy.primary, ...(taxonomy.secondary ?? [])]) {
      if (!label) continue;
      const material = [label.id, label.name].filter(Boolean).join(" ");
      if (material) rawLabels.push(material);
      const kind = normalizeExpectedKind(material);
      if (kind) kinds.add(kind);
    }
  }
  return { kinds: [...kinds].sort(), rawLabels };
}

function cveLocalizedLines(record: CveCatalogRecord) {
  const lines = new Set<number>();
  for (const location of record.localization?.locations ?? []) {
    const start = location.function?.start_line;
    const end = location.function?.end_line;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start! <= 0 || end! < start!) continue;
    // Function-level ground truth is a range, not a single vulnerable statement.
    // Cap expansion so malformed metadata cannot create unbounded benchmark work.
    const cappedEnd = Math.min(end!, start! + 2_000);
    for (let line = start!; line <= cappedEnd; line += 1) lines.add(line);
  }
  return [...lines].sort((a, b) => a - b);
}

export async function prepareCveSmartContractCases(
  root: string,
  opts: { maxCases?: number } = {}
): Promise<BenchmarkCase[]> {
  const catalog = await readBoundedJson<CveCatalog>(path.join(path.resolve(root), "cve.json"), 64_000_000);
  if (!catalog.records || typeof catalog.records !== "object") {
    throw new Error("CVE Smart Contracts cve.json is missing records.");
  }

  const maxCases = Math.max(1, Math.min(opts.maxCases ?? MAX_CASES_DEFAULT, MAX_CASES_DEFAULT));
  const out: BenchmarkCase[] = [];

  for (const [cveId, record] of Object.entries(catalog.records).sort(([a], [b]) => a.localeCompare(b))) {
    if (out.length >= maxCases) break;
    const sourceCandidate = record.artifacts?.source?.path ?? "";
    const sourcePath = await resolveCorpusSource(root, sourceCandidate);
    if (!sourcePath) continue;
    const sourceText = await readBoundedText(sourcePath);
    const labels = cveExpectedKinds(record);
    if (!labels.kinds.length) continue;

    out.push({
      id: `cve:${cveId}`,
      dataset: "CVE_SMART_CONTRACTS",
      sourcePath,
      sourceText,
      expectedKinds: labels.kinds,
      vulnerableLines: cveLocalizedLines(record),
      negative: false,
      metadata: {
        cve: cveId,
        sourceResolved: true,
        chain: record.artifacts?.source?.chain ?? null,
        contract: record.artifacts?.source?.contract ?? null,
        labels: labels.rawLabels.join("|"),
        localizationSummary: record.localization?.summary?.slice(0, 500) ?? null
      }
    });
  }
  return out;
}

function defihackMetadata(source: string) {
  const pick = (pattern: RegExp) => source.match(pattern)?.[1]?.trim();
  return {
    chain: pick(/(?:@KeyInfo\s*-\s*)?Chain\s*:\s*([^\n]+)/i) ?? null,
    vulnerableContract: pick(/Vulnerable(?: Contract)?\s*:\s*(0x[a-fA-F0-9]{40})/i) ?? null,
    attackTx: pick(/(?:Attack|Exploit|Drain) Tx\s*:\s*[^\s]*?(0x[a-fA-F0-9]{64})/i) ?? null,
    totalLost: pick(/Total Lost\s*:\s*([^\n]+)/i) ?? null
  };
}

export async function prepareDefiHackLabsCases(
  root: string,
  opts: { maxCases?: number } = {}
): Promise<BenchmarkCase[]> {
  const files = await walkFiles(root, file => /_exp\.sol$/i.test(file));
  const maxCases = Math.max(1, Math.min(opts.maxCases ?? MAX_CASES_DEFAULT, MAX_CASES_DEFAULT));
  const out: BenchmarkCase[] = [];
  for (const file of files.slice(0, maxCases)) {
    const sourceText = await readBoundedText(file);
    const relative = path.relative(root, file).replaceAll("\\", "/");
    out.push({
      id: `defihacklabs:${relative}`,
      dataset: "DEFIHACKLABS",
      sourcePath: file,
      sourceText,
      expectedKinds: [],
      vulnerableLines: [],
      negative: false,
      reproduction: {
        command: "forge",
        args: ["test", "--match-path", relative, "-vv"],
        workingDirectory: path.resolve(root)
      },
      metadata: { relativePath: relative, ...defihackMetadata(sourceText) }
    });
  }
  return out;
}

function observedKinds(findings: AnalysisFinding[]) {
  return [...new Set(findings.map(finding => finding.kind))];
}

function locationHits(findings: AnalysisFinding[], expectedLines: number[], tolerance = 3) {
  if (!expectedLines.length) return 0;
  const lines = findings.map(finding => finding.primaryLocation?.line).filter((line): line is number => Boolean(line));
  return expectedLines.filter(expected => lines.some(observed => Math.abs(observed - expected) <= tolerance)).length;
}

function countDetection(caseItem: BenchmarkCase, findings: AnalysisFinding[]) {
  if (!caseItem.expectedKinds.length) {
    return { tp: 0, fp: 0, fn: 0, tn: caseItem.negative && findings.length === 0 };
  }
  const observed = new Set(observedKinds(findings));
  const expected = new Set(caseItem.expectedKinds);
  const tp = [...expected].filter(kind => observed.has(kind)).length;
  const fn = [...expected].filter(kind => !observed.has(kind)).length;
  const fp = caseItem.negative
    ? observed.size
    : [...observed].filter(kind => !expected.has(kind)).length;
  return { tp, fp, fn, tn: caseItem.negative && observed.size === 0 };
}

async function reproduce(caseItem: BenchmarkCase, trusted: boolean, timeoutMs: number) {
  if (!caseItem.reproduction || !trusted) return { attempted: false as const };
  if (caseItem.reproduction.command !== "forge") throw new Error("Only the Forge benchmark reproducer is allowlisted.");
  return await new Promise<{ attempted: true; passed: boolean; error?: string }>(resolve => {
    const child = spawn("forge", caseItem.reproduction!.args, {
      cwd: caseItem.reproduction!.workingDirectory,
      shell: false,
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
      env: { ...process.env, FOUNDRY_DISABLE_NIGHTLY_WARNING: "1" }
    });
    let stderr = "";
    child.stderr.on("data", chunk => {
      if (stderr.length < 16_000) stderr += String(chunk).slice(0, 16_000 - stderr.length);
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ attempted: true, passed: false, error: "Reproduction timed out." });
    }, timeoutMs);
    child.on("error", error => {
      clearTimeout(timer);
      resolve({ attempted: true, passed: false, error: error.message });
    });
    child.on("exit", code => {
      clearTimeout(timer);
      resolve({ attempted: true, passed: code === 0, error: code === 0 ? undefined : stderr.slice(-2_000) || `forge exited ${code}` });
    });
  });
}

function ratio(numerator: number, denominator: number) {
  return denominator > 0 ? numerator / denominator : null;
}

export async function runBenchmark(
  cases: BenchmarkCase[],
  opts: {
    trustReproduction?: boolean;
    reproductionTimeoutMs?: number;
    maxCases?: number;
    datasetRevisions?: Partial<Record<BenchmarkDataset, string>>;
  } = {}
): Promise<BenchmarkMetrics> {
  const maxCases = Math.max(1, Math.min(opts.maxCases ?? cases.length, MAX_CASES_DEFAULT));
  const selected = cases.slice(0, maxCases);
  const results: BenchmarkCaseResult[] = [];

  for (const caseItem of selected) {
    const started = Date.now();
    const errors: string[] = [];
    let findings: AnalysisFinding[] = [];
    if (caseItem.sourceText) {
      try {
        findings = analyzeSoliditySources([{ name: path.basename(caseItem.sourcePath || "Benchmark.sol"), content: caseItem.sourceText }]).findings;
      } catch (error) {
        errors.push(error instanceof Error ? error.message : String(error));
      }
    } else if (caseItem.expectedKinds.length) {
      errors.push("Ground-truth case has no locally resolvable Solidity source; detection metrics for this case may be incomplete.");
    }

    const counts = countDetection(caseItem, findings);
    const reproduction = await reproduce(
      caseItem,
      Boolean(opts.trustReproduction),
      Math.max(1_000, Math.min(opts.reproductionTimeoutMs ?? 120_000, 900_000))
    );
    if ("error" in reproduction && reproduction.error) errors.push(reproduction.error);

    results.push({
      id: caseItem.id,
      dataset: caseItem.dataset,
      expectedKinds: caseItem.expectedKinds,
      observedKinds: observedKinds(findings),
      truePositives: counts.tp,
      falsePositives: counts.fp,
      falseNegatives: counts.fn,
      trueNegative: counts.tn,
      locationHits: locationHits(findings, caseItem.vulnerableLines),
      locationExpected: caseItem.vulnerableLines.length,
      reproductionAttempted: reproduction.attempted,
      reproductionPassed: reproduction.attempted ? reproduction.passed : undefined,
      durationMs: Date.now() - started,
      errors
    });
  }

  const tp = results.reduce((sum, item) => sum + item.truePositives, 0);
  const fp = results.reduce((sum, item) => sum + item.falsePositives, 0);
  const fn = results.reduce((sum, item) => sum + item.falseNegatives, 0);
  const tn = results.filter(item => item.trueNegative).length;
  const locationExpected = results.reduce((sum, item) => sum + item.locationExpected, 0);
  const locationHitCount = results.reduce((sum, item) => sum + item.locationHits, 0);
  const reproductions = results.filter(item => item.reproductionAttempted);
  const reproductionPassed = reproductions.filter(item => item.reproductionPassed).length;
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision !== null && recall !== null && precision + recall > 0
    ? 2 * precision * recall / (precision + recall)
    : null;

  const datasets = [...new Set(results.map(item => item.dataset))];
  return {
    generatedAt: new Date().toISOString(),
    datasets,
    cases: results.length,
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    precision,
    recall,
    f1,
    falsePositiveRate: ratio(fp, fp + tn),
    locationRecall: ratio(locationHitCount, locationExpected),
    reproductionRate: ratio(reproductionPassed, reproductions.length),
    totalDurationMs: results.reduce((sum, item) => sum + item.durationMs, 0),
    results,
    provenance: datasets.map(dataset => ({
      dataset,
      revision: opts.datasetRevisions?.[dataset],
      licenseNote:
        dataset === "DEFIHACKLABS"
          ? "DeFiHackLabs repository code is Apache-2.0; individual incident/source references may have separate provenance."
          : dataset === "CVE_SMART_CONTRACTS"
            ? "Dataset/original annotations are CC-BY-4.0 and software is MIT; third-party artifacts retain their original terms."
            : "SmartBugs Curated contracts retain original licenses; repository metadata follows the repository LICENSE."
    }))
  };
}

export function benchmarkMarkdown(metrics: BenchmarkMetrics) {
  const pct = (value: number | null) => value === null ? "n/a" : `${(value * 100).toFixed(2)}%`;
  const lines = [
    "# Risk Radar Benchmark Report",
    "",
    `Generated: ${metrics.generatedAt}`,
    `Datasets: ${metrics.datasets.join(", ")}`,
    `Cases: ${metrics.cases}`,
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Precision | ${pct(metrics.precision)} |`,
    `| Recall | ${pct(metrics.recall)} |`,
    `| F1 | ${pct(metrics.f1)} |`,
    `| False-positive rate | ${pct(metrics.falsePositiveRate)} |`,
    `| Vulnerable-location recall | ${pct(metrics.locationRecall)} |`,
    `| Reproduction rate | ${pct(metrics.reproductionRate)} |`,
    `| True positives | ${metrics.truePositives} |`,
    `| False positives | ${metrics.falsePositives} |`,
    `| False negatives | ${metrics.falseNegatives} |`,
    `| True negatives | ${metrics.trueNegatives} |`,
    "",
    "## Interpretation",
    "",
    "Metrics are computed only from the ground truth present in each imported corpus. A finding not listed by a corpus may still be valid; therefore these metrics measure agreement with declared benchmark labels rather than universal vulnerability truth.",
    "DeFiHackLabs reproduction is never executed unless the caller explicitly trusts the local corpus and enables reproduction.",
    "",
    "## Dataset provenance",
    "",
    ...metrics.provenance.map(item => `- **${item.dataset}** @ ${item.revision ?? "unrecorded revision"} — ${item.licenseNote}`)
  ];
  return lines.join("\n") + "\n";
}

export async function writeBenchmarkArtifacts(metrics: BenchmarkMetrics, outputDir: string) {
  const resolved = path.resolve(outputDir);
  await fs.mkdir(resolved, { recursive: true });
  const stamp = metrics.generatedAt.replace(/[:.]/g, "-");
  const jsonPath = path.join(resolved, `risk-radar-benchmark-${stamp}.json`);
  const markdownPath = path.join(resolved, `risk-radar-benchmark-${stamp}.md`);
  const latestJsonPath = path.join(resolved, "latest.json");
  const latestMarkdownPath = path.join(resolved, "latest.md");
  const json = JSON.stringify(metrics, null, 2);
  const markdown = benchmarkMarkdown(metrics);
  await Promise.all([
    fs.writeFile(jsonPath, json, "utf8"),
    fs.writeFile(markdownPath, markdown, "utf8"),
    fs.writeFile(latestJsonPath, json, "utf8"),
    fs.writeFile(latestMarkdownPath, markdown, "utf8")
  ]);
  return { jsonPath, markdownPath, latestJsonPath, latestMarkdownPath };
}
