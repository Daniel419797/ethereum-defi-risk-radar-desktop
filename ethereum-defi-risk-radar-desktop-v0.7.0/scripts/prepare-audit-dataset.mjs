import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { cleanAuditRecord, isPlaceholder } from "../dist/auditIntelligence/taxonomy.js";
import { evaluateAuditCorpus } from "../dist/auditIntelligence/evaluation.js";

const DEFAULT_SOURCE = "https://huggingface.co/datasets/Zaevlad/audit-findings-dataset/resolve/main/raw/bug_list_202608311315.csv?download=true";
const DEFAULT_OUTPUT = path.join(os.homedir(), ".defi-risk-radar", "audit-intelligence");
const MAX_DOWNLOAD_BYTES = 220 * 1024 * 1024;

function arg(name, fallback) {
  const prefix = `--${name}=`;
  return process.argv.find(value => value.startsWith(prefix))?.slice(prefix.length) ?? fallback;
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

async function download(url, target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5 * 60_000);
  try {
    const response = await fetch(url, { redirect: "follow", signal: controller.signal, headers: { "user-agent": "ethereum-defi-risk-radar-dataset-preparer/1" } });
    if (!response.ok || !response.body) throw new Error(`Dataset download failed with HTTP ${response.status}`);
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_DOWNLOAD_BYTES) throw new Error(`Dataset download exceeded ${MAX_DOWNLOAD_BYTES} bytes`);
      chunks.push(value);
    }
    const bytes = Buffer.concat(chunks.map(chunk => Buffer.from(chunk)), total);
    await fs.writeFile(target, bytes);
    return bytes.length;
  } finally {
    clearTimeout(timer);
  }
}

function* parseCsvRows(text) {
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') {
      quoted = true;
      continue;
    }
    if (char === ',') {
      row.push(field);
      field = "";
      continue;
    }
    if (char === '\n') {
      row.push(field.replace(/\r$/, ""));
      field = "";
      if (row.some(value => value.length > 0)) yield row;
      row = [];
      continue;
    }
    field += char;
  }
  if (quoted) throw new Error("CSV ended inside a quoted field");
  if (field.length || row.length) {
    row.push(field.replace(/\r$/, ""));
    yield row;
  }
}

function objectFromRow(headers, values) {
  const result = {};
  for (let index = 0; index < headers.length; index += 1) result[headers[index]] = values[index] ?? "";
  return result;
}

function stableBuildId(records) {
  const hash = crypto.createHash("sha256");
  for (const record of records) hash.update(record.sourceHash);
  return hash.digest("hex").slice(0, 16);
}

async function main() {
  const source = arg("source", DEFAULT_SOURCE);
  const outputDir = path.resolve(arg("output", DEFAULT_OUTPUT));
  const maxRecords = parsePositiveInt(arg("max-records", "100000"), 100_000);
  await fs.mkdir(outputDir, { recursive: true });
  const temporary = path.join(outputDir, `.raw-audit-findings-${process.pid}.csv`);
  let inputPath = source;
  let downloaded = false;

  try {
    if (/^https:\/\//i.test(source)) {
      console.log(`Downloading public audit corpus from ${source}`);
      const size = await download(source, temporary);
      console.log(`Downloaded ${(size / 1024 / 1024).toFixed(1)} MB`);
      inputPath = temporary;
      downloaded = true;
    }

    const stat = await fs.stat(inputPath);
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_DOWNLOAD_BYTES) throw new Error("Input CSV is empty, not a file, or exceeds the bounded size limit");
    const text = await fs.readFile(inputPath, "utf8");
    const iterator = parseCsvRows(text);
    const first = iterator.next();
    if (first.done) throw new Error("CSV has no rows");
    const headers = first.value.map(value => value.replace(/^\uFEFF/, "").trim());
    const required = ["bug_title", "bug_desc", "bug_poc", "bug_rec", "bug_sev"];
    for (const column of required) if (!headers.includes(column)) throw new Error(`CSV is missing required column: ${column}`);

    const records = [];
    const seen = new Set();
    let malformedRowsDropped = 0;
    let duplicateRowsDropped = 0;
    let placeholderPocRows = 0;
    let placeholderRecommendationRows = 0;
    let inputRows = 0;

    for (const values of iterator) {
      if (inputRows >= maxRecords) break;
      inputRows += 1;
      if (values.length !== headers.length) {
        malformedRowsDropped += 1;
        continue;
      }
      const raw = objectFromRow(headers, values);
      if (isPlaceholder(raw.bug_poc)) placeholderPocRows += 1;
      if (isPlaceholder(raw.bug_rec)) placeholderRecommendationRows += 1;
      const cleaned = cleanAuditRecord(raw);
      if (!cleaned) {
        malformedRowsDropped += 1;
        continue;
      }
      if (seen.has(cleaned.sourceHash)) {
        duplicateRowsDropped += 1;
        continue;
      }
      seen.add(cleaned.sourceHash);
      records.push(cleaned);
    }

    const generatedAt = new Date().toISOString();
    const trainCount = records.filter(record => record.split === "train").length;
    const benchmarkCount = records.length - trainCount;
    const metadata = {
      schemaVersion: 1,
      sourceName: "Zaevlad Smart Contract Audit Findings — locally cleaned",
      sourceUrl: /^https:\/\//i.test(source) ? source : undefined,
      generatedAt,
      buildId: stableBuildId(records),
      recordCount: records.length,
      trainCount,
      benchmarkCount,
      inputRows,
      duplicateRowsDropped,
      malformedRowsDropped,
      placeholderPocRows,
      placeholderRecommendationRows,
      licenseStatus: "UNVERIFIED_THIRD_PARTY",
      redistributionAllowed: false,
      cleaning: {
        proofOfConceptContentRetained: false,
        researcherHandlesRemovedFromTitles: true,
        exactDescriptionDuplicatesRemoved: true,
        severityNormalized: true,
        deterministicTaxonomyAssigned: true,
        deterministicTrainBenchmarkSplit: "80/20 by SHA-256 bucket",
        qualityScoreRecomputed: true,
        originalBugWeightPreservedOnlyAsSourceWeight: true
      },
      notes: [
        "The source dataset declares license: other and warns that underlying third-party audit-report licensing is unclear.",
        "This prepared corpus is local-only. Do not redistribute it or bundle it into commercial installers until provenance and rights are confirmed.",
        "PoC/exploit code is deliberately omitted from the cleaned corpus; only a boolean hasPoc indicator is retained.",
        "Historical intelligence is supporting defensive context, not proof of current exploitability."
      ]
    };

    const jsonl = `${records.map(record => JSON.stringify(record)).join("\n")}\n`;
    const benchmarkJsonl = `${records.filter(record => record.split === "benchmark").map(record => JSON.stringify(record)).join("\n")}\n`;
    await fs.writeFile(path.join(outputDir, "cleaned-audit-findings.jsonl"), jsonl, "utf8");
    await fs.writeFile(path.join(outputDir, "audit-benchmark.jsonl"), benchmarkJsonl, "utf8");
    await fs.writeFile(path.join(outputDir, "audit-dataset-stats.json"), `${JSON.stringify(metadata, null, 2)}\n`, "utf8");

    const evaluation = benchmarkCount > 0 && trainCount > 0 ? evaluateAuditCorpus(records) : undefined;
    if (evaluation) await fs.writeFile(path.join(outputDir, "audit-evaluation.json"), `${JSON.stringify(evaluation, null, 2)}\n`, "utf8");

    console.log(JSON.stringify({ outputDir, ...metadata, evaluation }, null, 2));
  } finally {
    if (downloaded) await fs.rm(temporary, { force: true });
  }
}

await main();
