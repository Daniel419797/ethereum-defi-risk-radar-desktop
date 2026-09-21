import path from "node:path";
import {
  prepareCveSmartContractCases,
  prepareDefiHackLabsCases,
  prepareSmartBugsCases,
  runBenchmark,
  writeBenchmarkArtifacts
} from "./benchmark.js";
import type { BenchmarkDataset } from "./model.js";

const PINNED_REVISIONS: Record<BenchmarkDataset, string> = {
  SMARTBUGS_CURATED: "230e649123477eff332742a59a1c7cc6dc286cab",
  CVE_SMART_CONTRACTS: "1128b7aae666df541a5ffcf56782df17113c3d36",
  DEFIHACKLABS: "cb457812eacd4dad09bbd1b62a1fe2fcff1a8669"
};

function option(args: string[], name: string) {
  return args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
}

function intOption(args: string[], name: string, fallback: number, min: number, max: number) {
  const raw = option(args, name);
  const value = raw === undefined ? fallback : Number.parseInt(raw, 10);
  return Number.isSafeInteger(value) ? Math.max(min, Math.min(value, max)) : fallback;
}

export async function runBenchmarkCli(args: string[], defaultOutputDir: string) {
  const roots = {
    smartbugs: option(args, "smartbugs"),
    cve: option(args, "cve"),
    defihacklabs: option(args, "defihacklabs")
  };
  if (!roots.smartbugs && !roots.cve && !roots.defihacklabs) {
    throw new Error("Usage: risk-radar benchmark [--smartbugs=<dir>] [--cve=<dir>] [--defihacklabs=<dir>] [--max=5000] [--output=<dir>] [--reproduce-defihacklabs --trust-third-party-code]");
  }

  const maxCases = intOption(args, "max", 5_000, 1, 5_000);
  const cases = [];
  if (roots.smartbugs) cases.push(...await prepareSmartBugsCases(path.resolve(roots.smartbugs), { maxCases }));
  if (roots.cve) cases.push(...await prepareCveSmartContractCases(path.resolve(roots.cve), { maxCases }));
  if (roots.defihacklabs) cases.push(...await prepareDefiHackLabsCases(path.resolve(roots.defihacklabs), { maxCases }));

  const reproduce = args.includes("--reproduce-defihacklabs");
  const trusted = args.includes("--trust-third-party-code");
  if (reproduce && !trusted) {
    throw new Error("DeFiHackLabs reproduction executes third-party Foundry tests. Add --trust-third-party-code only after reviewing and trusting the local corpus.");
  }

  const metrics = await runBenchmark(cases, {
    trustReproduction: reproduce && trusted,
    reproductionTimeoutMs: intOption(args, "reproduction-timeout-seconds", 120, 5, 900) * 1_000,
    maxCases,
    datasetRevisions: PINNED_REVISIONS
  });
  const outputDir = path.resolve(option(args, "output") ?? path.join(defaultOutputDir, "benchmarks"));
  const paths = await writeBenchmarkArtifacts(metrics, outputDir);
  console.log(JSON.stringify({
    cases: metrics.cases,
    datasets: metrics.datasets,
    precision: metrics.precision,
    recall: metrics.recall,
    f1: metrics.f1,
    falsePositiveRate: metrics.falsePositiveRate,
    locationRecall: metrics.locationRecall,
    reproductionRate: metrics.reproductionRate,
    paths
  }, null, 2));
  return metrics.falseNegatives > 0 ? 3 : 0;
}
