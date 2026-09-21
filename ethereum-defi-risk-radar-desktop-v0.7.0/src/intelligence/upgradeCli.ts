import fs from "node:fs/promises";
import path from "node:path";
import type { Candidate } from "../types.js";
import { candidateToVersionedProtocolFacts, selectCandidateFromReport } from "./platform.js";
import { compareProtocolVersions } from "./upgrade.js";

type RiskRadarReport = { candidates?: Candidate[] };

function option(args: string[], name: string) {
  return args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
}

async function readReport(filePath: string): Promise<RiskRadarReport> {
  const resolved = path.resolve(filePath);
  const stat = await fs.stat(resolved);
  if (!stat.isFile() || stat.size > 100_000_000) throw new Error("Risk Radar report must be JSON no larger than 100 MB.");
  return JSON.parse(await fs.readFile(resolved, "utf8")) as RiskRadarReport;
}

export async function runUpgradeDiffCli(args: string[], defaultOutputDir: string) {
  const positional = args.filter(arg => !arg.startsWith("--"));
  if (positional.length < 2) {
    throw new Error("Usage: risk-radar upgrade-diff <before-report.json> <after-report.json> [--candidate=<id|label|hostname>] [--output=<file>]");
  }

  const [beforePath, afterPath] = positional;
  const selector = option(args, "candidate");
  const beforeCandidate = selectCandidateFromReport(await readReport(beforePath), selector);
  const afterCandidate = selectCandidateFromReport(await readReport(afterPath), selector ?? beforeCandidate.id);
  const comparison = compareProtocolVersions(
    candidateToVersionedProtocolFacts(beforeCandidate),
    candidateToVersionedProtocolFacts(afterCandidate)
  );

  const outputPath = path.resolve(
    option(args, "output") ??
    path.join(defaultOutputDir, "upgrades", `${beforeCandidate.id}-upgrade-${Date.now()}.json`)
  );
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify({
    protocol: { id: beforeCandidate.id, label: afterCandidate.label },
    comparison
  }, null, 2), "utf8");

  console.log(JSON.stringify({ outputPath, comparison }, null, 2));
  return comparison.highImpactChanges > 0 ? 3 : 0;
}
