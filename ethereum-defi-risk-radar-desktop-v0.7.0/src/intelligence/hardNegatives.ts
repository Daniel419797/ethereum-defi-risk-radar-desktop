import fs from "node:fs/promises";
import path from "node:path";
import type {
  BenchmarkCase
} from "./model.js";

export type HardNegativeManifestEntry = {
  id: string;
  sourcePath: string;
  family:
    | "authorization"
    | "reentrancy"
    | "oracle_risk"
    | "arithmetic"
    | "upgradeability"
    | "bridge_messaging"
    | "signature_replay"
    | "mev_ordering"
    | "token_integration"
    | "other";
  rationale: string;
  origin:
    | "PATCHED_VULNERABLE_SAMPLE"
    | "SAFE_FIXTURE"
    | "AUDITED_SAFE_PATTERN";
  sourceReference?: string;
};

export type HardNegativeManifest = {
  version: 1;
  entries: HardNegativeManifestEntry[];
};

function inside(
  root: string,
  relative: string
) {
  const resolvedRoot =
    path.resolve(root);
  const resolved =
    path.resolve(
      root,
      relative
    );
  if (
    resolved !== resolvedRoot &&
    !resolved.startsWith(
      resolvedRoot + path.sep
    )
  ) {
    throw new Error(
      "Hard-negative path escaped corpus root."
    );
  }
  return resolved;
}

export async function loadHardNegativeCorpus(
  root: string
): Promise<BenchmarkCase[]> {
  const manifestPath = inside(
    root,
    "risk-radar-hard-negatives.json"
  );
  const parsed = JSON.parse(
    await fs.readFile(
      manifestPath,
      "utf8"
    )
  ) as HardNegativeManifest;
  if (
    parsed.version !== 1 ||
    !Array.isArray(parsed.entries)
  ) {
    throw new Error(
      "Unsupported hard-negative manifest."
    );
  }

  const ids = new Set<string>();
  const cases: BenchmarkCase[] = [];
  for (const entry of parsed.entries.slice(
    0,
    10_000
  )) {
    if (
      !entry.id ||
      ids.has(entry.id) ||
      !entry.sourcePath ||
      !entry.rationale
    ) {
      throw new Error(
        "Invalid or duplicate hard-negative manifest entry."
      );
    }
    ids.add(entry.id);
    const source =
      inside(
        root,
        entry.sourcePath
      );
    const stat = await fs.stat(
      source
    );
    if (
      !stat.isFile() ||
      stat.size > 20_000_000
    ) {
      throw new Error(
        "Hard-negative source is unavailable or exceeds 20 MB: " +
          entry.sourcePath
      );
    }
    cases.push({
      id:
        "hard-negative:" +
        entry.id,
      corpus:
        "SMARTBUGS_CURATED",
      sourcePath:
        entry.sourcePath,
      labels: [],
      metadata: {
        hardNegative: true,
        family: entry.family,
        origin: entry.origin,
        rationale:
          entry.rationale.slice(
            0,
            1_000
          ),
        sourceReference:
          entry.sourceReference ||
          ""
      }
    });
  }
  return cases;
}
