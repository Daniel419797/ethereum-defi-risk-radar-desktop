try {
  process.loadEnvFile?.(".env");
} catch {
  // .env is optional; normal environment variables still work.
}

import { TinyFishSearchClient } from "./tinyfish.js";
import { EtherscanClient } from "./etherscan.js";
import { scanLegacyEthereumDefi } from "./scanner.js";
import { writeReports } from "./report.js";

function getArg(name: string) {
  const prefix = `--${name}=`;
  const value = process.argv.find(arg => arg.startsWith(prefix));
  return value ? value.slice(prefix.length) : undefined;
}

function toInt(value: string | undefined, fallback: number) {
  if (!value) return fallback;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

async function main() {
  const apiKey = process.env.TINYFISH_API_KEY ?? "";
  const endpoint =
    process.env.TINYFISH_SEARCH_ENDPOINT ??
    "https://api.search.tinyfish.ai";

  const currentYear = new Date().getUTCFullYear();
  const startYear = toInt(getArg("start"), 2016);
  const endYear = Math.min(toInt(getArg("end"), currentYear), currentYear);
  const pagesPerQuery = Math.max(
    1,
    Math.min(
      toInt(
        getArg("pages"),
        toInt(process.env.MAX_PAGES_PER_QUERY, 1)
      ),
      10
    )
  );
  const minPublicSignals = Math.max(
    2,
    toInt(process.env.MIN_PUBLIC_SIGNALS, 2)
  );
  const maxEtherscanLookupsPerCandidate = Math.max(
    0,
    Math.min(
      toInt(process.env.MAX_ETHERSCAN_LOOKUPS_PER_CANDIDATE, 2),
      5
    )
  );
  const inspectVerifiedSource =
    (process.env.INSPECT_VERIFIED_SOURCE ?? "true").toLowerCase() !== "false";
  const maxSourceBytes = Math.max(
    10_000,
    Math.min(toInt(process.env.MAX_SOURCE_BYTES, 2_000_000), 5_000_000)
  );
  const maxSourceFindings = Math.max(
    1,
    Math.min(toInt(process.env.MAX_SOURCE_FINDINGS_PER_CONTRACT, 80), 250)
  );
  const outputDir = process.env.OUTPUT_DIR ?? "reports";

  if (startYear < 2016) {
    throw new Error("Start year must be 2016 or later.");
  }
  if (endYear < startYear) {
    throw new Error("End year must be >= start year.");
  }

  const client = new TinyFishSearchClient({ apiKey, endpoint });
  const etherscan = process.env.ETHERSCAN_API_KEY
    ? new EtherscanClient(process.env.ETHERSCAN_API_KEY)
    : undefined;

  console.log(
    `Ethereum DeFi Risk Radar: Ethereum Mainnet (chain 1), ${startYear}-${endYear}`
  );
  console.log(
    `TinyFish pages/query: ${pagesPerQuery}; Etherscan enrichment: ${etherscan ? "ON" : "OFF"}; verified-source inspection: ${etherscan && inspectVerifiedSource ? "ON" : "OFF"}`
  );
  console.log(
    "Findings are public risk signals for authorized/manual review, not proof of an exploitable vulnerability.\n"
  );

  const candidates = await scanLegacyEthereumDefi({
    client,
    etherscan,
    startYear,
    endYear,
    pagesPerQuery,
    minPublicSignals,
    maxEtherscanLookupsPerCandidate,
    inspectVerifiedSource,
    maxSourceBytes,
    maxSourceFindings,
    onProgress: msg => console.log(msg)
  });

  const paths = await writeReports({
    candidates,
    outputDir,
    startYear,
    endYear
  });

  console.log(`\nEthereum candidates: ${candidates.length}`);
  console.table(
    candidates.slice(0, 25).map(c => ({
      score: c.researchScore,
      eth: c.ethereumConfidence,
      class: c.classification,
      signals: c.kinds.join(", "),
      sources: c.sourceDiversity,
      verified: c.ethereum.verifiedSourceContracts,
      proxy: c.ethereum.proxyContracts,
      inspected: c.ethereum.sourceContractsInspected,
      sourceFlags: c.ethereum.sourceFindingCount,
      highReview: c.ethereum.sourceHighReviewCount,
      label: c.label.slice(0, 54)
    }))
  );

  console.log(`JSON: ${paths.jsonPath}`);
  console.log(`CSV:  ${paths.csvPath}`);
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
