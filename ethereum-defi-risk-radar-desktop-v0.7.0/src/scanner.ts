import crypto from "node:crypto";
import type {
  Candidate,
  Evidence,
  SignalKind,
  SourceTrust,
  TinyFishResult
} from "./types.js";
import { TinyFishSearchClient } from "./tinyfish.js";
import { EtherscanClient } from "./etherscan.js";
import { detectSignals } from "./signals.js";

const PURPOSE =
  "Defensive Ethereum DeFi OSINT research: identify legacy, deprecated, archived, historically exploited, or publicly audited Ethereum Mainnet protocols for manual security review. Do not probe live contracts, test exploitability, or produce exploit instructions.";

export const QUERY_TEMPLATES = [
  `"Ethereum DeFi protocol" {year} deprecated migration`,
  `"Ethereum DeFi" {year} "no longer maintained" protocol`,
  `"Ethereum DeFi protocol" {year} audit "high severity"`,
  `"Ethereum DeFi protocol" {year} exploit postmortem`,
  `"Ethereum DeFi" {year} archived repository`,
  `"Ethereum DeFi protocol" {year} "admin key" security`,
  `"Ethereum Mainnet" DeFi {year} "upgradeable proxy"`,
  `"ERC-20" DeFi protocol {year} migration security`
];

export type ScanProgressEvent = {
  phase: "SEARCH" | "ENRICH";
  message: string;
  completed: number;
  total: number;
  overallPercent: number;
};

const NOISE_DOMAINS = [
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "tiktok.com",
  "pinterest.com"
];

const HIGH_TRUST_HOSTS = new Set([
  "etherscan.io",
  "github.com",
  "immunefi.com",
  "defillama.com",
  "consensys.io",
  "openzeppelin.com",
  "blog.openzeppelin.com",
  "trailofbits.com",
  "chainsecurity.com",
  "certora.com"
]);

const MEDIUM_TRUST_SUFFIXES = [
  ".org",
  ".foundation",
  ".finance"
];

const ETHEREUM_PATTERNS: Array<[string, RegExp]> = [
  ["ethereum", /\bethereum\b/i],
  ["mainnet", /\bethereum mainnet\b|\bmainnet\b/i],
  ["eth", /\bETH\b/],
  ["erc20", /\bERC[- ]?20\b/i],
  ["etherscan", /\betherscan\b/i],
  ["solidity", /\bsolidity\b/i],
  ["evm", /\bEVM\b/i]
];

const EVM_ADDRESS_RE = /\b0x[a-fA-F0-9]{40}\b/g;

function normalizeText(value?: string) {
  return (value ?? "").replace(/\s+/g, " ").trim();
}

function findEthereumTerms(text: string) {
  return ETHEREUM_PATTERNS.filter(([, re]) => re.test(text)).map(([name]) => name);
}

function extractAddresses(text: string) {
  return [...new Set(text.match(EVM_ADDRESS_RE) ?? [])];
}

function sanitizeSnippet(value?: string) {
  return normalizeText(value).replace(EVM_ADDRESS_RE, "[contract-address]");
}

function hostnameOf(urlString: string) {
  try {
    return new URL(urlString).hostname.replace(/^www\./, "");
  } catch {
    return "unknown";
  }
}

function sourceTrust(host: string): SourceTrust {
  if (HIGH_TRUST_HOSTS.has(host)) return "HIGH";
  if (MEDIUM_TRUST_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return "MEDIUM";
  }
  return "GENERAL";
}

function candidateKey(result: TinyFishResult) {
  const url = normalizeText(result.url);
  const host = hostnameOf(url);
  const title = normalizeText(result.title).toLowerCase();
  const normalizedTitle = title
    .replace(
      /\b(ethereum|defi|audit|security|postmortem|post-mortem|deprecated|migration|mainnet)\b/g,
      ""
    )
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .slice(0, 100);

  return crypto
    .createHash("sha256")
    .update(`${host}|${normalizedTitle}`)
    .digest("hex")
    .slice(0, 16);
}

function classify(score: number, signalCount: number): Candidate["classification"] {
  if (score >= 58 && signalCount >= 3) return "HIGH_RESEARCH_PRIORITY";
  if (score >= 30 && signalCount >= 2) return "REVIEW";
  return "LOW_PUBLIC_SIGNAL";
}

function ethereumConfidence(evidence: Evidence[]) {
  const termSet = new Set(evidence.flatMap(e => e.ethereumTerms));
  const ethereumNamed = termSet.has("ethereum") || termSet.has("mainnet");
  const ethSpecific = termSet.has("etherscan") || termSet.has("erc20");
  const trustBonus = evidence.some(e => e.sourceTrust === "HIGH");

  let score = ethereumNamed ? 55 : 35;
  score += Math.min(termSet.size * 6, 24);
  if (ethSpecific) score += 10;
  if (trustBonus) score += 8;
  return Math.min(score, 100);
}

export async function scanLegacyEthereumDefi(opts: {
  client: TinyFishSearchClient;
  etherscan?: EtherscanClient;
  startYear: number;
  endYear: number;
  pagesPerQuery: number;
  minPublicSignals: number;
  maxEtherscanLookupsPerCandidate: number;
  inspectVerifiedSource: boolean;
  maxSourceBytes: number;
  maxSourceFindings: number;
  onProgress?: (message: string) => void;
  onProgressEvent?: (event: ScanProgressEvent) => void;
}): Promise<Candidate[]> {
  const evidenceByCandidate = new Map<string, Evidence[]>();
  const metadataByCandidate = new Map<
    string,
    {
      label: string;
      hostname: string;
      addresses: Set<string>;
    }
  >();

  const searchTotal =
    (opts.endYear - opts.startYear + 1) * QUERY_TEMPLATES.length * opts.pagesPerQuery;
  let searchCompleted = 0;

  opts.onProgressEvent?.({
    phase: "SEARCH",
    message: "Preparing Ethereum OSINT search",
    completed: 0,
    total: searchTotal,
    overallPercent: 0
  });

  for (let year = opts.startYear; year <= opts.endYear; year++) {
    for (const template of QUERY_TEMPLATES) {
      const query = template.replace("{year}", String(year));

      for (let page = 0; page < opts.pagesPerQuery; page++) {
        opts.onProgress?.(`Searching Ethereum ${year}: ${query} [page ${page}]`);

        const response = await opts.client.search({
          query,
          purpose: PURPOSE,
          language: "en",
          afterDate: `${year}-01-01`,
          beforeDate: `${year}-12-31`,
          page,
          excludeDomains: NOISE_DOMAINS
        });

        searchCompleted += 1;
        opts.onProgressEvent?.({
          phase: "SEARCH",
          message: `Searched Ethereum ${year}: ${query}`,
          completed: searchCompleted,
          total: searchTotal,
          overallPercent: Math.min(
            70,
            Math.round((searchCompleted / Math.max(searchTotal, 1)) * 70)
          )
        });

        for (const result of response.results ?? []) {
          const url = normalizeText(result.url);
          if (!url.startsWith("http")) continue;

          const title = normalizeText(result.title) || hostnameOf(url);
          const rawSnippet = normalizeText(result.snippet);
          const rawText = `${title}\n${rawSnippet}\n${url}`;
          const ethereumTerms = findEthereumTerms(rawText);

          // All queries are Ethereum-specific, but we still require at least one Ethereum/EVM marker
          // in the returned result to avoid generic DeFi search noise.
          if (ethereumTerms.length === 0) continue;

          const signals = detectSignals(rawText);
          if (!signals.length) continue;

          const id = candidateKey(result);
          const host = hostnameOf(url);
          const addresses = extractAddresses(rawText);

          const currentMeta = metadataByCandidate.get(id) ?? {
            label: title,
            hostname: host,
            addresses: new Set<string>()
          };
          for (const address of addresses) currentMeta.addresses.add(address);
          metadataByCandidate.set(id, currentMeta);

          const existing = evidenceByCandidate.get(id) ?? [];
          for (const signal of signals) {
            const duplicate = existing.some(
              e =>
                e.kind === signal.kind &&
                e.sourceUrl === url &&
                e.query === query
            );
            if (!duplicate) {
              existing.push({
                kind: signal.kind,
                weight: signal.weight,
                sourceUrl: url,
                sourceTitle: title,
                sourceHost: host,
                sourceTrust: sourceTrust(host),
                snippet: sanitizeSnippet(rawSnippet),
                year,
                query,
                ethereumTerms,
                contractReferenceCount: addresses.length
              });
            }
          }
          evidenceByCandidate.set(id, existing);
        }
      }
    }
  }

  const candidates: Candidate[] = [];
  const evidenceEntries = [...evidenceByCandidate.entries()];
  let enrichCompleted = 0;

  if (evidenceEntries.length === 0) {
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: "No qualifying public evidence candidates to enrich",
      completed: 0,
      total: 0,
      overallPercent: 95
    });
  }

  for (const [id, evidence] of evidenceEntries) {
    const uniqueKinds = [...new Set(evidence.map(e => e.kind))] as SignalKind[];
    const uniqueSourceHosts = new Set(evidence.map(e => e.sourceHost));
    const signalCount = uniqueKinds.length;
    const ethConfidence = ethereumConfidence(evidence);

    if (signalCount < opts.minPublicSignals || ethConfidence < 55) {
      enrichCompleted += 1;
      opts.onProgressEvent?.({
        phase: "ENRICH",
        message: `Filtered low-confidence candidate ${enrichCompleted}/${evidenceEntries.length}`,
        completed: enrichCompleted,
        total: evidenceEntries.length,
        overallPercent:
          70 + Math.round((enrichCompleted / Math.max(evidenceEntries.length, 1)) * 25)
      });
      continue;
    }

    const kindWeights = new Map<SignalKind, number>();
    for (const item of evidence) {
      kindWeights.set(
        item.kind,
        Math.max(kindWeights.get(item.kind) ?? 0, item.weight)
      );
    }

    let researchScore = [...kindWeights.values()].reduce((a, b) => a + b, 0);
    researchScore += Math.min(uniqueSourceHosts.size * 3, 12);
    researchScore += evidence.some(e => e.sourceTrust === "HIGH") ? 5 : 0;
    researchScore = Math.min(researchScore, 100);

    const metadata = metadataByCandidate.get(id)!;
    const contractReferencesObserved = metadata.addresses.size;
    let etherscanLookupsAttempted = 0;
    let verifiedSourceContracts = 0;
    let proxyContracts = 0;
    let sourceContractsInspected = 0;
    let sourceFindingCount = 0;
    let sourceHighReviewCount = 0;
    let advancedFindingCount = 0;
    const sourceInspections: Candidate["ethereum"]["sourceInspections"] = [];

    if (opts.etherscan && contractReferencesObserved > 0) {
      const selected = [...metadata.addresses].slice(
        0,
        opts.maxEtherscanLookupsPerCandidate
      );

      for (const address of selected) {
        etherscanLookupsAttempted += 1;
        try {
          const source = await opts.etherscan.getSourceMetadata(address, {
            inspectSource: opts.inspectVerifiedSource,
            maxSourceBytes: opts.maxSourceBytes,
            maxFindings: opts.maxSourceFindings
          });
          if (source.verified) verifiedSourceContracts += 1;
          if (source.proxy) proxyContracts += 1;
          if (source.sourceInspection) {
            sourceContractsInspected += 1;
            sourceFindingCount += source.sourceInspection.findingCount;
            sourceHighReviewCount += source.sourceInspection.severityCounts.HIGH_REVIEW;
            advancedFindingCount += source.sourceInspection.advancedAnalysis.findings.length;
            sourceInspections.push({
              contractRefId: crypto
                .createHash("sha256")
                .update(address.toLowerCase())
                .digest("hex")
                .slice(0, 12),
              contractName: source.contractName,
              compilerVersion: source.compilerVersion,
              proxy: source.proxy,
              inspection: source.sourceInspection
            });
          }
        } catch {
          // Etherscan enrichment is optional and must not fail the OSINT scan.
        }
      }
    }

    candidates.push({
      id,
      label: metadata.label,
      hostname: metadata.hostname,
      chain: "ethereum",
      network: "mainnet",
      researchScore,
      ethereumConfidence: ethConfidence,
      signalCount,
      sourceDiversity: uniqueSourceHosts.size,
      kinds: uniqueKinds,
      evidence: evidence.sort((a, b) => b.weight - a.weight).slice(0, 16),
      ethereum: {
        chainId: 1,
        network: "ethereum-mainnet",
        contractReferencesObserved,
        etherscanLookupsAttempted,
        verifiedSourceContracts,
        proxyContracts,
        sourceContractsInspected,
        sourceFindingCount,
        sourceHighReviewCount,
        advancedFindingCount,
        sourceInspections
      },
      classification: classify(researchScore, signalCount)
    });

    enrichCompleted += 1;
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: `Reviewed candidate ${enrichCompleted}/${evidenceEntries.length}`,
      completed: enrichCompleted,
      total: evidenceEntries.length,
      overallPercent:
        70 + Math.round((enrichCompleted / Math.max(evidenceEntries.length, 1)) * 25)
    });
  }

  return candidates.sort((a, b) => {
    if (b.researchScore !== a.researchScore) {
      return b.researchScore - a.researchScore;
    }
    return b.ethereumConfidence - a.ethereumConfidence;
  });
}
