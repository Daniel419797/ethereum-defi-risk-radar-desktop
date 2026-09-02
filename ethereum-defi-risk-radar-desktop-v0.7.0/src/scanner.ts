import crypto from "node:crypto";
import type {
  Candidate,
  Evidence,
  ProtocolResolutionEvidence,
  SignalKind,
  SourceTrust,
  TinyFishResult
} from "./types.js";
import { TinyFishSearchClient } from "./tinyfish.js";
import { EtherscanClient } from "./etherscan.js";
import { detectSignals } from "./signals.js";

const PURPOSE =
  "Defensive Ethereum DeFi OSINT research: use public documents only as leads, then promote a result to a protocol candidate only after resolving an Ethereum Mainnet deployment and validating verified source with Etherscan. Do not probe live contracts, test exploitability, or produce exploit instructions.";

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

const RESOLUTION_QUERY_TEMPLATES = [
  `"{protocol}" Ethereum Mainnet Etherscan address`,
  `"{protocol}" contract Etherscan Ethereum`
];

export type ScanProgressEvent = {
  phase: "SEARCH" | "ENRICH";
  message: string;
  completed: number;
  total: number;
  overallPercent: number;
};

export type EtherscanSourceClient = Pick<EtherscanClient, "getSourceMetadata">;

const NOISE_DOMAINS = [
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "tiktok.com",
  "pinterest.com"
];

const DOCUMENT_ONLY_HOSTS = new Set([
  "arxiv.org",
  "dl.acm.org",
  "ieeexplore.ieee.org",
  "researchgate.net",
  "semanticscholar.org",
  "sciencedirect.com",
  "link.springer.com"
]);

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
const EVM_ADDRESS_EXACT_RE = /^0x[a-fA-F0-9]{40}$/;
const MAX_PROTOCOL_GROUPS_TO_RESOLVE = 40;
const MAX_RESOLVED_ADDRESSES_PER_PROTOCOL = 8;

const GENERIC_DOCUMENT_PATTERNS = [
  /\bsurvey\b/i,
  /\bcharacteri[sz](?:e|ed|ing|ation)\b/i,
  /\bquality assurance\b/i,
  /\bdeveloper tools?\b/i,
  /\btools? list\b/i,
  /\bawesome[- ]list\b/i,
  /\bsystematic review\b/i,
  /\bliterature review\b/i,
  /\bresearch paper\b/i,
  /\bbenchmark\b/i,
  /\bdataset\b/i,
  /\btaxonomy\b/i,
  /\btutorial\b/i
];

const PUBLISHER_NAMES = new Set([
  "openzeppelin",
  "trail of bits",
  "trailofbits",
  "chainsecurity",
  "immunefi",
  "blocksec",
  "consensys",
  "certora",
  "sherlock",
  "halborn",
  "code4rena"
]);

const GENERIC_REPOSITORY_TOKENS = new Set([
  "awesome",
  "list",
  "lists",
  "tool",
  "tools",
  "developer",
  "developers",
  "resources",
  "resource",
  "docs",
  "documentation",
  "examples",
  "example",
  "tutorial",
  "tutorials",
  "papers",
  "research",
  "security"
]);

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

function isHttpsUrl(urlString: string) {
  try {
    return new URL(urlString).protocol === "https:";
  } catch {
    return false;
  }
}

function isTrustedEtherscanUrl(urlString: string) {
  return isHttpsUrl(urlString) && hostnameOf(urlString) === "etherscan.io";
}

function sourceTrust(host: string): SourceTrust {
  if (HIGH_TRUST_HOSTS.has(host)) return "HIGH";
  if (MEDIUM_TRUST_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return "MEDIUM";
  }
  return "GENERAL";
}

function words(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

function titleCaseSlug(value: string) {
  return value
    .replace(/\.git$/i, "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, char => char.toUpperCase());
}

function isGenericRepositoryName(value: string) {
  const tokens = words(value);
  if (!tokens.length) return true;
  const genericCount = tokens.filter(token => GENERIC_REPOSITORY_TOKENS.has(token)).length;
  return genericCount >= Math.max(2, Math.ceil(tokens.length * 0.5));
}

function cleanProtocolLabel(title: string, siteName?: string) {
  let pieces = title
    .split(/\s+[|—–]\s+|\s+-\s+|:\s+/)
    .map(piece => normalizeText(piece))
    .filter(Boolean);

  const normalizedSite = normalizeText(siteName).toLowerCase();
  if (
    pieces.length > 1 &&
    (PUBLISHER_NAMES.has(pieces[0].toLowerCase()) ||
      (normalizedSite && pieces[0].toLowerCase() === normalizedSite))
  ) {
    pieces = pieces.slice(1);
  }

  let candidate = pieces[0] ?? title;
  candidate = candidate
    .replace(
      /^(?:security\s+)?(?:audit|review|assessment|analysis|post[- ]?mortem|incident report)\s+(?:of|for)\s+/i,
      ""
    )
    .replace(
      /\b(?:smart contract )?(?:security )?(?:audit(?: report)?|security review|security assessment|exploit post[- ]?mortem|post[- ]?mortem|incident report|vulnerability report)\b.*$/i,
      ""
    )
    .replace(/\s*[:|—–-]\s*(?:audit|security|review|post[- ]?mortem|incident|analysis)\b.*$/i, "")
    .replace(/^ethereum\s*[:|-]\s*/i, "")
    .replace(/^defi\s*[:|-]\s*/i, "")
    .replace(/[\s:|—–-]+$/g, "")
    .trim();

  if (!candidate || candidate.length < 2 || candidate.length > 90) return null;
  const candidateWords = words(candidate);
  if (!candidateWords.length || candidateWords.length > 8) return null;

  const genericOnly = candidateWords.every(token =>
    [
      "ethereum",
      "defi",
      "smart",
      "contract",
      "contracts",
      "protocol",
      "security",
      "audit",
      "review",
      "mainnet",
      "solidity",
      "erc20",
      "risk"
    ].includes(token)
  );
  return genericOnly ? null : candidate;
}

function inferProtocolIdentity(result: TinyFishResult) {
  const url = normalizeText(result.url);
  const host = hostnameOf(url);
  const title = normalizeText(result.title);
  if (!title || DOCUMENT_ONLY_HOSTS.has(host)) return null;
  if (GENERIC_DOCUMENT_PATTERNS.some(pattern => pattern.test(title))) return null;

  if (host === "github.com") {
    try {
      const parsed = new URL(url);
      const [owner, repo] = parsed.pathname.split("/").filter(Boolean);
      if (!owner || !repo || isGenericRepositoryName(repo)) return null;
      const label = titleCaseSlug(repo);
      return { key: protocolKey(label), label };
    } catch {
      return null;
    }
  }

  const label = cleanProtocolLabel(title, result.site_name);
  return label ? { key: protocolKey(label), label } : null;
}

function protocolKey(label: string) {
  return label
    .toLowerCase()
    .replace(/\b(ethereum|mainnet|defi)\b/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function protocolId(key: string) {
  return crypto.createHash("sha256").update(`protocol|${key}`).digest("hex").slice(0, 16);
}

function contractRefId(address: string) {
  return crypto
    .createHash("sha256")
    .update(address.toLowerCase())
    .digest("hex")
    .slice(0, 12);
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

function researchScoreFor(evidence: Evidence[]) {
  const kindWeights = new Map<SignalKind, number>();
  for (const item of evidence) {
    kindWeights.set(item.kind, Math.max(kindWeights.get(item.kind) ?? 0, item.weight));
  }
  const uniqueSourceHosts = new Set(evidence.map(e => e.sourceHost));
  let score = [...kindWeights.values()].reduce((a, b) => a + b, 0);
  score += Math.min(uniqueSourceHosts.size * 3, 12);
  score += evidence.some(e => e.sourceTrust === "HIGH") ? 5 : 0;
  return Math.min(score, 100);
}

type ProtocolLead = {
  key: string;
  label: string;
  hostname: string;
  addresses: Set<string>;
  evidence: Evidence[];
  resolutionEvidence: ProtocolResolutionEvidence[];
};

async function resolveProtocolAddresses(opts: {
  client: TinyFishSearchClient;
  lead: ProtocolLead;
  onProgress?: (message: string) => void;
}) {
  const addresses = new Set(opts.lead.addresses);
  const evidence = [...opts.lead.resolutionEvidence];

  for (const template of RESOLUTION_QUERY_TEMPLATES) {
    if (addresses.size >= MAX_RESOLVED_ADDRESSES_PER_PROTOCOL) break;
    const query = template.replace("{protocol}", opts.lead.label);
    opts.onProgress?.(`Resolving ${opts.lead.label}: ${query}`);

    try {
      const response = await opts.client.search({
        query,
        purpose: PURPOSE,
        language: "en",
        page: 0,
        includeDomains: ["etherscan.io"],
        excludeDomains: NOISE_DOMAINS
      });

      for (const result of response.results ?? []) {
        const url = normalizeText(result.url);
        if (!isTrustedEtherscanUrl(url)) continue;
        const title = normalizeText(result.title) || hostnameOf(url);
        const rawText = `${title}\n${normalizeText(result.snippet)}\n${url}`;
        const found = extractAddresses(rawText);
        if (!found.length) continue;

        for (const address of found) {
          if (addresses.size >= MAX_RESOLVED_ADDRESSES_PER_PROTOCOL) break;
          addresses.add(address);
        }

        evidence.push({
          sourceUrl: url,
          sourceTitle: title,
          sourceHost: hostnameOf(url),
          sourceTrust: sourceTrust(hostnameOf(url)),
          query,
          contractReferenceCount: found.length
        });
      }
    } catch (error) {
      opts.onProgress?.(
        `Resolution search failed for ${opts.lead.label}: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  return { addresses: [...addresses], evidence };
}

export async function scanLegacyEthereumDefi(opts: {
  client: TinyFishSearchClient;
  etherscan?: EtherscanSourceClient;
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
  const leads = new Map<string, ProtocolLead>();

  const searchTotal =
    (opts.endYear - opts.startYear + 1) * QUERY_TEMPLATES.length * opts.pagesPerQuery;
  let searchCompleted = 0;

  opts.onProgressEvent?.({
    phase: "SEARCH",
    message: "Preparing Ethereum OSINT lead search",
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
            65,
            Math.round((searchCompleted / Math.max(searchTotal, 1)) * 65)
          )
        });

        for (const result of response.results ?? []) {
          const url = normalizeText(result.url);
          if (!isHttpsUrl(url)) continue;

          const identity = inferProtocolIdentity(result);
          if (!identity?.key) continue;

          const title = normalizeText(result.title) || hostnameOf(url);
          const rawSnippet = normalizeText(result.snippet);
          const rawText = `${title}\n${rawSnippet}\n${url}`;
          const ethereumTerms = findEthereumTerms(rawText);
          if (ethereumTerms.length === 0) continue;

          const signals = detectSignals(rawText);
          if (!signals.length) continue;

          const host = hostnameOf(url);
          const current = leads.get(identity.key) ?? {
            key: identity.key,
            label: identity.label,
            hostname: host,
            addresses: new Set<string>(),
            evidence: [],
            resolutionEvidence: []
          };

          // Only an Etherscan result is trusted as a direct deployment reference. Addresses
          // mentioned inside reports/posts may describe attackers, tokens, or unrelated systems.
          if (host === "etherscan.io") {
            const directAddresses = extractAddresses(rawText);
            for (const address of directAddresses) current.addresses.add(address);
            if (directAddresses.length) {
              current.resolutionEvidence.push({
                sourceUrl: url,
                sourceTitle: title,
                sourceHost: host,
                sourceTrust: sourceTrust(host),
                query,
                contractReferenceCount: directAddresses.length
              });
            }
          }

          for (const signal of signals) {
            const duplicate = current.evidence.some(
              e => e.kind === signal.kind && e.sourceUrl === url && e.query === query
            );
            if (!duplicate) {
              current.evidence.push({
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
                contractReferenceCount: extractAddresses(rawText).length
              });
            }
          }

          leads.set(identity.key, current);
        }
      }
    }
  }

  const qualifiedLeads = [...leads.values()]
    .map(lead => {
      const uniqueKinds = [...new Set(lead.evidence.map(e => e.kind))] as SignalKind[];
      const confidence = ethereumConfidence(lead.evidence);
      return {
        lead,
        uniqueKinds,
        confidence,
        score: researchScoreFor(lead.evidence)
      };
    })
    .filter(item => item.uniqueKinds.length >= opts.minPublicSignals && item.confidence >= 55)
    .sort((a, b) => b.score - a.score || b.confidence - a.confidence)
    .slice(0, MAX_PROTOCOL_GROUPS_TO_RESOLVE);

  if (!opts.etherscan || opts.maxEtherscanLookupsPerCandidate <= 0) {
    const reason = !opts.etherscan
      ? "Etherscan is not configured; document leads were not promoted to protocol candidates."
      : "Etherscan lookup budget is zero; document leads were not promoted to protocol candidates.";
    opts.onProgress?.(reason);
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: reason,
      completed: 0,
      total: qualifiedLeads.length,
      overallPercent: 95
    });
    return [];
  }

  if (qualifiedLeads.length === 0) {
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: "No protocol-shaped public leads qualified for contract resolution",
      completed: 0,
      total: 0,
      overallPercent: 95
    });
    return [];
  }

  const candidates: Candidate[] = [];
  let enrichCompleted = 0;

  for (const item of qualifiedLeads) {
    const { lead, uniqueKinds, confidence, score } = item;
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: `Resolving Ethereum Mainnet contracts for ${lead.label}`,
      completed: enrichCompleted,
      total: qualifiedLeads.length,
      overallPercent:
        65 + Math.round((enrichCompleted / Math.max(qualifiedLeads.length, 1)) * 30)
    });

    const resolved = await resolveProtocolAddresses({
      client: opts.client,
      lead,
      onProgress: opts.onProgress
    });

    const uniqueAddresses = [...new Set(resolved.addresses.map(address => address.toLowerCase()))]
      .filter(address => EVM_ADDRESS_EXACT_RE.test(address));

    let etherscanLookupsAttempted = 0;
    let verifiedSourceContracts = 0;
    let proxyContracts = 0;
    let proxyImplementationsResolved = 0;
    let sourceContractsInspected = 0;
    let sourceFindingCount = 0;
    let sourceHighReviewCount = 0;
    let advancedFindingCount = 0;
    const sourceInspections: Candidate["ethereum"]["sourceInspections"] = [];
    const lookedUpAddresses = new Set<string>();

    for (const rootAddress of uniqueAddresses) {
      if (etherscanLookupsAttempted >= opts.maxEtherscanLookupsPerCandidate) break;
      let currentAddress: string | undefined = rootAddress;
      const rootRef = contractRefId(rootAddress);
      let depth = 0;

      while (
        currentAddress &&
        depth <= 2 &&
        etherscanLookupsAttempted < opts.maxEtherscanLookupsPerCandidate
      ) {
        const normalizedAddress = currentAddress.toLowerCase();
        if (lookedUpAddresses.has(normalizedAddress)) break;
        lookedUpAddresses.add(normalizedAddress);
        etherscanLookupsAttempted += 1;

        try {
          const source = await opts.etherscan.getSourceMetadata(currentAddress, {
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
              contractRefId: contractRefId(currentAddress),
              rootContractRefId: rootRef,
              sourceRole: depth === 0 ? (source.proxy ? "PROXY" : "DIRECT") : "IMPLEMENTATION",
              contractName: source.contractName,
              compilerVersion: source.compilerVersion,
              proxy: source.proxy,
              inspection: source.sourceInspection
            });
          }

          const implementationAddress = source.implementationAddress?.trim();
          if (
            source.proxy &&
            implementationAddress &&
            EVM_ADDRESS_EXACT_RE.test(implementationAddress) &&
            implementationAddress.toLowerCase() !== normalizedAddress &&
            !lookedUpAddresses.has(implementationAddress.toLowerCase())
          ) {
            proxyImplementationsResolved += 1;
            currentAddress = implementationAddress;
            depth += 1;
            continue;
          }
        } catch (error) {
          opts.onProgress?.(
            `Etherscan validation failed for ${lead.label}: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        }

        break;
      }
    }

    // Documents are leads only. A row reaches Results only after at least one actual
    // Mainnet address returns verified source metadata from Etherscan.
    if (verifiedSourceContracts > 0) {
      candidates.push({
        id: protocolId(lead.key),
        entityKind: "PROTOCOL",
        resolutionStatus:
          sourceContractsInspected > 0 ? "SOURCE_ANALYZED" : "CONTRACTS_VERIFIED",
        label: lead.label,
        hostname: lead.hostname,
        chain: "ethereum",
        network: "mainnet",
        researchScore: score,
        ethereumConfidence: confidence,
        signalCount: uniqueKinds.length,
        sourceDiversity: new Set(lead.evidence.map(e => e.sourceHost)).size,
        kinds: uniqueKinds,
        evidence: lead.evidence.sort((a, b) => b.weight - a.weight).slice(0, 16),
        resolutionEvidence: resolved.evidence.slice(0, 12),
        ethereum: {
          chainId: 1,
          network: "ethereum-mainnet",
          contractReferencesObserved: uniqueAddresses.length,
          etherscanLookupsAttempted,
          verifiedSourceContracts,
          proxyContracts,
          proxyImplementationsResolved,
          sourceContractsInspected,
          sourceFindingCount,
          sourceHighReviewCount,
          advancedFindingCount,
          sourceInspections
        },
        classification: classify(score, uniqueKinds.length)
      });
    } else {
      opts.onProgress?.(`Filtered unresolved lead: ${lead.label}`);
    }

    enrichCompleted += 1;
    opts.onProgressEvent?.({
      phase: "ENRICH",
      message: `Resolved protocol lead ${enrichCompleted}/${qualifiedLeads.length}`,
      completed: enrichCompleted,
      total: qualifiedLeads.length,
      overallPercent:
        65 + Math.round((enrichCompleted / Math.max(qualifiedLeads.length, 1)) * 30)
    });
  }

  return candidates.sort((a, b) => {
    if (b.researchScore !== a.researchScore) {
      return b.researchScore - a.researchScore;
    }
    return b.ethereumConfidence - a.ethereumConfidence;
  });
}
