import { scanLegacyEthereumDefi } from "../dist/scanner.js";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";

const proxyAddress = "0x1111111111111111111111111111111111111111";
const implementationAddress = "0x2222222222222222222222222222222222222222";
const implementationInspection = inspectVerifiedSource(
  "pragma solidity ^0.8.20; contract EulerPool { function unsafe(address target) external { target.call(\"\"); } }"
);

const searchCalls = [];
const mockClient = {
  search: async input => {
    searchCalls.push(input);
    if (Array.isArray(input.includeDomains) && input.includeDomains.includes("etherscan.io")) {
      return {
        results: [
          {
            title: "Euler Finance Mainnet contract",
            url: `https://etherscan.io/address/${proxyAddress}`,
            snippet: `Verified Ethereum contract ${proxyAddress}`,
            site_name: "Etherscan"
          }
        ]
      };
    }

    return {
      results: [
        {
          title: "Survey on Quality Assurance of Smart Contracts",
          url: "https://arxiv.org/abs/2601.00001",
          snippet: "Ethereum high severity security review and exploit postmortem.",
          site_name: "arXiv"
        },
        {
          title: "Consensys/ethereum-developer-tools-list: Ethereum developer tools",
          url: "https://github.com/Consensys/ethereum-developer-tools-list",
          snippet: "Ethereum protocol security review, high severity audit finding, exploit postmortem.",
          site_name: "GitHub"
        },
        {
          title: "Euler Finance Security Review",
          url: "https://security.example/euler-finance-review",
          snippet: "Ethereum Mainnet protocol audit finding with high severity issues, an exploit postmortem, and a deprecated legacy deployment.",
          site_name: "Security Example"
        }
      ]
    };
  }
};

const etherscanCalls = [];
const mockEtherscan = {
  getSourceMetadata: async (address, opts) => {
    etherscanCalls.push({ address, opts });
    if (address.toLowerCase() === proxyAddress.toLowerCase()) {
      return {
        verified: true,
        contractName: "EulerProxy",
        compilerVersion: "v0.8.20",
        proxy: true,
        implementationAddress
      };
    }
    if (address.toLowerCase() === implementationAddress.toLowerCase()) {
      return {
        verified: true,
        contractName: "EulerPool",
        compilerVersion: "v0.8.20",
        proxy: false,
        sourceInspection: implementationInspection
      };
    }
    return { verified: false, proxy: false };
  }
};

const progress = [];
const candidates = await scanLegacyEthereumDefi({
  client: mockClient,
  etherscan: mockEtherscan,
  startYear: 2022,
  endYear: 2022,
  pagesPerQuery: 1,
  minPublicSignals: 2,
  maxEtherscanLookupsPerCandidate: 2,
  inspectVerifiedSource: true,
  maxSourceBytes: 2_000_000,
  maxSourceFindings: 80,
  onProgressEvent: event => progress.push(event)
});

if (candidates.length !== 1) {
  throw new Error(`Expected exactly one resolved protocol candidate, received ${candidates.length}.`);
}

const candidate = candidates[0];
if (candidate.entityKind !== "PROTOCOL") throw new Error("Resolved result must be a protocol entity.");
if (candidate.label !== "Euler Finance") throw new Error(`Unexpected protocol label: ${candidate.label}`);
if (candidate.resolutionStatus !== "SOURCE_ANALYZED") throw new Error(`Unexpected resolution status: ${candidate.resolutionStatus}`);
if (candidate.ethereum.contractReferencesObserved !== 1) throw new Error("Protocol deployment reference was not resolved.");
if (candidate.ethereum.verifiedSourceContracts !== 2) throw new Error("Proxy and implementation verified-source metadata were not both captured.");
if (candidate.ethereum.proxyImplementationsResolved !== 1) throw new Error("Proxy implementation resolution did not occur.");
if (candidate.ethereum.sourceContractsInspected !== 1) throw new Error("Implementation source was not inspected.");
if (!candidate.resolutionEvidence.length) throw new Error("Contract-resolution evidence is missing.");
if (candidates.some(item => /survey|developer tools/i.test(item.label))) {
  throw new Error("Document-only search results were promoted to protocol candidates.");
}
if (etherscanCalls.length !== 2) throw new Error(`Expected bounded proxy + implementation Etherscan lookups, received ${etherscanCalls.length}.`);
if (!searchCalls.some(call => Array.isArray(call.includeDomains) && call.includeDomains.includes("etherscan.io"))) {
  throw new Error("Protocol resolver did not perform an Etherscan-targeted search.");
}
if (progress.at(-1)?.overallPercent !== 95) throw new Error("Protocol resolution progress did not reach the pre-report boundary.");

const noEtherscanProgress = [];
const withoutEtherscan = await scanLegacyEthereumDefi({
  client: mockClient,
  startYear: 2022,
  endYear: 2022,
  pagesPerQuery: 1,
  minPublicSignals: 2,
  maxEtherscanLookupsPerCandidate: 2,
  inspectVerifiedSource: true,
  maxSourceBytes: 2_000_000,
  maxSourceFindings: 80,
  onProgressEvent: event => noEtherscanProgress.push(event)
});
if (withoutEtherscan.length !== 0) {
  throw new Error("Document leads must not become protocol candidates without Etherscan verification.");
}
if (!/not configured/i.test(noEtherscanProgress.at(-1)?.message ?? "")) {
  throw new Error("Missing explicit no-Etherscan promotion warning.");
}

console.log("Protocol discovery checks passed: document rejection, protocol resolution, Etherscan verification, proxy implementation handoff, source analysis, and fail-closed promotion.");
