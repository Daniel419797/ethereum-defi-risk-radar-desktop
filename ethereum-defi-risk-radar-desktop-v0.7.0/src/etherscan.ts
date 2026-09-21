import { inspectVerifiedSource, type SourceInspection } from "./sourceAnalyzer.js";
import { fetchJsonBounded } from "./boundedFetch.js";
import type { BytecodeAttestation } from "./intelligence/model.js";
import type { ReadOnlyChainReader } from "./intelligence/rpc.js";
import { attestRuntimeBytecode } from "./intelligence/bytecode.js";
import { analyzeRuntimeBytecode, type BytecodeAnalysisReport } from "./analysis/bytecode/analyzer.js";
import { reproduceVerifiedBuild } from "./intelligence/deterministicBuild.js";
import { profileVerifiedSourceLanguage, type SourceLanguageProfile } from "./intelligence/sourceLanguage.js";

export type EtherscanSourceMetadata = {
  verified: boolean;
  contractName?: string;
  compilerVersion?: string;
  proxy: boolean;
  implementationAddress?: string;
  sourceInspection?: SourceInspection;
  sourceLanguageProfile?: SourceLanguageProfile;
  bytecodeAnalysis?: BytecodeAnalysisReport;
  bytecodeAttestation?: BytecodeAttestation;
};

type EtherscanResponse = {
  status?: string;
  message?: string;
  result?:
    | Array<{
        SourceCode?: string;
        ContractName?: string;
        CompilerVersion?: string;
        OptimizationUsed?: string;
        Runs?: string;
        EVMVersion?: string;
        Library?: string;
        Proxy?: string;
        Implementation?: string;
      }>
    | string;
};

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

function parseLibraries(value?: string) {
  const libraries: Record<string, string> = {};
  for (const item of (value || "").split(/[;,]/)) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const separator = trimmed.lastIndexOf(":");
    if (separator <= 0) continue;
    const name = trimmed.slice(0, separator).trim();
    const address = trimmed.slice(separator + 1).trim();
    if (name && EVM_ADDRESS_RE.test(address)) {
      libraries[name] = address;
    }
  }
  return Object.keys(libraries).length ? libraries : undefined;
}

export class EtherscanClient {
  private readonly apiKey: string;
  private readonly endpoint = "https://api.etherscan.io/v2/api";

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async getSourceMetadata(
    address: string,
    opts?: {
      inspectSource?: boolean;
      maxSourceBytes?: number;
      maxFindings?: number;
      chainReader?: ReadOnlyChainReader;
      pinnedBlockNumber?: number;
      attestBytecode?: boolean;
      solcExecutable?: string;
    }
  ): Promise<EtherscanSourceMetadata> {
    const url = new URL(this.endpoint);
    url.searchParams.set("chainid", "1");
    url.searchParams.set("module", "contract");
    url.searchParams.set("action", "getsourcecode");
    url.searchParams.set("address", address);
    url.searchParams.set("apikey", this.apiKey);

    const responseLimit = Math.max(
      1_000_000,
      Math.min((opts?.maxSourceBytes ?? 2_000_000) + 500_000, 10_000_000)
    );
    const { response, payload } = await fetchJsonBounded<EtherscanResponse>(
      url,
      {
        headers: { Accept: "application/json" }
      },
      { timeoutMs: 30_000, maxBytes: responseLimit }
    );

    if (!response.ok) {
      throw new Error("Etherscan HTTP " + response.status);
    }

    if (payload.status === "0" && typeof payload.result === "string") {
      const detail =
        payload.result.trim() ||
        payload.message?.trim() ||
        "Unknown API error";
      throw new Error("Etherscan API error: " + detail.slice(0, 300));
    }

    const first = Array.isArray(payload.result)
      ? payload.result[0]
      : undefined;

    if (!first) {
      return { verified: false, proxy: false };
    }

    const source = (first.SourceCode ?? "").trim();
    const name = (first.ContractName ?? "").trim();
    const compilerVersion = (first.CompilerVersion ?? "").trim();
    const implementation = (first.Implementation ?? "").trim();
    const verified = Boolean(source || name);
    const proxy =
      first.Proxy === "1" ||
      Boolean(implementation);

    const sourceLanguageProfile =
      verified && source
        ? profileVerifiedSourceLanguage({
            source,
            compilerVersion
          })
        : undefined;

    let observedRuntimeBytecode: string | undefined;
    let bytecodeAnalysis: BytecodeAnalysisReport | undefined;
    let bytecodeAttestation: BytecodeAttestation | undefined;

    if (opts?.chainReader && opts.pinnedBlockNumber !== undefined) {
      try {
        const chainId = await opts.chainReader.getChainId();
        if (chainId !== 1) {
          throw new Error("Bytecode analysis requires Ethereum Mainnet chainId 1.");
        }
        observedRuntimeBytecode = await opts.chainReader.getCode(
          address,
          opts.pinnedBlockNumber
        );
        if (observedRuntimeBytecode !== "0x") {
          bytecodeAnalysis = analyzeRuntimeBytecode(observedRuntimeBytecode);
        }

        if (opts.attestBytecode) {
          if (
            verified &&
            source &&
            name &&
            compilerVersion &&
            observedRuntimeBytecode !== "0x"
          ) {
            const reproduction = await reproduceVerifiedBuild({
              rawSource: source,
              contractName: name,
              compilerVersion,
              observedRuntimeBytecode,
              optimizationUsed: first.OptimizationUsed === "1",
              runs: Number.parseInt(first.Runs || "200", 10),
              evmVersion: (first.EVMVersion ?? "").trim() || undefined,
              libraries: parseLibraries(first.Library),
              allowCachedContainer: true
            });
            bytecodeAttestation = reproduction.attestation;
          } else {
            bytecodeAttestation = attestRuntimeBytecode({
              observedRuntimeBytecode: observedRuntimeBytecode || null,
              compilerVersion: compilerVersion || undefined,
              unavailableReason:
                verified
                  ? "Verified source/compiler metadata was incomplete, so source-to-runtime equivalence was not claimed."
                  : "Source is not verified; deployed runtime bytecode was analyzed directly."
            });
          }
        }
      } catch (error) {
        if (opts.attestBytecode) {
          bytecodeAttestation = attestRuntimeBytecode({
            observedRuntimeBytecode: observedRuntimeBytecode || null,
            compilerVersion: compilerVersion || undefined,
            unavailableReason:
              "Bytecode analysis/attestation could not complete: " +
              (error instanceof Error ? error.message : String(error))
          });
        }
      }
    }

    const sourceInspection =
      verified &&
      source &&
      opts?.inspectSource &&
      sourceLanguageProfile?.language === "SOLIDITY"
        ? inspectVerifiedSource(source, {
            maxBytes: opts.maxSourceBytes,
            maxFindings: opts.maxFindings
          })
        : undefined;

    return {
      verified,
      contractName: name || undefined,
      compilerVersion:
        compilerVersion || undefined,
      proxy,
      implementationAddress:
        EVM_ADDRESS_RE.test(implementation)
          ? implementation
          : undefined,
      sourceInspection,
      sourceLanguageProfile,
      bytecodeAnalysis,
      bytecodeAttestation
    };
  }
}
