import { inspectVerifiedSource, type SourceInspection } from "./sourceAnalyzer.js";
import { fetchJsonBounded } from "./boundedFetch.js";
import type { BytecodeAttestation } from "./intelligence/model.js";
import type { ReadOnlyChainReader } from "./intelligence/rpc.js";
import { attestRuntimeBytecode } from "./intelligence/bytecode.js";
import { attestVerifiedSourceWithLocalSolc } from "./intelligence/solcAttestation.js";

export type EtherscanSourceMetadata = {
  verified: boolean;
  contractName?: string;
  compilerVersion?: string;
  proxy: boolean;
  implementationAddress?: string;
  sourceInspection?: SourceInspection;
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
        Proxy?: string;
        Implementation?: string;
      }>
    | string;
};

const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

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

    let bytecodeAttestation: BytecodeAttestation | undefined;
    if (opts?.chainReader && opts.attestBytecode) {
      try {
        const chainId = await opts.chainReader.getChainId();
        if (chainId !== 1) {
          throw new Error(
            "Bytecode attestation requires Ethereum Mainnet chainId 1."
          );
        }

        const blockNumber =
          opts.pinnedBlockNumber ??
          (await opts.chainReader.getBlock("latest")).number;
        const observedRuntimeBytecode =
          await opts.chainReader.getCode(address, blockNumber);

        if (
          verified &&
          source &&
          name &&
          compilerVersion
        ) {
          bytecodeAttestation =
            await attestVerifiedSourceWithLocalSolc({
              rawSource: source,
              contractName: name,
              compilerVersion,
              observedRuntimeBytecode,
              optimizationUsed:
                first.OptimizationUsed === "1",
              runs: Number.parseInt(
                first.Runs || "200",
                10
              ),
              evmVersion:
                (first.EVMVersion ?? "").trim() ||
                undefined,
              executable: opts.solcExecutable
            });
        } else {
          bytecodeAttestation =
            attestRuntimeBytecode({
              observedRuntimeBytecode,
              compilerVersion:
                compilerVersion || undefined,
              unavailableReason:
                "Verified source/compiler metadata was incomplete, so only deployed runtime bytecode was observed."
            });
        }
      } catch (error) {
        bytecodeAttestation =
          attestRuntimeBytecode({
            observedRuntimeBytecode: null,
            compilerVersion:
              compilerVersion || undefined,
            unavailableReason:
              "Bytecode attestation could not run: " +
              (error instanceof Error
                ? error.message
                : String(error))
          });
      }
    }

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
      sourceInspection:
        verified &&
        source &&
        opts?.inspectSource
          ? inspectVerifiedSource(source, {
              maxBytes: opts.maxSourceBytes,
              maxFindings: opts.maxFindings
            })
          : undefined,
      bytecodeAttestation
    };
  }
}
