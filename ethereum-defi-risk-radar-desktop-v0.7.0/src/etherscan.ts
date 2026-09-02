import { inspectVerifiedSource, type SourceInspection } from "./sourceAnalyzer.js";
import { fetchJsonBounded } from "./boundedFetch.js";

export type EtherscanSourceMetadata = {
  verified: boolean;
  contractName?: string;
  compilerVersion?: string;
  proxy: boolean;
  implementationAddress?: string;
  sourceInspection?: SourceInspection;
};

type EtherscanResponse = {
  status?: string;
  message?: string;
  result?: Array<{
    SourceCode?: string;
    ContractName?: string;
    CompilerVersion?: string;
    Proxy?: string;
    Implementation?: string;
  }> | string;
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
      throw new Error(`Etherscan HTTP ${response.status}`);
    }

    if (payload.status === "0" && typeof payload.result === "string") {
      const detail =
        payload.result.trim() || payload.message?.trim() || "Unknown API error";
      throw new Error(`Etherscan API error: ${detail.slice(0, 300)}`);
    }

    const first = Array.isArray(payload.result) ? payload.result[0] : undefined;

    if (!first) {
      return { verified: false, proxy: false };
    }

    const source = (first.SourceCode ?? "").trim();
    const name = (first.ContractName ?? "").trim();
    const implementation = (first.Implementation ?? "").trim();
    const verified = Boolean(source || name);
    const proxy = first.Proxy === "1" || Boolean(implementation);

    return {
      verified,
      contractName: name || undefined,
      compilerVersion: (first.CompilerVersion ?? "").trim() || undefined,
      proxy,
      implementationAddress:
        EVM_ADDRESS_RE.test(implementation) ? implementation : undefined,
      sourceInspection:
        verified && source && opts?.inspectSource
          ? inspectVerifiedSource(source, {
              maxBytes: opts.maxSourceBytes,
              maxFindings: opts.maxFindings
            })
          : undefined
    };
  }
}
