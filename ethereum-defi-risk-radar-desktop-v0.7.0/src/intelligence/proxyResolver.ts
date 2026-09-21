import {
  analyzeRuntimeBytecode
} from "../analysis/bytecode/analyzer.js";
import {
  functionSelector
} from "../analysis/bytecode/keccak.js";
import {
  decodeAddressWord,
  decodeDynamicAddressArray,
  decodeDynamicBytes4Array,
  encodeAddressWord,
  encodeCall
} from "./abi.js";
import type {
  ReadOnlyEthereumRpcClient
} from "./rpc.js";
import {
  EIP1967_ADMIN_SLOT,
  EIP1967_BEACON_SLOT,
  EIP1967_IMPLEMENTATION_SLOT
} from "./snapshot.js";

export type ResolvedProxyKind =
  | "NONE"
  | "EIP7702_DELEGATION"
  | "ERC1167_MINIMAL"
  | "TRANSPARENT"
  | "UUPS"
  | "BEACON"
  | "ERC2535_DIAMOND"
  | "CUSTOM_DELEGATECALL";

export type DiamondFacet = {
  address: string;
  selectors: string[];
};

export type ProxyResolution = {
  address: string;
  blockNumber: number;
  kind: ResolvedProxyKind;
  implementation?: string;
  admin?: string;
  beacon?: string;
  delegatedAccountImplementation?: string;
  facets: DiamondFacet[];
  evidence: string[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
  limitations: string[];
};

function storageAddress(value: string) {
  const normalized = value
    .replace(/^0x/, "")
    .padStart(64, "0");
  if (!/^[a-f0-9]{64}$/i.test(normalized)) {
    return undefined;
  }
  const address =
    "0x" + normalized.slice(-40).toLowerCase();
  return /^0x0{40}$/.test(address)
    ? undefined
    : address;
}

function minimalProxyTarget(
  runtimeBytecode: string
) {
  const body = runtimeBytecode
    .toLowerCase()
    .replace(/^0x/, "");
  const match = body.match(
    /^363d3d373d3d3d363d73([a-f0-9]{40})5af43d82803e903d91602b57fd5bf3$/
  );
  return match
    ? "0x" + match[1]
    : undefined;
}

async function safeStorage(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  slot: string,
  blockNumber: number
) {
  try {
    return storageAddress(
      await reader.getStorageAt(
        address,
        slot,
        blockNumber
      )
    );
  } catch {
    return undefined;
  }
}

async function safeCall(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  data: string,
  blockNumber: number
) {
  try {
    return await reader.call(
      address,
      data,
      blockNumber
    );
  } catch {
    return undefined;
  }
}

async function resolveDiamondFacets(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  blockNumber: number
) {
  const result = await safeCall(
    reader,
    address,
    encodeCall("facetAddresses()"),
    blockNumber
  );
  if (!result) return [];

  let addresses: string[];
  try {
    addresses =
      decodeDynamicAddressArray(result);
  } catch {
    return [];
  }

  const facets: DiamondFacet[] = [];
  for (const facet of addresses.slice(0, 256)) {
    const selectorsResult = await safeCall(
      reader,
      address,
      encodeCall(
        "facetFunctionSelectors(address)",
        [encodeAddressWord(facet)]
      ),
      blockNumber
    );
    let selectors: string[] = [];
    if (selectorsResult) {
      try {
        selectors =
          decodeDynamicBytes4Array(
            selectorsResult
          ).slice(0, 10_000);
      } catch {
        selectors = [];
      }
    }
    facets.push({
      address: facet,
      selectors
    });
  }
  return facets;
}

export async function resolveComplexProxy(opts: {
  reader: ReadOnlyEthereumRpcClient;
  address: string;
  blockNumber: number;
}): Promise<ProxyResolution> {
  const runtime = await opts.reader.getCode(
    opts.address,
    opts.blockNumber
  );
  const analysis =
    analyzeRuntimeBytecode(runtime);
  const evidence = [
    ...analysis.proxySignals
  ];
  const limitations: string[] = [];
  const facets: DiamondFacet[] = [];

  if (
    analysis.semantics.eip7702Delegation
  ) {
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind: "EIP7702_DELEGATION",
      delegatedAccountImplementation:
        analysis.semantics
          .eip7702Delegation,
      facets,
      evidence: [
        "EIP-7702 delegation designation runtime."
      ],
      confidence: "HIGH",
      limitations: [
        "Delegated account code can change through a later authorization transaction; monitor the account code over time."
      ]
    };
  }

  const minimal =
    minimalProxyTarget(runtime);
  if (minimal) {
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind: "ERC1167_MINIMAL",
      implementation: minimal,
      facets,
      evidence: [
        "Canonical ERC-1167 runtime bytecode pattern."
      ],
      confidence: "HIGH",
      limitations: []
    };
  }

  const [implementation, admin, beacon] =
    await Promise.all([
      safeStorage(
        opts.reader,
        opts.address,
        EIP1967_IMPLEMENTATION_SLOT,
        opts.blockNumber
      ),
      safeStorage(
        opts.reader,
        opts.address,
        EIP1967_ADMIN_SLOT,
        opts.blockNumber
      ),
      safeStorage(
        opts.reader,
        opts.address,
        EIP1967_BEACON_SLOT,
        opts.blockNumber
      )
    ]);

  if (beacon) {
    const response = await safeCall(
      opts.reader,
      beacon,
      encodeCall("implementation()"),
      opts.blockNumber
    );
    const beaconImplementation =
      response
        ? (() => {
            try {
              return decodeAddressWord(
                response
              );
            } catch {
              return undefined;
            }
          })()
        : undefined;
    if (beaconImplementation) {
      evidence.push(
        "Beacon implementation() resolved at pinned block."
      );
    } else {
      limitations.push(
        "Beacon address was resolved but implementation() could not be decoded."
      );
    }
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind: "BEACON",
      implementation:
        beaconImplementation,
      admin,
      beacon,
      facets,
      evidence,
      confidence: beaconImplementation
        ? "HIGH"
        : "MEDIUM",
      limitations
    };
  }

  if (
    analysis.proxyKind ===
    "ERC2535_DIAMOND"
  ) {
    facets.push(
      ...(await resolveDiamondFacets(
        opts.reader,
        opts.address,
        opts.blockNumber
      ))
    );
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind: "ERC2535_DIAMOND",
      facets,
      evidence: [
        ...evidence,
        facets.length
          ? "Diamond loupe resolved " +
            facets.length +
            " facet(s)."
          : "Diamond loupe selectors were observed but facet enumeration was unavailable."
      ],
      confidence: facets.length
        ? "HIGH"
        : "MEDIUM",
      limitations
    };
  }

  if (implementation) {
    let kind: ResolvedProxyKind =
      admin ? "TRANSPARENT" : "UUPS";
    if (!admin) {
      try {
        const implementationCode =
          await opts.reader.getCode(
            implementation,
            opts.blockNumber
          );
        const implementationAnalysis =
          analyzeRuntimeBytecode(
            implementationCode
          );
        const proxiableSelector =
          functionSelector(
            "proxiableUUID()"
          );
        if (
          !implementationAnalysis.selectors.includes(
            proxiableSelector
          )
        ) {
          kind =
            "CUSTOM_DELEGATECALL";
          limitations.push(
            "Implementation slot is populated but proxiableUUID() was not recovered; UUPS classification remains unresolved."
          );
        }
      } catch {
        limitations.push(
          "Implementation runtime could not be inspected."
        );
      }
    }
    evidence.push(
      "EIP-1967 implementation slot resolved at pinned block."
    );
    if (admin) {
      evidence.push(
        "EIP-1967 admin slot is populated."
      );
    }
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind,
      implementation,
      admin,
      facets,
      evidence,
      confidence:
        kind === "CUSTOM_DELEGATECALL"
          ? "MEDIUM"
          : "HIGH",
      limitations
    };
  }

  if (
    analysis.proxyKind ===
    "CUSTOM_DELEGATECALL"
  ) {
    return {
      address: opts.address.toLowerCase(),
      blockNumber: opts.blockNumber,
      kind: "CUSTOM_DELEGATECALL",
      facets,
      evidence,
      confidence: "LOW",
      limitations: [
        "Delegatecall exists but no standardized implementation source was resolved from pinned state."
      ]
    };
  }

  return {
    address: opts.address.toLowerCase(),
    blockNumber: opts.blockNumber,
    kind: "NONE",
    facets,
    evidence,
    confidence: "HIGH",
    limitations
  };
}
