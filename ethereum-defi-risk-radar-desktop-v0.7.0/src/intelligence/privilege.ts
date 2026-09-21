import {
  analyzeRuntimeBytecode
} from "../analysis/bytecode/analyzer.js";
import {
  functionSelector
} from "../analysis/bytecode/keccak.js";
import {
  decodeAddressWord,
  decodeDynamicAddressArray,
  decodeUintWord,
  encodeBytes32Word,
  encodeCall,
  encodeUintWord
} from "./abi.js";
import type {
  ReadOnlyEthereumRpcClient
} from "./rpc.js";
import type {
  ProxyResolution
} from "./proxyResolver.js";

export type AuthorityKind =
  | "EOA"
  | "SAFE_MULTISIG"
  | "TIMELOCK"
  | "ACCESS_CONTROL"
  | "CONTRACT"
  | "UNKNOWN";

export type AuthorityNode = {
  address: string;
  kind: AuthorityKind;
  threshold?: number;
  members?: string[];
  delaySeconds?: number;
  codePresent: boolean;
  evidence: string[];
};

export type PrivilegedCapability =
  | "UPGRADE"
  | "PAUSE"
  | "MINT"
  | "BURN"
  | "TREASURY_MOVE"
  | "ROLE_ADMIN"
  | "GOVERNANCE_EXECUTE";

export type PrivilegeMap = {
  target: string;
  blockNumber: number;
  controllers: AuthorityNode[];
  capabilities: Array<{
    capability: PrivilegedCapability;
    selector: string;
    confidence: "LOW" | "MEDIUM" | "HIGH";
    evidence: string[];
  }>;
  minimumAuthority?: {
    signatures: number;
    members: number;
    delaySeconds?: number;
    basis: string;
  };
  limitations: string[];
};

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

async function discoverSafe(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  blockNumber: number
) {
  const [ownersRaw, thresholdRaw] =
    await Promise.all([
      safeCall(
        reader,
        address,
        encodeCall("getOwners()"),
        blockNumber
      ),
      safeCall(
        reader,
        address,
        encodeCall("getThreshold()"),
        blockNumber
      )
    ]);
  if (!ownersRaw || !thresholdRaw) {
    return undefined;
  }
  try {
    const owners =
      decodeDynamicAddressArray(
        ownersRaw
      );
    const threshold = Number(
      decodeUintWord(thresholdRaw)
    );
    if (
      !owners.length ||
      !Number.isSafeInteger(threshold) ||
      threshold <= 0 ||
      threshold > owners.length
    ) {
      return undefined;
    }
    return { owners, threshold };
  } catch {
    return undefined;
  }
}

async function discoverTimelock(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  blockNumber: number
) {
  const raw = await safeCall(
    reader,
    address,
    encodeCall("getMinDelay()"),
    blockNumber
  );
  if (!raw) return undefined;
  try {
    const value = decodeUintWord(raw);
    if (
      value >
      BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      return undefined;
    }
    return Number(value);
  } catch {
    return undefined;
  }
}

async function discoverDefaultAdminMembers(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  blockNumber: number
) {
  const zeroRole =
    "0x" + "0".repeat(64);
  const countRaw = await safeCall(
    reader,
    address,
    encodeCall(
      "getRoleMemberCount(bytes32)",
      [encodeBytes32Word(zeroRole)]
    ),
    blockNumber
  );
  if (!countRaw) return [];
  let count = 0;
  try {
    count = Number(
      decodeUintWord(countRaw)
    );
  } catch {
    return [];
  }
  if (
    !Number.isSafeInteger(count) ||
    count < 0 ||
    count > 100
  ) {
    return [];
  }

  const members: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const raw = await safeCall(
      reader,
      address,
      encodeCall(
        "getRoleMember(bytes32,uint256)",
        [
          encodeBytes32Word(zeroRole),
          encodeUintWord(index)
        ]
      ),
      blockNumber
    );
    if (!raw) continue;
    try {
      members.push(
        decodeAddressWord(raw)
      );
    } catch {
      // Skip undecodable role member.
    }
  }
  return members;
}

async function authorityNode(
  reader: ReadOnlyEthereumRpcClient,
  address: string,
  blockNumber: number
): Promise<AuthorityNode> {
  const code = await reader.getCode(
    address,
    blockNumber
  );
  const codePresent = code !== "0x";
  if (!codePresent) {
    return {
      address,
      kind: "EOA",
      codePresent,
      evidence: [
        "No runtime bytecode at pinned block."
      ]
    };
  }

  const safe = await discoverSafe(
    reader,
    address,
    blockNumber
  );
  if (safe) {
    return {
      address,
      kind: "SAFE_MULTISIG",
      threshold: safe.threshold,
      members: safe.owners,
      codePresent,
      evidence: [
        "getOwners() and getThreshold() returned a coherent multisig configuration."
      ]
    };
  }

  const delay = await discoverTimelock(
    reader,
    address,
    blockNumber
  );
  if (delay !== undefined) {
    return {
      address,
      kind: "TIMELOCK",
      delaySeconds: delay,
      codePresent,
      evidence: [
        "getMinDelay() resolved at pinned block."
      ]
    };
  }

  const admins =
    await discoverDefaultAdminMembers(
      reader,
      address,
      blockNumber
    );
  if (admins.length) {
    return {
      address,
      kind: "ACCESS_CONTROL",
      members: admins,
      codePresent,
      evidence: [
        "Enumerable DEFAULT_ADMIN_ROLE members resolved at pinned block."
      ]
    };
  }

  return {
    address,
    kind: "CONTRACT",
    codePresent,
    evidence: [
      "Controller is a contract but no Safe, TimelockController or enumerable default-admin interface was resolved."
    ]
  };
}

function selectorCapabilities(
  runtimeBytecode: string
) {
  const analysis =
    analyzeRuntimeBytecode(
      runtimeBytecode
    );
  const selectors = new Set(
    analysis.selectors
  );
  const definitions: Array<[
    PrivilegedCapability,
    string[]
  ]> = [
    [
      "UPGRADE",
      [
        "upgradeTo(address)",
        "upgradeToAndCall(address,bytes)",
        "diamondCut((address,uint8,bytes4[])[],address,bytes)"
      ]
    ],
    [
      "PAUSE",
      ["pause()", "unpause()"]
    ],
    [
      "MINT",
      [
        "mint(address,uint256)",
        "mint(uint256)"
      ]
    ],
    [
      "BURN",
      [
        "burn(uint256)",
        "burn(address,uint256)"
      ]
    ],
    [
      "TREASURY_MOVE",
      [
        "sweep(address,address,uint256)",
        "rescueTokens(address,address,uint256)",
        "withdraw(address,uint256)"
      ]
    ],
    [
      "ROLE_ADMIN",
      [
        "grantRole(bytes32,address)",
        "revokeRole(bytes32,address)"
      ]
    ],
    [
      "GOVERNANCE_EXECUTE",
      [
        "execute(address,uint256,bytes,bytes32,bytes32)",
        "executeBatch(address[],uint256[],bytes[],bytes32,bytes32)"
      ]
    ]
  ];

  return definitions.flatMap(
    ([capability, signatures]) =>
      signatures
        .map(signature => ({
          signature,
          selector:
            functionSelector(signature)
        }))
        .filter(item =>
          selectors.has(item.selector)
        )
        .map(item => ({
          capability,
          selector: item.selector,
          confidence: "HIGH" as const,
          evidence: [
            "Recovered runtime selector for " +
              item.signature
          ]
        }))
  );
}

export async function buildPrivilegeMap(opts: {
  reader: ReadOnlyEthereumRpcClient;
  target: string;
  blockNumber: number;
  proxy?: ProxyResolution;
}) {
  const runtime =
    await opts.reader.getCode(
      opts.target,
      opts.blockNumber
    );
  const capabilities =
    selectorCapabilities(runtime);
  const controllerAddresses =
    new Set<string>();
  if (opts.proxy?.admin) {
    controllerAddresses.add(
      opts.proxy.admin
    );
  }

  for (const signature of [
    "owner()",
    "admin()",
    "guardian()",
    "pauser()"
  ]) {
    const raw = await safeCall(
      opts.reader,
      opts.target,
      encodeCall(signature),
      opts.blockNumber
    );
    if (!raw) continue;
    try {
      const address =
        decodeAddressWord(raw);
      if (!/^0x0{40}$/.test(address)) {
        controllerAddresses.add(address);
      }
    } catch {
      // Not a simple address-returning authority method.
    }
  }

  const controllers: AuthorityNode[] = [];
  for (const address of [
    ...controllerAddresses
  ].slice(0, 50)) {
    controllers.push(
      await authorityNode(
        opts.reader,
        address,
        opts.blockNumber
      )
    );
  }

  let minimumAuthority:
    | PrivilegeMap["minimumAuthority"]
    | undefined;
  const safe = controllers.find(
    controller =>
      controller.kind === "SAFE_MULTISIG" &&
      controller.threshold &&
      controller.members
  );
  const timelock = controllers.find(
    controller =>
      controller.kind === "TIMELOCK"
  );
  if (safe) {
    minimumAuthority = {
      signatures: safe.threshold!,
      members: safe.members!.length,
      delaySeconds:
        timelock?.delaySeconds,
      basis:
        timelock
          ? "Resolved Safe threshold plus connected/observed timelock controller."
          : "Resolved Safe threshold at pinned block."
    };
  } else if (
    controllers.some(
      controller => controller.kind === "EOA"
    )
  ) {
    minimumAuthority = {
      signatures: 1,
      members: 1,
      delaySeconds:
        timelock?.delaySeconds,
      basis:
        "A resolved privileged controller has no runtime bytecode and is therefore an EOA at the pinned block."
    };
  }

  return {
    target: opts.target.toLowerCase(),
    blockNumber: opts.blockNumber,
    controllers,
    capabilities,
    minimumAuthority,
    limitations: [
      "Selector presence establishes a privileged surface, not that every matching method is currently callable by every controller.",
      "Non-enumerable AccessControl roles cannot be exhaustively recovered through eth_call alone.",
      "Governance proposal/quorum paths require event-history correlation for complete authority provenance."
    ]
  } satisfies PrivilegeMap;
}
