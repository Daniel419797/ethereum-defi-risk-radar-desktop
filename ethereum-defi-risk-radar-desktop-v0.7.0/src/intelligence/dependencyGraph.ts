import { createHash } from "node:crypto";
import {
  disassembleRuntimeBytecode
} from "../analysis/bytecode/disassembler.js";
import {
  analyzeRuntimeBytecode
} from "../analysis/bytecode/analyzer.js";
import {
  stripSolidityMetadata
} from "./bytecode.js";
import type {
  ReadOnlyEthereumRpcClient
} from "./rpc.js";
import {
  profileModernEvmSemantics
} from "./semantics.js";

export type DependencyNode = {
  id: string;
  address: string;
  codeHash: string;
  runtimeBytes: number;
  proxyKind: string;
  standards: string[];
  depth: number;
};

export type DependencyEdge = {
  from: string;
  to: string;
  kind:
    | "LITERAL_CALL_TARGET"
    | "DELEGATECALL_TARGET"
    | "STATICCALL_TARGET";
  pc: number;
  confidence: "LOW" | "MEDIUM";
};

export type CrossProtocolDependencyGraph = {
  version: 1;
  root: string;
  blockNumber: number;
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  truncated: boolean;
  limitations: string[];
};

function nodeId(address: string) {
  return (
    "dep:" +
    createHash("sha256")
      .update(address.toLowerCase())
      .digest("hex")
      .slice(0, 16)
  );
}

function codeHash(code: string) {
  return (
    "sha256:" +
    createHash("sha256")
      .update(
        Buffer.from(
          code.replace(/^0x/, ""),
          "hex"
        )
      )
      .digest("hex")
  );
}

function candidateTargets(
  runtimeBytecode: string
) {
  const stripped =
    stripSolidityMetadata(
      runtimeBytecode
    );
  const instructions =
    disassembleRuntimeBytecode(
      stripped
    );
  const rows: Array<{
    address: string;
    pc: number;
    kind: DependencyEdge["kind"];
  }> = [];

  for (
    let index = 0;
    index < instructions.length;
    index += 1
  ) {
    const instruction = instructions[index];
    if (
      ![
        "CALL",
        "DELEGATECALL",
        "STATICCALL"
      ].includes(instruction.name)
    ) {
      continue;
    }
    const window = instructions.slice(
      Math.max(0, index - 16),
      index
    );
    const push20 = [...window]
      .reverse()
      .find(
        row =>
          row.name === "PUSH20" &&
          /^0x[a-f0-9]{40}$/.test(
            row.immediate || ""
          )
      );
    if (!push20?.immediate) continue;
    const address =
      push20.immediate.toLowerCase();
    if (
      /^0x0{40}$/.test(address) ||
      /^0x0{39}[1-9a-f]$/.test(address)
    ) {
      continue;
    }
    rows.push({
      address,
      pc: instruction.pc,
      kind:
        instruction.name ===
        "DELEGATECALL"
          ? "DELEGATECALL_TARGET"
          : instruction.name ===
              "STATICCALL"
            ? "STATICCALL_TARGET"
            : "LITERAL_CALL_TARGET"
    });
  }

  const seen = new Set<string>();
  return rows.filter(row => {
    const key =
      row.address +
      "|" +
      row.kind +
      "|" +
      row.pc;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function buildCrossProtocolDependencyGraph(opts: {
  reader: ReadOnlyEthereumRpcClient;
  rootAddress: string;
  blockNumber: number;
  maxDepth?: number;
  maxNodes?: number;
}): Promise<CrossProtocolDependencyGraph> {
  const maxDepth = Math.max(
    1,
    Math.min(opts.maxDepth ?? 2, 4)
  );
  const maxNodes = Math.max(
    2,
    Math.min(opts.maxNodes ?? 128, 512)
  );
  const nodes = new Map<string, DependencyNode>();
  const edges: DependencyEdge[] = [];
  const queue: Array<{
    address: string;
    depth: number;
  }> = [
    {
      address:
        opts.rootAddress.toLowerCase(),
      depth: 0
    }
  ];
  let truncated = false;

  while (queue.length) {
    const current = queue.shift()!;
    const id = nodeId(current.address);
    if (nodes.has(id)) continue;
    if (nodes.size >= maxNodes) {
      truncated = true;
      break;
    }

    let code = "0x";
    try {
      code = await opts.reader.getCode(
        current.address,
        opts.blockNumber
      );
    } catch {
      continue;
    }
    if (code === "0x") continue;

    const analysis =
      analyzeRuntimeBytecode(code);
    const semantics =
      profileModernEvmSemantics(
        analysis
      );
    nodes.set(id, {
      id,
      address: current.address,
      codeHash: codeHash(code),
      runtimeBytes:
        analysis.runtimeBytes,
      proxyKind: analysis.proxyKind,
      standards:
        semantics.standards.map(
          item => item.standard
        ),
      depth: current.depth
    });

    if (current.depth >= maxDepth) {
      continue;
    }

    for (const target of candidateTargets(
      code
    ).slice(0, 128)) {
      try {
        const targetCode =
          await opts.reader.getCode(
            target.address,
            opts.blockNumber
          );
        if (targetCode === "0x") continue;
      } catch {
        continue;
      }
      const targetId =
        nodeId(target.address);
      edges.push({
        from: id,
        to: targetId,
        kind: target.kind,
        pc: target.pc,
        confidence: "MEDIUM"
      });
      if (!nodes.has(targetId)) {
        queue.push({
          address:
            target.address,
          depth:
            current.depth + 1
        });
      }
    }
  }

  return {
    version: 1,
    root:
      opts.rootAddress.toLowerCase(),
    blockNumber: opts.blockNumber,
    nodes: [...nodes.values()],
    edges,
    truncated,
    limitations: [
      "Dependencies are limited to literal PUSH20 addresses observed near CALL-family opcodes; storage-derived and calldata-derived targets require deeper stack/state analysis.",
      "Literal address presence does not prove the target is reached on every execution path.",
      "Traversal is bounded by maxDepth and maxNodes."
    ]
  };
}

export function computeBlastRadius(
  graph: CrossProtocolDependencyGraph,
  failedAddress: string
) {
  const failed = nodeId(
    failedAddress.toLowerCase()
  );
  const reverse = new Map<
    string,
    string[]
  >();
  for (const edge of graph.edges) {
    const rows =
      reverse.get(edge.to) || [];
    rows.push(edge.from);
    reverse.set(edge.to, rows);
  }

  const impacted = new Set<string>();
  const queue = [failed];
  while (queue.length) {
    const current = queue.shift()!;
    for (const parent of
      reverse.get(current) || []) {
      if (impacted.has(parent)) {
        continue;
      }
      impacted.add(parent);
      queue.push(parent);
    }
  }

  const byId = new Map(
    graph.nodes.map(node => [
      node.id,
      node
    ])
  );
  return [...impacted]
    .map(id => byId.get(id))
    .filter(
      (node): node is DependencyNode =>
        Boolean(node)
    )
    .sort(
      (a, b) =>
        a.depth - b.depth ||
        a.address.localeCompare(
          b.address
        )
    );
}
