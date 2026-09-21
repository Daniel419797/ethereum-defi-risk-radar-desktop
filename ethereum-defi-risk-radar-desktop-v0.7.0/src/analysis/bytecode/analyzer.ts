import { createHash } from "node:crypto";
import { finalizeFinding } from "../evidence.js";
import type { AnalysisFinding } from "../model.js";
import {
  buildBytecodeCfg,
  disassembleRuntimeBytecode,
  recoverFunctionSelectors,
  type EvmBasicBlock,
  type EvmInstruction
} from "./disassembler.js";

const EIP1967_IMPLEMENTATION =
  "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_ADMIN =
  "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const EIP1967_BEACON =
  "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";
const EIP1822_PROXIABLE =
  "c5f16f0fcc639fa48a6947836d9850f504798be2088011016d1a67f3b7d0c30a";

export type BytecodeProxyKind =
  | "EIP1967"
  | "EIP1822_UUPS"
  | "ERC1167_MINIMAL"
  | "ERC2535_DIAMOND"
  | "CUSTOM_DELEGATECALL"
  | "NONE";

export type BytecodeModernSemantics = {
  eip7702Delegation?: string;
  usesTransientStorage: boolean;
  usesCreate2: boolean;
  usesSelfdestruct: boolean;
  usesBlobOpcodes: boolean;
};

export type BytecodeSurface = {
  pc: number;
  opcode: string;
  detail: string;
};

export type BytecodeAnalysisReport = {
  engine: "bytecode";
  runtimeBytes: number;
  instructionCount: number;
  selectors: string[];
  blocks: EvmBasicBlock[];
  proxyKind: BytecodeProxyKind;
  proxySignals: string[];
  semantics: BytecodeModernSemantics;
  externalCallSites: BytecodeSurface[];
  storageWriteSites: BytecodeSurface[];
  creationSites: BytecodeSurface[];
  findings: AnalysisFinding[];
  limitations: string[];
  digest: string;
};

function byteLength(runtimeBytecode: string) {
  return Math.max(
    0,
    (runtimeBytecode.replace(/^0x/, "").length / 2)
  );
}

function containsPush32(
  instructions: EvmInstruction[],
  value: string
) {
  return instructions.some(
    instruction =>
      instruction.name === "PUSH32" &&
      instruction.immediate?.slice(2).toLowerCase() ===
        value.toLowerCase()
  );
}

function detectMinimalProxy(runtimeBytecode: string) {
  const body = runtimeBytecode.toLowerCase().replace(/^0x/, "");
  return /^363d3d373d3d3d363d73[a-f0-9]{40}5af43d82803e903d91602b57fd5bf3$/.test(
    body
  );
}

function detectEip7702(runtimeBytecode: string) {
  const body = runtimeBytecode.toLowerCase().replace(/^0x/, "");
  if (!/^ef0100[a-f0-9]{40}$/.test(body)) return undefined;
  return "0x" + body.slice(6);
}

function inferProxyKind(
  runtimeBytecode: string,
  instructions: EvmInstruction[],
  selectors: string[]
): { kind: BytecodeProxyKind; signals: string[] } {
  const signals: string[] = [];
  if (detectMinimalProxy(runtimeBytecode)) {
    return {
      kind: "ERC1167_MINIMAL",
      signals: ["Canonical ERC-1167 runtime forwarding pattern."]
    };
  }

  if (containsPush32(instructions, EIP1967_IMPLEMENTATION)) {
    signals.push("EIP-1967 implementation slot constant.");
  }
  if (containsPush32(instructions, EIP1967_ADMIN)) {
    signals.push("EIP-1967 admin slot constant.");
  }
  if (containsPush32(instructions, EIP1967_BEACON)) {
    signals.push("EIP-1967 beacon slot constant.");
  }
  if (containsPush32(instructions, EIP1822_PROXIABLE)) {
    signals.push("ERC-1822/UUPS proxiable slot constant.");
  }

  const hasDelegatecall = instructions.some(
    instruction => instruction.name === "DELEGATECALL"
  );
  const diamondSelectors = new Set([
    "0x1f931c1c", // diamondCut
    "0x7a0ed627", // facets
    "0xadfca15e", // facetFunctionSelectors
    "0x52ef6b2c", // facetAddresses
    "0xcdffacc6"  // facetAddress
  ]);
  const diamondMatches = selectors.filter(selector =>
    diamondSelectors.has(selector)
  );
  if (diamondMatches.length >= 2 && hasDelegatecall) {
    signals.push(
      "Multiple ERC-2535 loupe/cut selectors plus delegatecall."
    );
    return { kind: "ERC2535_DIAMOND", signals };
  }
  if (
    signals.some(signal => signal.includes("EIP-1967")) &&
    hasDelegatecall
  ) {
    return { kind: "EIP1967", signals };
  }
  if (
    signals.some(signal => signal.includes("ERC-1822")) &&
    hasDelegatecall
  ) {
    return { kind: "EIP1822_UUPS", signals };
  }
  if (hasDelegatecall) {
    signals.push(
      "Runtime contains DELEGATECALL without a recognized standard proxy fingerprint."
    );
    return { kind: "CUSTOM_DELEGATECALL", signals };
  }
  return { kind: "NONE", signals };
}

function nearbyStateWriteAfterCall(
  block: EvmBasicBlock
) {
  const callIndex = block.instructions.findIndex(
    instruction =>
      instruction.name === "CALL" ||
      instruction.name === "DELEGATECALL" ||
      instruction.name === "CALLCODE"
  );
  if (callIndex < 0) return false;
  return block.instructions
    .slice(callIndex + 1)
    .some(instruction => instruction.name === "SSTORE");
}

function findingId(
  runtimeBytecode: string,
  rule: string,
  pc: number
) {
  return createHash("sha256")
    .update(runtimeBytecode + "|" + rule + "|" + pc)
    .digest("hex")
    .slice(0, 18);
}

function bytecodeFinding(opts: {
  runtimeBytecode: string;
  rule: string;
  pc: number;
  kind: AnalysisFinding["kind"];
  severity: AnalysisFinding["severity"];
  confidence: AnalysisFinding["confidence"];
  title: string;
  description: string;
  limitations: string[];
}) {
  return finalizeFinding({
    id: findingId(
      opts.runtimeBytecode,
      opts.rule,
      opts.pc
    ),
    kind: opts.kind,
    engine: "bytecode",
    severity: opts.severity,
    confidence: opts.confidence,
    evidenceStrength: "STRUCTURAL",
    evidenceClass: "BYTECODE_STRUCTURAL",
    title: opts.title,
    description: opts.description,
    evidencePath: [
      "runtime-bytecode",
      "pc:" + opts.pc,
      opts.rule
    ],
    reachableFromExternalEntry: undefined,
    limitations: opts.limitations
  });
}

export function analyzeRuntimeBytecode(
  runtimeBytecode: string
): BytecodeAnalysisReport {
  const instructions =
    disassembleRuntimeBytecode(runtimeBytecode);
  const blocks = buildBytecodeCfg(instructions);
  const selectors = recoverFunctionSelectors(instructions);
  const proxy = inferProxyKind(
    runtimeBytecode,
    instructions,
    selectors
  );
  const eip7702Delegation =
    detectEip7702(runtimeBytecode);

  const externalCallSites = instructions
    .filter(instruction =>
      ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"].includes(
        instruction.name
      )
    )
    .map(instruction => ({
      pc: instruction.pc,
      opcode: instruction.name,
      detail:
        "External execution opcode observed in deployed runtime."
    }));
  const storageWriteSites = instructions
    .filter(instruction => instruction.name === "SSTORE")
    .map(instruction => ({
      pc: instruction.pc,
      opcode: instruction.name,
      detail: "Persistent storage write."
    }));
  const creationSites = instructions
    .filter(instruction =>
      instruction.name === "CREATE" ||
      instruction.name === "CREATE2"
    )
    .map(instruction => ({
      pc: instruction.pc,
      opcode: instruction.name,
      detail: "Runtime contract creation surface."
    }));

  const findings: AnalysisFinding[] = [];

  for (const instruction of instructions) {
    if (instruction.name === "ORIGIN") {
      findings.push(
        bytecodeFinding({
          runtimeBytecode,
          rule: "tx-origin",
          pc: instruction.pc,
          kind: "authorization",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          title: "Runtime reads transaction origin",
          description:
            "The deployed bytecode executes ORIGIN. If the resulting value participates in authorization, delegated/account-composed calls can violate caller assumptions.",
          limitations: [
            "Stack-level data flow from ORIGIN to a privileged branch is not proven by this signal alone.",
            "No source location is claimed because verified source is unavailable."
          ]
        })
      );
    }
    if (instruction.name === "CALLCODE") {
      findings.push(
        bytecodeFinding({
          runtimeBytecode,
          rule: "callcode",
          pc: instruction.pc,
          kind: "cross_contract_calls",
          severity: "MEDIUM",
          confidence: "HIGH",
          title: "Legacy CALLCODE execution surface",
          description:
            "The runtime uses CALLCODE, a legacy context-sharing external execution opcode that warrants manual review.",
          limitations: [
            "The target and attacker influence over it require stack/data-flow analysis."
          ]
        })
      );
    }
  }

  for (const block of blocks) {
    if (!nearbyStateWriteAfterCall(block)) continue;
    const call = block.instructions.find(instruction =>
      ["CALL", "DELEGATECALL", "CALLCODE"].includes(
        instruction.name
      )
    );
    if (!call) continue;
    findings.push(
      bytecodeFinding({
        runtimeBytecode,
        rule: "call-before-sstore",
        pc: call.pc,
        kind: "reentrancy",
        severity: "MEDIUM",
        confidence: "LOW",
        title:
          "External execution precedes a persistent state write in one basic block",
        description:
          "A CALL-family opcode is followed by SSTORE before the basic block terminates. This is a bytecode review signal for effects-after-interactions behavior.",
        limitations: [
          "This does not prove reentrancy or external reachability.",
          "Stack, storage aliasing, guard dominance and callee trust remain unresolved.",
          "Treat as BYTECODE_STRUCTURAL review evidence, not exploit proof."
        ]
      })
    );
  }

  if (proxy.kind !== "NONE") {
    findings.push(
      bytecodeFinding({
        runtimeBytecode,
        rule: "proxy-surface",
        pc:
          instructions.find(
            instruction =>
              instruction.name === "DELEGATECALL"
          )?.pc ?? 0,
        kind: "upgradeability",
        severity: "INFO",
        confidence:
          proxy.kind === "CUSTOM_DELEGATECALL"
            ? "LOW"
            : "HIGH",
        title:
          proxy.kind === "CUSTOM_DELEGATECALL"
            ? "Custom delegatecall/proxy surface"
            : proxy.kind + " proxy surface",
        description:
          proxy.signals.join(" "),
        limitations: [
          "Upgrade authority and implementation identity require pinned state or event history.",
          "Proxy presence is not itself a vulnerability."
        ]
      })
    );
  }

  if (eip7702Delegation) {
    findings.push(
      bytecodeFinding({
        runtimeBytecode,
        rule: "eip7702-delegation",
        pc: 0,
        kind: "authorization",
        severity: "INFO",
        confidence: "HIGH",
        title: "EIP-7702 delegated account code",
        description:
          "The account code matches the EIP-7702 delegation designation and delegates execution to " +
          eip7702Delegation +
          ".",
        limitations: [
          "This is an account-execution semantic, not a vulnerability by itself.",
          "Authorization analysis must reason about delegated code rather than assuming EOA code is empty."
        ]
      })
    );
  }

  const semantics: BytecodeModernSemantics = {
    eip7702Delegation,
    usesTransientStorage: instructions.some(
      instruction =>
        instruction.name === "TLOAD" ||
        instruction.name === "TSTORE"
    ),
    usesCreate2: instructions.some(
      instruction => instruction.name === "CREATE2"
    ),
    usesSelfdestruct: instructions.some(
      instruction => instruction.name === "SELFDESTRUCT"
    ),
    usesBlobOpcodes: instructions.some(
      instruction =>
        instruction.name === "BLOBHASH" ||
        instruction.name === "BLOBBASEFEE"
    )
  };

  return {
    engine: "bytecode",
    runtimeBytes: byteLength(runtimeBytecode),
    instructionCount: instructions.length,
    selectors,
    blocks,
    proxyKind: proxy.kind,
    proxySignals: proxy.signals,
    semantics,
    externalCallSites,
    storageWriteSites,
    creationSites,
    findings,
    limitations: [
      "Bytecode analysis has no source-variable names, source-level types or comments.",
      "Dynamic jump targets, stack aliases and storage key semantics are conservative unless resolved.",
      "BYTECODE_STRUCTURAL evidence never implies exploitability."
    ],
    digest:
      "sha256:" +
      createHash("sha256")
        .update(runtimeBytecode.toLowerCase())
        .digest("hex")
  };
}
