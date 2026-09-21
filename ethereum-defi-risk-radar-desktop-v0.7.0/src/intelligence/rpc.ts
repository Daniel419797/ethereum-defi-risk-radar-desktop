import { createHash } from "node:crypto";
import { fetchJsonBounded } from "../boundedFetch.js";
import type {
  ContractStateSnapshot,
  PinnedStateSnapshot,
  SnapshotCallObservation,
  SnapshotStorageObservation
} from "./model.js";

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const HASH_RE = /^0x[a-fA-F0-9]{64}$/;
const HEX_RE = /^0x(?:[a-fA-F0-9]{2})*$/;
const WORD_RE = /^0x[a-fA-F0-9]{64}$/;
const READ_ONLY_METHODS = new Set([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_call",
  "eth_getProof"
]);

export const STANDARD_PROXY_SLOTS = [
  {
    label: "eip1967.implementation",
    slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
  },
  {
    label: "eip1967.admin",
    slot: "0xb53127684a568b3173ae13b9f8a6016e01971a8d6a7178505b5d6103"
  },
  {
    label: "eip1967.beacon",
    slot: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
  }
] as const;

type JsonRpcEnvelope<T> = {
  jsonrpc?: string;
  id?: number;
  result?: T;
  error?: { code?: number; message?: string };
};

export type ReadonlyRpc = <T>(method: string, params: unknown[]) => Promise<T>;

export type SnapshotContractTarget = {
  address: string;
  contractRefId: string;
  sourceRole?: "DIRECT" | "PROXY" | "IMPLEMENTATION";
  slots?: Array<{ slot: string; label: string }>;
  calls?: Array<{ id: string; data: string }>;
};

export type CaptureSnapshotOptions = {
  confirmations?: number;
  maxContracts?: number;
  maxCallsPerContract?: number;
  maxSlotsPerContract?: number;
  signal?: AbortSignal;
  blockNumber?: number;
  expectedBlockHash?: string;
};

function safeRpcEndpoint(value: string, allowLoopback = false) {
  const url = new URL(value);
  if (url.username || url.password) {
    throw new Error("RPC endpoint must not use URL-embedded basic-auth credentials.");
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "::1";
  if (url.protocol !== "https:" && !(allowLoopback && loopback && url.protocol === "http:")) {
    throw new Error("Ethereum RPC endpoint must use HTTPS; loopback HTTP is allowed only for local test/replay use.");
  }
  return url;
}

function hexQuantity(value: number) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Block number must be a non-negative safe integer.");
  return `0x${value.toString(16)}`;
}

function quantityToNumber(value: string, label: string) {
  if (!/^0x[0-9a-fA-F]+$/.test(value)) throw new Error(`RPC returned invalid ${label}.`);
  const parsed = Number.parseInt(value.slice(2), 16);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`RPC returned out-of-range ${label}.`);
  return parsed;
}

function runtimeBytes(value: string) {
  if (!HEX_RE.test(value)) throw new Error("RPC returned invalid runtime bytecode.");
  return Math.max(0, (value.length - 2) / 2);
}

function sha256Hex(value: string) {
  if (!HEX_RE.test(value)) throw new Error("Expected canonical hexadecimal bytes.");
  return createHash("sha256").update(Buffer.from(value.slice(2), "hex")).digest("hex");
}

function canonicalAddress(value: string) {
  if (!ADDRESS_RE.test(value)) throw new Error("Snapshot target contains an invalid Ethereum address.");
  return value.toLowerCase();
}

function canonicalSlot(value: string) {
  if (!WORD_RE.test(value)) throw new Error("Storage slot must be a 32-byte canonical hex word.");
  return value.toLowerCase();
}

export function createReadonlyEthereumRpc(
  endpoint: string,
  opts: { timeoutMs?: number; maxResponseBytes?: number; allowLoopback?: boolean; signal?: AbortSignal } = {}
): ReadonlyRpc {
  const url = safeRpcEndpoint(endpoint, opts.allowLoopback);
  const timeoutMs = Math.max(1_000, Math.min(opts.timeoutMs ?? 20_000, 120_000));
  const maxResponseBytes = Math.max(32_768, Math.min(opts.maxResponseBytes ?? 4_000_000, 16_000_000));
  let requestId = 0;

  return async <T>(method: string, params: unknown[]) => {
    if (!READ_ONLY_METHODS.has(method)) throw new Error(`Blocked non-read-only Ethereum RPC method: ${method}`);
    const id = ++requestId;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    if (Buffer.byteLength(body) > 1_000_000) throw new Error("Ethereum RPC request exceeded the 1 MB safety limit.");

    const { response, payload } = await fetchJsonBounded<JsonRpcEnvelope<T>>(
      url,
      {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/json", accept: "application/json" },
        body,
        signal: opts.signal
      },
      { timeoutMs, maxBytes: maxResponseBytes }
    );

    if (!response.ok) throw new Error(`Ethereum RPC returned HTTP ${response.status}.`);
    if (payload.jsonrpc !== "2.0" || payload.id !== id) throw new Error("Ethereum RPC returned a mismatched JSON-RPC envelope.");
    if (payload.error) throw new Error(`Ethereum RPC error ${payload.error.code ?? "unknown"}: ${payload.error.message ?? "unknown error"}`);
    if (!("result" in payload)) throw new Error("Ethereum RPC response omitted result.");
    return payload.result as T;
  };
}

async function pinnedBlock(
  rpc: ReadonlyRpc,
  opts: CaptureSnapshotOptions
): Promise<{ head: number; number: number; hash: string; parentHash?: string; timestamp?: number }> {
  const chainId = await rpc<string>("eth_chainId", []);
  if (chainId !== "0x1") throw new Error("Protocol intelligence requires Ethereum Mainnet chainId 1.");

  const head = quantityToNumber(await rpc<string>("eth_blockNumber", []), "head block number");
  const confirmations = Math.max(0, Math.min(opts.confirmations ?? 12, 2_048));
  const requested = opts.blockNumber ?? Math.max(0, head - confirmations);
  if (requested > head) throw new Error("Pinned snapshot block cannot be ahead of the RPC head.");

  const tag = hexQuantity(requested);
  const block = await rpc<{ number?: string; hash?: string; parentHash?: string; timestamp?: string } | null>(
    "eth_getBlockByNumber",
    [tag, false]
  );
  if (!block?.number || !block.hash || !HASH_RE.test(block.hash)) throw new Error("RPC did not return a canonical pinned block.");
  if (quantityToNumber(block.number, "block number") !== requested) throw new Error("RPC returned a different block than requested.");
  if (opts.expectedBlockHash && block.hash.toLowerCase() !== opts.expectedBlockHash.toLowerCase()) {
    throw new Error("Pinned block hash does not match the expected canonical hash.");
  }

  return {
    head,
    number: requested,
    hash: block.hash.toLowerCase(),
    parentHash: block.parentHash && HASH_RE.test(block.parentHash) ? block.parentHash.toLowerCase() : undefined,
    timestamp: block.timestamp ? quantityToNumber(block.timestamp, "block timestamp") : undefined
  };
}

async function captureContract(
  rpc: ReadonlyRpc,
  target: SnapshotContractTarget,
  blockTag: string,
  limits: Required<Pick<CaptureSnapshotOptions, "maxCallsPerContract" | "maxSlotsPerContract">>
): Promise<ContractStateSnapshot> {
  const address = canonicalAddress(target.address);
  const code = await rpc<string>("eth_getCode", [address, blockTag]);
  if (!HEX_RE.test(code)) throw new Error("RPC returned non-canonical runtime bytecode.");

  const slotMap = new Map<string, string>();
  for (const item of [...STANDARD_PROXY_SLOTS, ...(target.slots ?? [])]) {
    if (slotMap.size >= limits.maxSlotsPerContract) break;
    const slot = canonicalSlot(item.slot);
    if (!slotMap.has(slot)) slotMap.set(slot, item.label.slice(0, 120));
  }

  const storage: SnapshotStorageObservation[] = [];
  for (const [slot, label] of slotMap) {
    const value = await rpc<string>("eth_getStorageAt", [address, slot, blockTag]);
    if (!WORD_RE.test(value)) throw new Error("RPC returned a non-canonical storage word.");
    storage.push({ slot, label, value: value.toLowerCase() });
  }

  const calls: SnapshotCallObservation[] = [];
  for (const call of (target.calls ?? []).slice(0, limits.maxCallsPerContract)) {
    if (!HEX_RE.test(call.data) || call.data.length > 131_074) {
      calls.push({ id: call.id.slice(0, 120), toRefId: target.contractRefId, data: "0x", error: "Invalid or oversized call data." });
      continue;
    }
    try {
      const result = await rpc<string>("eth_call", [{ to: address, data: call.data }, blockTag]);
      calls.push({
        id: call.id.slice(0, 120),
        toRefId: target.contractRefId,
        data: call.data.toLowerCase(),
        result: HEX_RE.test(result) ? result.toLowerCase() : undefined,
        error: HEX_RE.test(result) ? undefined : "RPC returned non-canonical call data."
      });
    } catch (error) {
      calls.push({
        id: call.id.slice(0, 120),
        toRefId: target.contractRefId,
        data: call.data.toLowerCase(),
        error: error instanceof Error ? error.message.slice(0, 300) : "eth_call failed"
      });
    }
  }

  return {
    contractRefId: target.contractRefId,
    sourceRole: target.sourceRole,
    codeSha256: sha256Hex(code),
    codeBytes: runtimeBytes(code),
    storage,
    calls
  };
}

export async function capturePinnedStateSnapshot(
  rpc: ReadonlyRpc,
  targets: SnapshotContractTarget[],
  opts: CaptureSnapshotOptions = {}
): Promise<PinnedStateSnapshot> {
  const maxContracts = Math.max(1, Math.min(opts.maxContracts ?? 64, 256));
  const maxCallsPerContract = Math.max(0, Math.min(opts.maxCallsPerContract ?? 16, 64));
  const maxSlotsPerContract = Math.max(3, Math.min(opts.maxSlotsPerContract ?? 24, 128));
  const unique = new Map<string, SnapshotContractTarget>();
  for (const target of targets) {
    if (unique.size >= maxContracts) break;
    const address = canonicalAddress(target.address);
    if (!unique.has(address)) unique.set(address, { ...target, address });
  }
  if (!unique.size) throw new Error("Pinned state snapshot requires at least one contract.");

  opts.signal?.throwIfAborted();
  const block = await pinnedBlock(rpc, opts);
  const blockTag = hexQuantity(block.number);
  const contracts: ContractStateSnapshot[] = [];

  for (const target of unique.values()) {
    opts.signal?.throwIfAborted();
    contracts.push(await captureContract(rpc, target, blockTag, { maxCallsPerContract, maxSlotsPerContract }));
  }

  const capturedAt = new Date().toISOString();
  const stable = JSON.stringify({
    chainId: 1,
    blockNumber: block.number,
    blockHash: block.hash,
    contracts
  });
  return {
    schemaVersion: 1,
    chainId: 1,
    network: "ethereum-mainnet",
    capturedAt,
    blockNumber: block.number,
    blockHash: block.hash,
    parentHash: block.parentHash,
    timestamp: block.timestamp,
    confirmationsFromHead: Math.max(0, block.head - block.number),
    contracts,
    snapshotHash: createHash("sha256").update(stable).digest("hex")
  };
}

export function proxySlotValue(snapshot: PinnedStateSnapshot, contractRefId: string, label: string) {
  return snapshot.contracts
    .find(contract => contract.contractRefId === contractRefId)
    ?.storage.find(slot => slot.label === label)?.value;
}

export function storageWordAddress(value: string | undefined) {
  if (!value || !WORD_RE.test(value) || /^0x0{64}$/i.test(value)) return undefined;
  const candidate = "0x" + value.slice(-40);
  return ADDRESS_RE.test(candidate) ? candidate.toLowerCase() : undefined;
}
