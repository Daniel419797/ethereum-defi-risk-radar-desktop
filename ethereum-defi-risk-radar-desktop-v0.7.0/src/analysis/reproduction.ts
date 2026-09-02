import { createHash } from "node:crypto";
import { fetchJsonBounded } from "../boundedFetch.js";
import { finalizeFinding } from "./evidence.js";
import type { AnalysisFinding, Counterexample } from "./model.js";

export type ForkTransaction = { from: string; to: string; data?: string; value?: string };
export type ForkInvariantCall = { to: string; data: string; expectedBefore?: string; violation: "changed" | "transaction_reverted" | "zero"; transactionIndex?: number };
export type ForkReplaySpec = { rpcUrl: string; chainId: 1; blockNumber: number; blockHash: string; transactions: ForkTransaction[]; invariant: ForkInvariantCall; invariantId: string };
type JsonRpc = <T>(method: string, params: unknown[]) => Promise<T>;
type TransactionReceipt = { status?: string; transactionHash?: string };

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const BYTES = /^0x(?:[a-fA-F0-9]{2})*$/;
const HASH = /^0x[a-fA-F0-9]{64}$/;
const QUANTITY = /^0x(?:0|[1-9a-fA-F][a-fA-F0-9]*)$/;

function exactKeys(value: Record<string, unknown>, allowed: string[], label: string) {
  const extra = Object.keys(value).filter(key => !allowed.includes(key));
  if (extra.length) throw new Error(`${label} contains unsupported fields: ${extra.join(", ")}`);
}

function validateSpec(input: ForkReplaySpec) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Fork replay spec must be an object");
  exactKeys(input as unknown as Record<string, unknown>, ["rpcUrl", "chainId", "blockNumber", "blockHash", "transactions", "invariant", "invariantId"], "Fork replay spec");
  if (input.chainId !== 1) throw new Error("Fork replay requires Ethereum mainnet chainId 1");
  if (!Number.isSafeInteger(input.blockNumber) || input.blockNumber <= 0) throw new Error("Fork replay requires a positive pinned block number");
  if (!HASH.test(input.blockHash)) throw new Error("Fork replay requires a canonical pinned block hash");
  if (typeof input.invariantId !== "string" || !input.invariantId.trim() || input.invariantId.length > 200) throw new Error("Fork replay requires a bounded invariantId");
  if (!Array.isArray(input.transactions) || !input.transactions.length || input.transactions.length > 1_000) throw new Error("Fork replay requires 1-1000 transactions");
  const url = new URL(input.rpcUrl);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password) throw new Error("Fork replay RPC must be an unauthenticated IPv4 loopback HTTP endpoint");
  for (const tx of input.transactions) {
    if (!tx || typeof tx !== "object" || Array.isArray(tx)) throw new Error("Each fork transaction must be an object");
    exactKeys(tx as unknown as Record<string, unknown>, ["from", "to", "data", "value"], "Fork transaction");
    if (!ADDRESS.test(tx.from) || !ADDRESS.test(tx.to) || (tx.data !== undefined && !BYTES.test(tx.data)) || (tx.value !== undefined && !QUANTITY.test(tx.value))) throw new Error("Fork transaction fields must be canonical hex values");
  }
  if (!input.invariant || typeof input.invariant !== "object" || Array.isArray(input.invariant)) throw new Error("Fork invariant must be an object");
  exactKeys(input.invariant as unknown as Record<string, unknown>, ["to", "data", "expectedBefore", "violation", "transactionIndex"], "Fork invariant");
  if (!ADDRESS.test(input.invariant.to) || !BYTES.test(input.invariant.data) || (input.invariant.expectedBefore !== undefined && !BYTES.test(input.invariant.expectedBefore))) throw new Error("Fork invariant fields must be canonical hex values");
  if (!["changed", "transaction_reverted", "zero"].includes(input.invariant.violation)) throw new Error("Fork invariant violation is unsupported");
  if (input.invariant.violation === "transaction_reverted" && (!Number.isInteger(input.invariant.transactionIndex) || input.invariant.transactionIndex! < 0 || input.invariant.transactionIndex! >= input.transactions.length)) throw new Error("transaction_reverted requires a valid transactionIndex");
  return input;
}

function rpcClient(url: string, timeoutMs: number, signal?: AbortSignal): JsonRpc {
  let id = 0;
  return async <T>(method: string, params: unknown[]) => {
    const requestId = ++id;
    const body = JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params });
    if (body.length > 2_000_000) throw new Error("Anvil RPC request exceeded 2 MB");
    const { payload, response } = await fetchJsonBounded<{ jsonrpc?: string; id?: number; result?: T; error?: { message?: string } }>(new URL(url), { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body, signal }, { timeoutMs, maxBytes: 2_000_000 });
    if (!response.ok) throw new Error(`Anvil RPC returned HTTP ${response.status}`);
    if (payload.jsonrpc !== "2.0" || payload.id !== requestId) throw new Error("Anvil RPC returned a mismatched JSON-RPC response");
    if (payload.error) throw new Error(payload.error.message ?? "Anvil RPC error");
    if (!("result" in payload)) throw new Error("Anvil RPC response omitted result");
    return payload.result as T;
  };
}

export async function replayOnPinnedAnvil(rawSpec: ForkReplaySpec, opts: { timeoutMs?: number; rpc?: JsonRpc; signal?: AbortSignal } = {}): Promise<AnalysisFinding | undefined> {
  const spec = validateSpec(rawSpec);
  const rpc = opts.rpc ?? rpcClient(spec.rpcUrl, opts.timeoutMs ?? 30_000, opts.signal);
  const cleanupRpc = opts.rpc ?? rpcClient(spec.rpcUrl, opts.timeoutMs ?? 30_000);
  opts.signal?.throwIfAborted();
  if (!String(await rpc<string>("web3_clientVersion", [])).toLowerCase().includes("anvil")) throw new Error("Fork replay endpoint did not identify as Anvil");
  if (await rpc<string>("eth_chainId", []) !== "0x1") throw new Error("Fork replay endpoint is not Ethereum mainnet");
  const blockTag = `0x${spec.blockNumber.toString(16)}`;
  const block = await rpc<{ number?: string; hash?: string } | null>("eth_getBlockByNumber", [blockTag, false]);
  if (!block || block.number !== blockTag || block.hash?.toLowerCase() !== spec.blockHash.toLowerCase()) throw new Error("Fork replay endpoint does not match the pinned canonical block hash");
  if (await rpc<string>("eth_blockNumber", []) !== blockTag) throw new Error("Fork replay endpoint is not positioned at the pinned block");
  const snapshot = await rpc<string>("evm_snapshot", []);
  try {
    const call = { to: spec.invariant.to, data: spec.invariant.data };
    const before = await rpc<string>("eth_call", [call, blockTag]);
    if (spec.invariant.expectedBefore !== undefined && spec.invariant.expectedBefore !== before) throw new Error("Fork invariant baseline does not match expectedBefore");
    const hashes: string[] = [];
    const receipts: Array<{ status: string; transactionHash: string }> = [];
    for (const tx of spec.transactions) {
      opts.signal?.throwIfAborted();
      await rpc<boolean>("anvil_impersonateAccount", [tx.from]);
      try {
        const projected = { from: tx.from, to: tx.to, ...(tx.data === undefined ? {} : { data: tx.data }), ...(tx.value === undefined ? {} : { value: tx.value }), gas: "0x7a1200" };
        const hash = await rpc<string>("eth_sendTransaction", [projected]);
        if (!HASH.test(hash)) throw new Error("Anvil returned an invalid transaction hash");
        hashes.push(hash);
        let receipt: TransactionReceipt | null = null;
        for (let attempt = 0; attempt < 20 && !receipt; attempt += 1) {
          opts.signal?.throwIfAborted();
          receipt = await rpc<TransactionReceipt | null>("eth_getTransactionReceipt", [hash]);
          if (!receipt) await new Promise(resolve => setTimeout(resolve, 25));
        }
        if (!receipt || receipt.transactionHash?.toLowerCase() !== hash.toLowerCase() || !["0x0", "0x1"].includes(receipt.status ?? "")) throw new Error("Anvil returned an invalid or unavailable transaction receipt");
        receipts.push(receipt as { status: string; transactionHash: string });
      } catch (error) {
        throw new Error(`Fork transaction could not be replayed: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        await cleanupRpc<boolean>("anvil_stopImpersonatingAccount", [tx.from]);
      }
    }
    const after = await rpc<string>("eth_call", [call, "latest"]);
    if (spec.invariant.violation !== "transaction_reverted" && receipts.some(receipt => receipt.status === "0x0")) throw new Error("Fork replay transaction reverted before the requested state invariant could be evaluated");
    const violated = spec.invariant.violation === "changed" ? after !== before : spec.invariant.violation === "zero" ? /^0x0*$/.test(after) : receipts[spec.invariant.transactionIndex!]?.status === "0x0";
    if (!violated) return undefined;
    const sequence = spec.transactions.map((tx, index) => `${hashes[index]}:${JSON.stringify({ from: tx.from, to: tx.to, data: tx.data, value: tx.value })}`);
    const counterexample: Counterexample = { engine: "anvil", scope: "model", sequence, observedViolation: `${spec.invariantId}: ${spec.invariant.violation}; before=${before}; after=${after}`, invariantId: spec.invariantId, seed: spec.blockNumber };
    return finalizeFinding({ id: createHash("sha256").update(JSON.stringify(counterexample)).digest("hex").slice(0, 16), kind: "invariant_testing", engine: "anvil", severity: "HIGH", evidenceStrength: "EXECUTED", evidenceScope: "model", title: `External Anvil replay observed ${spec.invariantId}`, description: counterexample.observedViolation, counterexample, limitations: ["The caller-selected loopback endpoint is not process-authenticated, so this observation cannot earn fork-scope REPRODUCED evidence or CONFIRMED_AT_PINNED_BLOCK."] });
  } finally {
    const restored = await cleanupRpc<boolean>("evm_revert", [snapshot]);
    if (!restored) throw new Error("Anvil replay state could not be restored to its snapshot");
  }
}
