import { createHash } from "node:crypto";
import { finalizeFinding } from "./evidence.js";
import type { AnalysisFinding, Counterexample } from "./model.js";
import { fetchJsonBounded } from "../boundedFetch.js";

export type ForkTransaction = { from: string; to: string; data?: string; value?: string };
export type ForkInvariantCall = { to: string; data: string; expectedBefore?: string; violation: "changed" | "reverted" | "zero" };
export type ForkReplaySpec = { rpcUrl: string; blockNumber: number; transactions: ForkTransaction[]; invariant: ForkInvariantCall; invariantId: string };
type JsonRpc = <T>(method: string, params: unknown[]) => Promise<T>;

function rpcClient(url: string, timeoutMs: number): JsonRpc {
  let id = 0;
  return async <T>(method: string, params: unknown[]) => {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const body = JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params });
      if (body.length > 2_000_000) throw new Error("Anvil RPC request exceeded 2 MB");
      const { payload } = await fetchJsonBounded<{ result?: T; error?: { message?: string } }>(new URL(url), { method: "POST", headers: { "content-type": "application/json" }, body, signal: controller.signal }, { timeoutMs, maxBytes: 2_000_000 });
      if (payload.error) throw new Error(payload.error.message ?? "Anvil RPC error");
      return payload.result as T;
    } finally { clearTimeout(timer); }
  };
}

export async function replayOnPinnedAnvil(spec: ForkReplaySpec, opts: { timeoutMs?: number; rpc?: JsonRpc } = {}): Promise<AnalysisFinding | undefined> {
  if (!Number.isSafeInteger(spec.blockNumber) || spec.blockNumber <= 0) throw new Error("Fork replay requires a positive pinned block number");
  if (!/^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?(?:\/.*)?$/i.test(spec.rpcUrl)) throw new Error("Fork replay RPC must be a loopback Anvil endpoint");
  if (!spec.transactions.length || spec.transactions.length > 1_000) throw new Error("Fork replay requires 1-1000 transactions");
  const addressRe = /^0x[a-fA-F0-9]{40}$/; const bytesRe = /^0x(?:[a-fA-F0-9]{2})*$/;
  if (!addressRe.test(spec.invariant.to) || !bytesRe.test(spec.invariant.data) || spec.transactions.some(transaction => !addressRe.test(transaction.from) || !addressRe.test(transaction.to) || (transaction.data !== undefined && !bytesRe.test(transaction.data)))) throw new Error("Fork replay addresses and calldata must be canonical hex values");
  const rpc = opts.rpc ?? rpcClient(spec.rpcUrl, opts.timeoutMs ?? 30_000); const actualBlock = Number.parseInt(await rpc<string>("eth_blockNumber", []), 16);
  if (actualBlock !== spec.blockNumber) throw new Error(`Anvil block ${actualBlock} does not match pinned block ${spec.blockNumber}`);
  const before = await rpc<string>("eth_call", [{ to: spec.invariant.to, data: spec.invariant.data }, "latest"]); let reverted = false; const hashes: string[] = [];
  if (spec.invariant.expectedBefore !== undefined && spec.invariant.expectedBefore !== before) throw new Error("Fork invariant baseline does not match expectedBefore");
  for (const transaction of spec.transactions) {
    await rpc<boolean>("anvil_impersonateAccount", [transaction.from]);
    try {
      const hash = await rpc<string>("eth_sendTransaction", [{ ...transaction, gas: "0x7a1200" }]); hashes.push(hash);
      const receipt = await rpc<{ status?: string }>("eth_getTransactionReceipt", [hash]); if (receipt?.status === "0x0") reverted = true;
    } catch (error) { throw new Error(`Fork transaction could not be replayed: ${error instanceof Error ? error.message : String(error)}`); }
    finally { await rpc<boolean>("anvil_stopImpersonatingAccount", [transaction.from]); }
  }
  const after = await rpc<string>("eth_call", [{ to: spec.invariant.to, data: spec.invariant.data }, "latest"]);
  const violated = spec.invariant.violation === "changed" ? after !== before : spec.invariant.violation === "zero" ? /^0x0*$/.test(after) : reverted;
  if (!violated) return undefined;
  const sequence = spec.transactions.map((transaction, index) => `${hashes[index] ?? "reverted"}:${JSON.stringify(transaction)}`); const counterexample: Counterexample = { engine: "anvil", scope: "fork", sequence, observedViolation: `${spec.invariantId}: ${spec.invariant.violation}; before=${before}; after=${after}`, invariantId: spec.invariantId, blockNumber: spec.blockNumber };
  return finalizeFinding({ id: createHash("sha256").update(JSON.stringify(counterexample)).digest("hex").slice(0, 16), kind: "invariant_testing", engine: "anvil", severity: "HIGH", evidenceStrength: "REPRODUCED", evidenceScope: "fork", title: `Fork replay violated ${spec.invariantId}`, description: counterexample.observedViolation, counterexample });
}
