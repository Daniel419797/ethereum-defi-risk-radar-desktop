import { fetchJsonBounded } from "../boundedFetch.js";

const ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const HASH = /^0x[a-fA-F0-9]{64}$/;
const HEX = /^0x(?:[a-fA-F0-9]{2})*$/;
const QUANTITY = /^0x(?:0|[1-9a-fA-F][a-fA-F0-9]*)$/;

type RpcEnvelope<T> = { jsonrpc?: string; id?: number; result?: T; error?: { code?: number; message?: string } };

function validateEndpoint(value: string) {
  const url = new URL(value);
  const local = url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
  const remote = url.protocol === "https:";
  if (!local && !remote) throw new Error("Ethereum RPC must use HTTPS, or HTTP on localhost/127.0.0.1.");
  if (url.username || url.password) throw new Error("Ethereum RPC URL must not contain URL userinfo credentials.");
  return url;
}

export type ChainBlock = { number: number; hash: string; timestamp: number };

export interface ReadOnlyChainReader {
  getChainId(): Promise<number>;
  getBlock(block: "latest" | number): Promise<ChainBlock>;
  getCode(address: string, blockNumber: number): Promise<string>;
  getStorageAt(address: string, slot: string, blockNumber: number): Promise<string>;
  call(address: string, data: string, blockNumber: number): Promise<string>;
}

export class ReadOnlyEthereumRpcClient implements ReadOnlyChainReader {
  private readonly endpoint: URL;
  private id = 0;
  constructor(endpoint: string, private readonly timeoutMs = 20_000) {
    this.endpoint = validateEndpoint(endpoint);
  }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const allowed = new Set(["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_call"]);
    if (!allowed.has(method)) throw new Error("Blocked non-read-only Ethereum RPC method.");
    const requestId = ++this.id;
    const body = JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params });
    const { response, payload } = await fetchJsonBounded<RpcEnvelope<T>>(
      this.endpoint,
      { method: "POST", redirect: "error", headers: { "content-type": "application/json" }, body },
      { timeoutMs: this.timeoutMs, maxBytes: 4_000_000 }
    );
    if (!response.ok) throw new Error("Ethereum RPC returned HTTP " + response.status);
    if (payload.jsonrpc !== "2.0" || payload.id !== requestId) throw new Error("Ethereum RPC response identity mismatch.");
    if (payload.error) throw new Error(payload.error.message || "Ethereum RPC returned an error.");
    if (!("result" in payload)) throw new Error("Ethereum RPC response omitted result.");
    return payload.result as T;
  }

  async getChainId() {
    const value = await this.rpc<string>("eth_chainId", []);
    if (!QUANTITY.test(value)) throw new Error("Ethereum RPC returned invalid chain id.");
    return Number.parseInt(value.slice(2), 16);
  }

  async getBlock(block: "latest" | number): Promise<ChainBlock> {
    const tag = block === "latest" ? "latest" : "0x" + block.toString(16);
    const value = await this.rpc<{ number?: string; hash?: string; timestamp?: string } | null>("eth_getBlockByNumber", [tag, false]);
    if (!value?.number || !value.hash || !value.timestamp || !QUANTITY.test(value.number) || !HASH.test(value.hash) || !QUANTITY.test(value.timestamp)) {
      throw new Error("Ethereum RPC returned an invalid block.");
    }
    return { number: Number.parseInt(value.number.slice(2), 16), hash: value.hash.toLowerCase(), timestamp: Number.parseInt(value.timestamp.slice(2), 16) };
  }

  async getCode(address: string, blockNumber: number) {
    if (!ADDRESS.test(address)) throw new Error("Invalid Ethereum address.");
    const value = await this.rpc<string>("eth_getCode", [address, "0x" + blockNumber.toString(16)]);
    if (!HEX.test(value)) throw new Error("Ethereum RPC returned invalid runtime bytecode.");
    return value.toLowerCase();
  }

  async getStorageAt(address: string, slot: string, blockNumber: number) {
    if (!ADDRESS.test(address) || !/^0x[a-fA-F0-9]{64}$/.test(slot)) throw new Error("Invalid storage query.");
    const value = await this.rpc<string>("eth_getStorageAt", [address, slot, "0x" + blockNumber.toString(16)]);
    if (!HEX.test(value)) throw new Error("Ethereum RPC returned invalid storage value.");
    return value.toLowerCase();
  }

  async call(address: string, data: string, blockNumber: number) {
    if (!ADDRESS.test(address) || !HEX.test(data)) throw new Error("Invalid eth_call query.");
    const value = await this.rpc<string>("eth_call", [{ to: address, data }, "0x" + blockNumber.toString(16)]);
    if (!HEX.test(value)) throw new Error("Ethereum RPC returned invalid eth_call result.");
    return value.toLowerCase();
  }
}
