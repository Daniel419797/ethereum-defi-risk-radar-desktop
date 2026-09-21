import { fetchJsonBounded } from "../boundedFetch.js";

export const ETH_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
export const ETH_HASH_RE = /^0x[a-fA-F0-9]{64}$/;
export const ETH_HEX_RE = /^0x(?:[a-fA-F0-9]{2})*$/;
export const ETH_QUANTITY_RE = /^0x(?:0|[1-9a-fA-F][a-fA-F0-9]*)$/;

type RpcEnvelope<T> = {
  jsonrpc?: string;
  id?: number;
  result?: T;
  error?: { code?: number; message?: string };
};

export type ChainBlock = {
  number: number;
  hash: string;
  timestamp: number;
};

export type RpcTransaction = {
  hash: string;
  from: string;
  to: string | null;
  input: string;
  value: string;
  blockNumber?: string | null;
  transactionIndex?: string | null;
};

export type RpcLog = {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex: string;
  removed?: boolean;
};

export type RpcTransactionReceipt = {
  transactionHash: string;
  blockNumber: string;
  blockHash: string;
  status?: string;
  gasUsed?: string;
  effectiveGasPrice?: string;
  contractAddress?: string | null;
  logs: RpcLog[];
};

export type RpcCallTrace = {
  type?: string;
  from?: string;
  to?: string;
  input?: string;
  output?: string;
  value?: string;
  gas?: string;
  gasUsed?: string;
  error?: string;
  revertReason?: string;
  calls?: RpcCallTrace[];
};

function validateEndpoint(value: string) {
  const url = new URL(value);
  const local =
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" ||
      url.hostname === "localhost");
  const remote = url.protocol === "https:";
  if (!local && !remote) {
    throw new Error(
      "Ethereum RPC must use HTTPS, or HTTP on localhost/127.0.0.1."
    );
  }
  if (url.username || url.password) {
    throw new Error(
      "Ethereum RPC URL must not contain URL userinfo credentials."
    );
  }
  return url;
}

function blockTag(blockNumber: number) {
  if (
    !Number.isSafeInteger(blockNumber) ||
    blockNumber < 0
  ) {
    throw new Error("Invalid Ethereum block number.");
  }
  return "0x" + blockNumber.toString(16);
}

function normalizeAddress(value: string) {
  if (!ETH_ADDRESS_RE.test(value)) {
    throw new Error("Invalid Ethereum address.");
  }
  return value.toLowerCase();
}

function normalizeTopic(value: string | null) {
  if (value === null) return null;
  if (!ETH_HASH_RE.test(value)) {
    throw new Error("Invalid Ethereum log topic.");
  }
  return value.toLowerCase();
}

export interface ReadOnlyChainReader {
  getChainId(): Promise<number>;
  getBlock(
    block: "latest" | number
  ): Promise<ChainBlock>;
  getCode(
    address: string,
    blockNumber: number
  ): Promise<string>;
  getStorageAt(
    address: string,
    slot: string,
    blockNumber: number
  ): Promise<string>;
  call(
    address: string,
    data: string,
    blockNumber: number
  ): Promise<string>;
}

export class ReadOnlyEthereumRpcClient
  implements ReadOnlyChainReader
{
  private readonly endpoint: URL;
  private id = 0;

  constructor(
    endpoint: string,
    private readonly timeoutMs = 20_000
  ) {
    this.endpoint = validateEndpoint(endpoint);
  }

  private async rpc<T>(
    method: string,
    params: unknown[],
    maxBytes = 4_000_000
  ): Promise<T> {
    const allowed = new Set([
      "eth_chainId",
      "eth_getBlockByNumber",
      "eth_getBlockByHash",
      "eth_getCode",
      "eth_getStorageAt",
      "eth_call",
      "eth_getBalance",
      "eth_getTransactionByHash",
      "eth_getTransactionReceipt",
      "eth_getLogs",
      "debug_traceTransaction"
    ]);
    if (!allowed.has(method)) {
      throw new Error(
        "Blocked non-read-only Ethereum RPC method."
      );
    }

    const requestId = ++this.id;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: requestId,
      method,
      params
    });
    if (body.length > 2_000_000) {
      throw new Error(
        "Ethereum RPC request exceeded 2 MB."
      );
    }

    const { response, payload } =
      await fetchJsonBounded<RpcEnvelope<T>>(
        this.endpoint,
        {
          method: "POST",
          redirect: "error",
          headers: {
            "content-type": "application/json"
          },
          body
        },
        {
          timeoutMs: this.timeoutMs,
          maxBytes: Math.max(
            4_000_000,
            Math.min(maxBytes, 50_000_000)
          )
        }
      );

    if (!response.ok) {
      throw new Error(
        "Ethereum RPC returned HTTP " +
          response.status
      );
    }
    if (
      payload.jsonrpc !== "2.0" ||
      payload.id !== requestId
    ) {
      throw new Error(
        "Ethereum RPC response identity mismatch."
      );
    }
    if (payload.error) {
      throw new Error(
        payload.error.message ||
          "Ethereum RPC returned an error."
      );
    }
    if (!("result" in payload)) {
      throw new Error(
        "Ethereum RPC response omitted result."
      );
    }
    return payload.result as T;
  }

  async getChainId() {
    const value = await this.rpc<string>(
      "eth_chainId",
      []
    );
    if (!ETH_QUANTITY_RE.test(value)) {
      throw new Error(
        "Ethereum RPC returned invalid chain id."
      );
    }
    return Number.parseInt(
      value.slice(2),
      16
    );
  }

  async getBlock(
    block: "latest" | number
  ): Promise<ChainBlock> {
    const tag =
      block === "latest"
        ? "latest"
        : blockTag(block);
    const value = await this.rpc<{
      number?: string;
      hash?: string;
      timestamp?: string;
    } | null>(
      "eth_getBlockByNumber",
      [tag, false]
    );
    if (
      !value?.number ||
      !value.hash ||
      !value.timestamp ||
      !ETH_QUANTITY_RE.test(value.number) ||
      !ETH_HASH_RE.test(value.hash) ||
      !ETH_QUANTITY_RE.test(value.timestamp)
    ) {
      throw new Error(
        "Ethereum RPC returned an invalid block."
      );
    }
    return {
      number: Number.parseInt(
        value.number.slice(2),
        16
      ),
      hash: value.hash.toLowerCase(),
      timestamp: Number.parseInt(
        value.timestamp.slice(2),
        16
      )
    };
  }

  async getBlockByHash(hash: string) {
    if (!ETH_HASH_RE.test(hash)) {
      throw new Error("Invalid block hash.");
    }
    const value = await this.rpc<{
      number?: string;
      hash?: string;
      timestamp?: string;
    } | null>(
      "eth_getBlockByHash",
      [hash, false]
    );
    if (
      !value?.number ||
      !value.hash ||
      !value.timestamp
    ) {
      throw new Error(
        "Ethereum RPC returned an invalid block."
      );
    }
    return {
      number: Number.parseInt(
        value.number.slice(2),
        16
      ),
      hash: value.hash.toLowerCase(),
      timestamp: Number.parseInt(
        value.timestamp.slice(2),
        16
      )
    };
  }

  async getCode(
    address: string,
    blockNumber: number
  ) {
    const value = await this.rpc<string>(
      "eth_getCode",
      [
        normalizeAddress(address),
        blockTag(blockNumber)
      ]
    );
    if (!ETH_HEX_RE.test(value)) {
      throw new Error(
        "Ethereum RPC returned invalid runtime bytecode."
      );
    }
    return value.toLowerCase();
  }

  async getStorageAt(
    address: string,
    slot: string,
    blockNumber: number
  ) {
    if (
      !/^0x[a-fA-F0-9]{64}$/.test(slot)
    ) {
      throw new Error("Invalid storage query.");
    }
    const value = await this.rpc<string>(
      "eth_getStorageAt",
      [
        normalizeAddress(address),
        slot.toLowerCase(),
        blockTag(blockNumber)
      ]
    );
    if (!ETH_HEX_RE.test(value)) {
      throw new Error(
        "Ethereum RPC returned invalid storage value."
      );
    }
    return value.toLowerCase();
  }

  async call(
    address: string,
    data: string,
    blockNumber: number
  ) {
    if (!ETH_HEX_RE.test(data)) {
      throw new Error("Invalid eth_call data.");
    }
    const value = await this.rpc<string>(
      "eth_call",
      [
        {
          to: normalizeAddress(address),
          data: data.toLowerCase()
        },
        blockTag(blockNumber)
      ]
    );
    if (!ETH_HEX_RE.test(value)) {
      throw new Error(
        "Ethereum RPC returned invalid eth_call result."
      );
    }
    return value.toLowerCase();
  }

  async getBalance(
    address: string,
    blockNumber: number
  ) {
    const value = await this.rpc<string>(
      "eth_getBalance",
      [
        normalizeAddress(address),
        blockTag(blockNumber)
      ]
    );
    if (!ETH_QUANTITY_RE.test(value)) {
      throw new Error(
        "Ethereum RPC returned invalid balance."
      );
    }
    return BigInt(value);
  }

  async getTransactionByHash(
    transactionHash: string
  ) {
    if (!ETH_HASH_RE.test(transactionHash)) {
      throw new Error(
        "Invalid transaction hash."
      );
    }
    const value =
      await this.rpc<RpcTransaction | null>(
        "eth_getTransactionByHash",
        [transactionHash]
      );
    if (!value) return null;
    if (
      !ETH_HASH_RE.test(value.hash) ||
      !ETH_ADDRESS_RE.test(value.from) ||
      (value.to !== null &&
        !ETH_ADDRESS_RE.test(value.to)) ||
      !ETH_HEX_RE.test(value.input) ||
      !ETH_QUANTITY_RE.test(value.value)
    ) {
      throw new Error(
        "Ethereum RPC returned an invalid transaction."
      );
    }
    return value;
  }

  async getTransactionReceipt(
    transactionHash: string
  ) {
    if (!ETH_HASH_RE.test(transactionHash)) {
      throw new Error(
        "Invalid transaction hash."
      );
    }
    const value =
      await this.rpc<RpcTransactionReceipt | null>(
        "eth_getTransactionReceipt",
        [transactionHash],
        12_000_000
      );
    if (!value) return null;
    if (
      !ETH_HASH_RE.test(
        value.transactionHash
      ) ||
      !ETH_HASH_RE.test(value.blockHash) ||
      !ETH_QUANTITY_RE.test(
        value.blockNumber
      ) ||
      !Array.isArray(value.logs)
    ) {
      throw new Error(
        "Ethereum RPC returned an invalid transaction receipt."
      );
    }
    return value;
  }

  async getLogs(opts: {
    fromBlock: number;
    toBlock: number;
    address?: string | string[];
    topics?: Array<
      string | null | string[]
    >;
  }) {
    if (
      opts.toBlock < opts.fromBlock ||
      opts.toBlock - opts.fromBlock >
        250_000
    ) {
      throw new Error(
        "Log query block range is invalid or too large."
      );
    }

    const address = Array.isArray(
      opts.address
    )
      ? opts.address.map(normalizeAddress)
      : opts.address
        ? normalizeAddress(opts.address)
        : undefined;

    const topics = opts.topics?.map(
      topic =>
        Array.isArray(topic)
          ? topic.map(value =>
              normalizeTopic(value)
            )
          : normalizeTopic(topic)
    );

    const value = await this.rpc<RpcLog[]>(
      "eth_getLogs",
      [
        {
          fromBlock: blockTag(
            opts.fromBlock
          ),
          toBlock: blockTag(opts.toBlock),
          ...(address
            ? { address }
            : {}),
          ...(topics ? { topics } : {})
        }
      ],
      20_000_000
    );
    if (!Array.isArray(value)) {
      throw new Error(
        "Ethereum RPC returned invalid logs."
      );
    }
    return value.slice(0, 100_000);
  }

  async debugTraceTransaction(
    transactionHash: string
  ) {
    if (!ETH_HASH_RE.test(transactionHash)) {
      throw new Error(
        "Invalid transaction hash."
      );
    }
    const trace = await this.rpc<RpcCallTrace>(
      "debug_traceTransaction",
      [
        transactionHash,
        {
          tracer: "callTracer",
          tracerConfig: {
            onlyTopCall: false,
            withLog: false
          },
          timeout: "30s"
        }
      ],
      40_000_000
    );
    return trace;
  }
}
