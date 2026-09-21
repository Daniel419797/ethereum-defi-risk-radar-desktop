import type {
  ReadOnlyEthereumRpcClient
} from "./rpc.js";
import {
  decodeKnownEvent,
  EVENT_TOPICS,
  type DecodedKnownEvent,
  type KnownEventKind
} from "./eventCatalog.js";

export type UpgradeTimelineEntry = {
  blockNumber: number;
  transactionHash: string;
  kind: KnownEventKind;
  fields: Record<string, string>;
  source: string;
};

export type UpgradeTimeline = {
  address: string;
  fromBlock: number;
  toBlock: number;
  entries: UpgradeTimelineEntry[];
  implementationHistory: string[];
  adminHistory: string[];
  ownershipHistory: string[];
  timelockDelayHistory: string[];
  truncated: boolean;
  limitations: string[];
};

const CONTROL_EVENTS: KnownEventKind[] = [
  "UPGRADED",
  "ADMIN_CHANGED",
  "BEACON_UPGRADED",
  "DIAMOND_CUT",
  "OWNERSHIP_TRANSFERRED",
  "ROLE_GRANTED",
  "ROLE_REVOKED",
  "MIN_DELAY_CHANGE",
  "PROPOSAL_EXECUTED"
];

export async function reconstructUpgradeTimeline(opts: {
  reader: ReadOnlyEthereumRpcClient;
  address: string;
  fromBlock: number;
  toBlock: number;
  chunkSize?: number;
  maxEntries?: number;
}) {
  if (
    opts.toBlock < opts.fromBlock
  ) {
    throw new Error(
      "Upgrade timeline block range is invalid."
    );
  }
  const chunkSize = Math.max(
    100,
    Math.min(
      opts.chunkSize ?? 20_000,
      100_000
    )
  );
  const maxEntries = Math.max(
    1,
    Math.min(
      opts.maxEntries ?? 10_000,
      50_000
    )
  );
  const entries: UpgradeTimelineEntry[] = [];
  let truncated = false;

  for (
    let start = opts.fromBlock;
    start <= opts.toBlock;
    start += chunkSize
  ) {
    const end = Math.min(
      opts.toBlock,
      start + chunkSize - 1
    );
    const logs =
      await opts.reader.getLogs({
        fromBlock: start,
        toBlock: end,
        address: opts.address,
        topics: [
          CONTROL_EVENTS.map(
            kind => EVENT_TOPICS[kind]
          )
        ]
      });
    for (const log of logs) {
      const decoded =
        decodeKnownEvent(log);
      if (
        !decoded ||
        !CONTROL_EVENTS.includes(
          decoded.kind
        )
      ) {
        continue;
      }
      entries.push({
        blockNumber:
          decoded.blockNumber,
        transactionHash:
          decoded.transactionHash,
        kind: decoded.kind,
        fields: decoded.fields,
        source:
          log.address.toLowerCase()
      });
      if (
        entries.length >=
        maxEntries
      ) {
        truncated = true;
        break;
      }
    }
    if (truncated) break;
  }

  entries.sort(
    (a, b) =>
      a.blockNumber -
        b.blockNumber ||
      a.transactionHash.localeCompare(
        b.transactionHash
      )
  );

  const implementationHistory =
    entries.flatMap(entry => {
      if (
        entry.kind === "UPGRADED"
      ) {
        return entry.fields.account
          ? [entry.fields.account]
          : [];
      }
      return [];
    });
  const adminHistory =
    entries.flatMap(entry =>
      entry.kind ===
        "ADMIN_CHANGED" &&
      entry.fields.newAdmin
        ? [entry.fields.newAdmin]
        : []
    );
  const ownershipHistory =
    entries.flatMap(entry =>
      entry.kind ===
        "OWNERSHIP_TRANSFERRED" &&
      entry.fields.newOwner
        ? [entry.fields.newOwner]
        : []
    );
  const timelockDelayHistory =
    entries.flatMap(entry =>
      entry.kind ===
        "MIN_DELAY_CHANGE" &&
      entry.fields.newDelay
        ? [entry.fields.newDelay]
        : []
    );

  return {
    address:
      opts.address.toLowerCase(),
    fromBlock: opts.fromBlock,
    toBlock: opts.toBlock,
    entries,
    implementationHistory,
    adminHistory,
    ownershipHistory,
    timelockDelayHistory,
    truncated,
    limitations: [
      "Timeline reconstructs standardized control events emitted by the watched address; silent/custom upgrades require bytecode/state comparison.",
      "RoleGranted/RoleRevoked history does not prove the current complete role set if the requested block range begins after deployment."
    ]
  } satisfies UpgradeTimeline;
}
