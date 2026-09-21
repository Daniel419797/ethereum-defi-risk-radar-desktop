import type {
  ReadOnlyEthereumRpcClient
} from "./rpc.js";
import {
  addressTopic,
  decodeKnownEvent,
  EVENT_TOPICS,
  type DecodedKnownEvent
} from "./eventCatalog.js";

export type RuntimeAlert = {
  severity:
    | "INFO"
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "CRITICAL";
  kind:
    | "UPGRADE"
    | "AUTHORITY_CHANGE"
    | "PAUSE"
    | "TOKEN_OUTFLOW"
    | "LARGE_APPROVAL"
    | "MINT"
    | "BURN";
  blockNumber: number;
  transactionHash: string;
  contract: string;
  summary: string;
  evidence: Record<string, string>;
};

function eventAlert(
  event: DecodedKnownEvent
): RuntimeAlert | undefined {
  if (
    event.kind === "UPGRADED" ||
    event.kind ===
      "BEACON_UPGRADED" ||
    event.kind === "DIAMOND_CUT"
  ) {
    return {
      severity: "HIGH",
      kind: "UPGRADE",
      blockNumber:
        event.blockNumber,
      transactionHash:
        event.transactionHash,
      contract: event.address,
      summary:
        event.kind.replaceAll(
          "_",
          " "
        ) +
        " observed.",
      evidence: event.fields
    };
  }

  if (
    [
      "ADMIN_CHANGED",
      "OWNERSHIP_TRANSFERRED",
      "ROLE_GRANTED",
      "ROLE_REVOKED",
      "MIN_DELAY_CHANGE"
    ].includes(event.kind)
  ) {
    return {
      severity: "HIGH",
      kind: "AUTHORITY_CHANGE",
      blockNumber:
        event.blockNumber,
      transactionHash:
        event.transactionHash,
      contract: event.address,
      summary:
        event.kind.replaceAll(
          "_",
          " "
        ) +
        " observed.",
      evidence: event.fields
    };
  }

  if (
    event.kind === "PAUSED" ||
    event.kind === "UNPAUSED"
  ) {
    return {
      severity:
        event.kind === "PAUSED"
          ? "HIGH"
          : "MEDIUM",
      kind: "PAUSE",
      blockNumber:
        event.blockNumber,
      transactionHash:
        event.transactionHash,
      contract: event.address,
      summary:
        event.kind === "PAUSED"
          ? "Emergency pause observed."
          : "Protocol unpause observed.",
      evidence: event.fields
    };
  }

  return undefined;
}

async function controlAlerts(opts: {
  reader: ReadOnlyEthereumRpcClient;
  watchedAddresses: string[];
  fromBlock: number;
  toBlock: number;
}) {
  const topics = [
    "UPGRADED",
    "ADMIN_CHANGED",
    "BEACON_UPGRADED",
    "DIAMOND_CUT",
    "OWNERSHIP_TRANSFERRED",
    "ROLE_GRANTED",
    "ROLE_REVOKED",
    "PAUSED",
    "UNPAUSED",
    "MIN_DELAY_CHANGE"
  ].map(
    key =>
      EVENT_TOPICS[
        key as keyof typeof EVENT_TOPICS
      ]
  );
  const logs =
    await opts.reader.getLogs({
      fromBlock: opts.fromBlock,
      toBlock: opts.toBlock,
      address:
        opts.watchedAddresses,
      topics: [topics]
    });
  return logs.flatMap(log => {
    const decoded =
      decodeKnownEvent(log);
    const alert = decoded
      ? eventAlert(decoded)
      : undefined;
    return alert ? [alert] : [];
  });
}

async function tokenFlowAlerts(opts: {
  reader: ReadOnlyEthereumRpcClient;
  watchedAddresses: string[];
  fromBlock: number;
  toBlock: number;
  rawOutflowThreshold?: bigint;
  rawApprovalThreshold?: bigint;
}) {
  const alerts: RuntimeAlert[] = [];
  for (const watched of
    opts.watchedAddresses.slice(0, 50)) {
    const fromTopic =
      addressTopic(watched);

    const transfers =
      await opts.reader.getLogs({
        fromBlock: opts.fromBlock,
        toBlock: opts.toBlock,
        topics: [
          EVENT_TOPICS.TRANSFER,
          fromTopic
        ]
      });
    for (const log of
      transfers.slice(0, 5_000)) {
      const decoded =
        decodeKnownEvent(log);
      if (!decoded) continue;
      const value = BigInt(
        decoded.fields.value || "0"
      );
      if (
        opts.rawOutflowThreshold !==
          undefined &&
        value <
          opts.rawOutflowThreshold
      ) {
        continue;
      }
      const burn =
        /^0x0{40}$/.test(
          decoded.fields.to || ""
        );
      alerts.push({
        severity:
          opts.rawOutflowThreshold !==
          undefined
            ? "HIGH"
            : "INFO",
        kind: burn
          ? "BURN"
          : "TOKEN_OUTFLOW",
        blockNumber:
          decoded.blockNumber,
        transactionHash:
          decoded.transactionHash,
        contract:
          decoded.address,
        summary: burn
          ? "Token burn from watched address."
          : "Token outflow from watched address.",
        evidence: decoded.fields
      });
    }

    const approvals =
      await opts.reader.getLogs({
        fromBlock: opts.fromBlock,
        toBlock: opts.toBlock,
        topics: [
          EVENT_TOPICS.APPROVAL,
          fromTopic
        ]
      });
    for (const log of
      approvals.slice(0, 5_000)) {
      const decoded =
        decodeKnownEvent(log);
      if (!decoded) continue;
      const value = BigInt(
        decoded.fields.value || "0"
      );
      if (
        opts.rawApprovalThreshold ===
          undefined ||
        value <
          opts.rawApprovalThreshold
      ) {
        continue;
      }
      alerts.push({
        severity: "HIGH",
        kind: "LARGE_APPROVAL",
        blockNumber:
          decoded.blockNumber,
        transactionHash:
          decoded.transactionHash,
        contract:
          decoded.address,
        summary:
          "Approval exceeded configured raw-unit threshold.",
        evidence: decoded.fields
      });
    }
  }
  return alerts;
}

export async function scanRuntimeActivity(opts: {
  reader: ReadOnlyEthereumRpcClient;
  watchedAddresses: string[];
  fromBlock: number;
  toBlock: number;
  rawOutflowThreshold?: bigint;
  rawApprovalThreshold?: bigint;
}) {
  if (
    !opts.watchedAddresses.length
  ) {
    return {
      alerts: [] as RuntimeAlert[],
      limitations: [
        "No watched addresses supplied."
      ]
    };
  }
  if (
    opts.toBlock - opts.fromBlock >
    25_000
  ) {
    throw new Error(
      "Transaction-aware monitoring is capped at 25,000 blocks per cycle."
    );
  }

  const normalized = [
    ...new Set(
      opts.watchedAddresses.map(
        value =>
          value.toLowerCase()
      )
    )
  ].slice(0, 100);

  const [
    controls,
    flows
  ] = await Promise.all([
    controlAlerts({
      reader: opts.reader,
      watchedAddresses:
        normalized,
      fromBlock: opts.fromBlock,
      toBlock: opts.toBlock
    }),
    tokenFlowAlerts({
      reader: opts.reader,
      watchedAddresses:
        normalized,
      fromBlock: opts.fromBlock,
      toBlock: opts.toBlock,
      rawOutflowThreshold:
        opts.rawOutflowThreshold,
      rawApprovalThreshold:
        opts.rawApprovalThreshold
    })
  ]);

  const alerts = [
    ...controls,
    ...flows
  ].sort(
    (a, b) =>
      a.blockNumber -
        b.blockNumber ||
      a.transactionHash.localeCompare(
        b.transactionHash
      )
  );

  return {
    alerts,
    limitations: [
      "Raw token values are not converted to economic value unless the caller supplies token-specific thresholds.",
      "Event absence is not proof that custom assembly or silent state changes did not occur; snapshot/code monitoring remains authoritative for silent upgrades.",
      "Monitoring is read-only and does not sign or broadcast transactions."
    ]
  };
}
