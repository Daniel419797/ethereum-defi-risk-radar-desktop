import {
  eventTopic
} from "../analysis/bytecode/keccak.js";
import {
  decodeAddressWord,
  decodeUintWord,
  topicAddress
} from "./abi.js";
import type { RpcLog } from "./rpc.js";

export type KnownEventKind =
  | "UPGRADED"
  | "ADMIN_CHANGED"
  | "BEACON_UPGRADED"
  | "DIAMOND_CUT"
  | "OWNERSHIP_TRANSFERRED"
  | "ROLE_GRANTED"
  | "ROLE_REVOKED"
  | "PAUSED"
  | "UNPAUSED"
  | "MIN_DELAY_CHANGE"
  | "PROPOSAL_EXECUTED"
  | "TRANSFER"
  | "APPROVAL";

const signatures: Record<
  KnownEventKind,
  string
> = {
  UPGRADED: "Upgraded(address)",
  ADMIN_CHANGED:
    "AdminChanged(address,address)",
  BEACON_UPGRADED:
    "BeaconUpgraded(address)",
  DIAMOND_CUT:
    "DiamondCut((address,uint8,bytes4[])[],address,bytes)",
  OWNERSHIP_TRANSFERRED:
    "OwnershipTransferred(address,address)",
  ROLE_GRANTED:
    "RoleGranted(bytes32,address,address)",
  ROLE_REVOKED:
    "RoleRevoked(bytes32,address,address)",
  PAUSED: "Paused(address)",
  UNPAUSED: "Unpaused(address)",
  MIN_DELAY_CHANGE:
    "MinDelayChange(uint256,uint256)",
  PROPOSAL_EXECUTED:
    "ProposalExecuted(uint256)",
  TRANSFER:
    "Transfer(address,address,uint256)",
  APPROVAL:
    "Approval(address,address,uint256)"
};

export const EVENT_TOPICS =
  Object.fromEntries(
    Object.entries(signatures).map(
      ([kind, signature]) => [
        kind,
        eventTopic(signature)
      ]
    )
  ) as Record<KnownEventKind, string>;

const byTopic = new Map(
  Object.entries(EVENT_TOPICS).map(
    ([kind, topic]) => [
      topic.toLowerCase(),
      kind as KnownEventKind
    ]
  )
);

export type DecodedKnownEvent = {
  kind: KnownEventKind;
  address: string;
  blockNumber: number;
  transactionHash: string;
  logIndex: number;
  fields: Record<string, string>;
};

function quantity(value: string) {
  return Number.parseInt(
    value.replace(/^0x/, "") || "0",
    16
  );
}

export function decodeKnownEvent(
  log: RpcLog
): DecodedKnownEvent | undefined {
  const kind = byTopic.get(
    log.topics[0]?.toLowerCase()
  );
  if (!kind) return undefined;
  const fields: Record<string, string> =
    {};

  try {
    if (
      kind === "UPGRADED" ||
      kind === "BEACON_UPGRADED" ||
      kind === "PAUSED" ||
      kind === "UNPAUSED"
    ) {
      if (log.topics[1]) {
        fields.account =
          topicAddress(log.topics[1]);
      }
    } else if (
      kind === "OWNERSHIP_TRANSFERRED"
    ) {
      if (log.topics[1]) {
        fields.previousOwner =
          topicAddress(log.topics[1]);
      }
      if (log.topics[2]) {
        fields.newOwner =
          topicAddress(log.topics[2]);
      }
    } else if (
      kind === "ROLE_GRANTED" ||
      kind === "ROLE_REVOKED"
    ) {
      if (log.topics[1]) {
        fields.role =
          log.topics[1].toLowerCase();
      }
      if (log.topics[2]) {
        fields.account =
          topicAddress(log.topics[2]);
      }
      if (log.topics[3]) {
        fields.sender =
          topicAddress(log.topics[3]);
      }
    } else if (
      kind === "ADMIN_CHANGED"
    ) {
      fields.previousAdmin =
        decodeAddressWord(log.data, 0);
      fields.newAdmin =
        decodeAddressWord(log.data, 1);
    } else if (
      kind === "MIN_DELAY_CHANGE"
    ) {
      fields.oldDelay =
        decodeUintWord(
          log.data,
          0
        ).toString();
      fields.newDelay =
        decodeUintWord(
          log.data,
          1
        ).toString();
    } else if (
      kind === "PROPOSAL_EXECUTED"
    ) {
      if (log.topics[1]) {
        fields.proposalId =
          BigInt(
            log.topics[1]
          ).toString();
      } else {
        fields.proposalId =
          decodeUintWord(
            log.data,
            0
          ).toString();
      }
    } else if (
      kind === "TRANSFER" ||
      kind === "APPROVAL"
    ) {
      if (log.topics[1]) {
        fields.from =
          topicAddress(log.topics[1]);
      }
      if (log.topics[2]) {
        fields.to =
          topicAddress(log.topics[2]);
      }
      fields.value =
        decodeUintWord(
          log.data,
          0
        ).toString();
    }
  } catch {
    fields.decodeStatus = "partial";
  }

  return {
    kind,
    address:
      log.address.toLowerCase(),
    blockNumber:
      quantity(log.blockNumber),
    transactionHash:
      log.transactionHash.toLowerCase(),
    logIndex: quantity(log.logIndex),
    fields
  };
}

export function addressTopic(
  address: string
) {
  const body = address
    .toLowerCase()
    .replace(/^0x/, "");
  if (!/^[a-f0-9]{40}$/.test(body)) {
    throw new Error(
      "Invalid address topic."
    );
  }
  return (
    "0x" +
    body.padStart(64, "0")
  );
}
