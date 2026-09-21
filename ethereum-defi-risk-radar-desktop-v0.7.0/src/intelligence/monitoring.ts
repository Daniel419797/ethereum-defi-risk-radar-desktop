import { createHash } from "node:crypto";
import {
  capturePinnedStateSnapshot,
  createReadonlyEthereumRpc,
  proxySlotObservation,
  type SnapshotContractTarget
} from "./rpc.js";
import type {
  MonitorEvent,
  MonitorEventKind,
  MonitorState,
  MonitorTarget,
  PinnedStateSnapshot
} from "./model.js";

function eventId(targetId: string, kind: MonitorEventKind, contractRefId: string | undefined, blockNumber: number | undefined, before: string | undefined, after: string | undefined) {
  return createHash("sha256")
    .update([targetId, kind, contractRefId ?? "", blockNumber ?? "", before ?? "", after ?? ""].join("|"))
    .digest("hex")
    .slice(0, 20);
}

function emitChange(
  events: MonitorEvent[],
  target: MonitorTarget,
  kind: MonitorEventKind,
  summary: string,
  snapshot: PinnedStateSnapshot,
  values: { contractRefId?: string; before?: string; after?: string; severity?: MonitorEvent["severity"] }
) {
  events.push({
    id: eventId(target.id, kind, values.contractRefId, snapshot.blockNumber, values.before, values.after),
    targetId: target.id,
    kind,
    observedAt: new Date().toISOString(),
    severity: values.severity ?? "HIGH",
    summary,
    blockNumber: snapshot.blockNumber,
    blockHash: snapshot.blockHash,
    contractRefId: values.contractRefId,
    before: values.before,
    after: values.after
  });
}

function compareSnapshots(target: MonitorTarget, before: PinnedStateSnapshot, after: PinnedStateSnapshot) {
  const events: MonitorEvent[] = [];
  const oldContracts = new Map(before.contracts.map(contract => [contract.contractRefId, contract]));
  const newContracts = new Map(after.contracts.map(contract => [contract.contractRefId, contract]));

  for (const [refId, current] of newContracts) {
    const previous = oldContracts.get(refId);
    if (!previous) continue;

    if (previous.codeSha256 !== current.codeSha256) {
      emitChange(
        events,
        target,
        "RUNTIME_CODE_CHANGED",
        "Runtime bytecode hash changed between finalized protocol snapshots.",
        after,
        { contractRefId: refId, before: previous.codeSha256, after: current.codeSha256, severity: "CRITICAL" }
      );
    }

    const slotChecks = [
      ["eip1967.implementation", "IMPLEMENTATION_CHANGED", "CRITICAL"],
      ["eip1967.admin", "ADMIN_CHANGED", "HIGH"],
      ["eip1967.beacon", "BEACON_CHANGED", "HIGH"]
    ] as const;

    for (const [slot, kind, severity] of slotChecks) {
      const oldWord = proxySlotObservation(before, refId, slot);
      const newWord = proxySlotObservation(after, refId, slot);
      if (!oldWord || !newWord || oldWord.valueSha256 === newWord.valueSha256) continue;
      emitChange(
        events,
        target,
        kind,
        `${slot} changed on the monitored protocol.`,
        after,
        {
          contractRefId: refId,
          before: oldWord.decodedAddressRef ?? oldWord.valueSha256,
          after: newWord.decodedAddressRef ?? newWord.valueSha256,
          severity
        }
      );
    }
  }

  if (!events.length && before.blockHash !== after.blockHash) {
    emitChange(
      events,
      target,
      "NEW_BLOCK_BASELINE",
      "Pinned finalized baseline advanced with no monitored code/proxy-control changes.",
      after,
      { severity: "INFO", before: String(before.blockNumber), after: String(after.blockNumber) }
    );
  }

  return events;
}

function snapshotTargets(target: MonitorTarget): SnapshotContractTarget[] {
  return target.contracts.map(contract => ({
    address: contract.address,
    contractRefId: contract.contractRefId,
    sourceRole: contract.sourceRole
  }));
}

export async function monitorProtocolOnce(
  target: MonitorTarget,
  previous?: MonitorState,
  opts: { signal?: AbortSignal; timeoutMs?: number } = {}
): Promise<MonitorState> {
  if (target.confirmations < 0 || target.confirmations > 2_048) {
    throw new Error("Monitor confirmations must be between 0 and 2048.");
  }
  if (!target.contracts.length || target.contracts.length > 128) {
    throw new Error("Monitor target must contain between 1 and 128 contracts.");
  }
  const rpc = createReadonlyEthereumRpc(target.rpcUrl, {
    timeoutMs: opts.timeoutMs ?? 20_000,
    signal: opts.signal
  });

  try {
    const snapshot = await capturePinnedStateSnapshot(rpc, snapshotTargets(target), {
      confirmations: target.confirmations,
      maxContracts: 128,
      signal: opts.signal
    });
    const events = previous?.latestSnapshot
      ? compareSnapshots(target, previous.latestSnapshot, snapshot)
      : [{
          id: eventId(target.id, "NEW_BLOCK_BASELINE", undefined, snapshot.blockNumber, undefined, snapshot.blockHash),
          targetId: target.id,
          kind: "NEW_BLOCK_BASELINE" as const,
          observedAt: new Date().toISOString(),
          severity: "INFO" as const,
          summary: "Initial pinned monitoring baseline captured.",
          blockNumber: snapshot.blockNumber,
          blockHash: snapshot.blockHash
        }];

    return {
      schemaVersion: 1,
      target: {
        id: target.id,
        protocolId: target.protocolId,
        label: target.label,
        confirmations: target.confirmations,
        contracts: target.contracts.map(({ address: _address, ...rest }) => rest)
      },
      latestSnapshot: snapshot,
      events: [...(previous?.events ?? []), ...events].slice(-5_000),
      updatedAt: new Date().toISOString()
    };
  } catch (error) {
    const now = new Date().toISOString();
    const message = error instanceof Error ? error.message : String(error);
    return {
      schemaVersion: 1,
      target: {
        id: target.id,
        protocolId: target.protocolId,
        label: target.label,
        confirmations: target.confirmations,
        contracts: target.contracts.map(({ address: _address, ...rest }) => rest)
      },
      latestSnapshot: previous?.latestSnapshot,
      events: [
        ...(previous?.events ?? []),
        {
          id: eventId(target.id, "MONITOR_ERROR", undefined, previous?.latestSnapshot?.blockNumber, message, now),
          targetId: target.id,
          kind: "MONITOR_ERROR",
          observedAt: now,
          severity: "MEDIUM",
          summary: message.slice(0, 500),
          blockNumber: previous?.latestSnapshot?.blockNumber,
          blockHash: previous?.latestSnapshot?.blockHash
        }
      ].slice(-5_000),
      updatedAt: now
    };
  }
}

function wait(ms: number, signal?: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("Monitoring cancelled."));
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(signal.reason instanceof Error ? signal.reason : new Error("Monitoring cancelled."));
    }, { once: true });
  });
}

export async function runContinuousProtocolMonitor(
  target: MonitorTarget,
  opts: {
    initialState?: MonitorState;
    intervalMs?: number;
    iterations?: number;
    signal?: AbortSignal;
    onCycle?: (state: MonitorState, newEvents: MonitorEvent[]) => void | Promise<void>;
  } = {}
) {
  const intervalMs = Math.max(30_000, Math.min(opts.intervalMs ?? 300_000, 86_400_000));
  const iterations = opts.iterations === undefined ? Number.POSITIVE_INFINITY : Math.max(1, opts.iterations);
  let state = opts.initialState;
  let completed = 0;

  while (completed < iterations) {
    opts.signal?.throwIfAborted();
    const previousEventIds = new Set(state?.events.map(event => event.id) ?? []);
    state = await monitorProtocolOnce(target, state, { signal: opts.signal });
    const newEvents = state.events.filter(event => !previousEventIds.has(event.id));
    await opts.onCycle?.(state, newEvents);
    completed += 1;
    if (completed >= iterations) break;
    await wait(intervalMs, opts.signal);
  }

  return state!;
}
