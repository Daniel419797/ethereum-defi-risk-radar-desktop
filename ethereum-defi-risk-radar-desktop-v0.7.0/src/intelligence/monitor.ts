import type { MonitorChange, MonitorDiff, PinnedStateSnapshot } from "./model.js";
import { capturePinnedStateSnapshot, type SnapshotTarget } from "./snapshot.js";
import type { ReadOnlyChainReader } from "./rpc.js";

function contractMap(snapshot: PinnedStateSnapshot) {
  return new Map(snapshot.contracts.map(contract => [contract.contractRefId, contract]));
}

export function diffPinnedSnapshots(previous: PinnedStateSnapshot, current: PinnedStateSnapshot): MonitorDiff {
  if (previous.chainId !== current.chainId) throw new Error("Cannot compare snapshots from different chains.");
  if (current.blockNumber <= previous.blockNumber) throw new Error("Current snapshot must be newer than previous snapshot.");

  const changes: MonitorChange[] = [];
  const before = contractMap(previous);
  const after = contractMap(current);

  for (const [contractRefId, next] of after) {
    const prior = before.get(contractRefId);
    if (!prior) continue;

    const add = (
      kind: MonitorChange["kind"],
      left: string | null,
      right: string | null,
      severity: MonitorChange["severity"],
      probeId?: string
    ) => {
      if (left === right) return;
      changes.push({ kind, contractRefId, probeId, before: left, after: right, severity });
    };

    add("CODE_CHANGED", prior.codeHash, next.codeHash, "CRITICAL");
    add("IMPLEMENTATION_CHANGED", prior.implementationSlot, next.implementationSlot, "HIGH");
    add("ADMIN_CHANGED", prior.adminSlot, next.adminSlot, "HIGH");
    add("BEACON_CHANGED", prior.beaconSlot, next.beaconSlot, "HIGH");

    const previousProbes = new Map(prior.probes.map(probe => [probe.id, probe]));
    for (const probe of next.probes) {
      const old = previousProbes.get(probe.id);
      if (!old || !old.success || !probe.success) continue;
      add("PROBE_CHANGED", old.value, probe.value, "MEDIUM", probe.id);
    }
  }

  return {
    previousBlock: previous.blockNumber,
    currentBlock: current.blockNumber,
    changed: changes.length > 0,
    changes
  };
}

export async function runMonitorCycle(opts: {
  reader: ReadOnlyChainReader;
  targets: SnapshotTarget[];
  previous?: PinnedStateSnapshot;
  blockNumber?: number;
}) {
  const snapshot = await capturePinnedStateSnapshot({
    reader: opts.reader,
    targets: opts.targets,
    blockNumber: opts.blockNumber
  });

  return {
    snapshot,
    diff:
      opts.previous && snapshot.blockNumber > opts.previous.blockNumber
        ? diffPinnedSnapshots(opts.previous, snapshot)
        : undefined
  };
}
