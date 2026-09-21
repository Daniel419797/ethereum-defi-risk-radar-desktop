import { createHash } from "node:crypto";
import type { ContractStateSnapshot, PinnedStateSnapshot, SnapshotProbe } from "./model.js";
import type { ReadOnlyChainReader } from "./rpc.js";
import { bytecodeHash, bytecodeSize } from "./bytecode.js";

export const EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
export const EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

export type SnapshotCallProbe = { id: string; data: string };
export type SnapshotTarget = { address: string; contractRefId: string; callProbes?: SnapshotCallProbe[] };

function digest(value: unknown) {
  return "sha256:" + createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function normalizeStorageAddress(value: string) {
  const body = value.replace(/^0x/, "").padStart(64, "0");
  if (!/^[a-f0-9]{64}$/i.test(body)) return null;
  const address = "0x" + body.slice(-40).toLowerCase();
  return /^0x0{40}$/.test(address) ? null : address;
}

async function safeStorage(reader: ReadOnlyChainReader, address: string, slot: string, blockNumber: number) {
  try {
    return await reader.getStorageAt(address, slot, blockNumber);
  } catch {
    return null;
  }
}

async function captureContract(reader: ReadOnlyChainReader, target: SnapshotTarget, blockNumber: number) {
  const code = await reader.getCode(target.address, blockNumber);
  const [implementationRaw, adminRaw, beaconRaw] = await Promise.all([
    safeStorage(reader, target.address, EIP1967_IMPLEMENTATION_SLOT, blockNumber),
    safeStorage(reader, target.address, EIP1967_ADMIN_SLOT, blockNumber),
    safeStorage(reader, target.address, EIP1967_BEACON_SLOT, blockNumber)
  ]);

  const probes: SnapshotProbe[] = [];
  for (const probe of target.callProbes ?? []) {
    try {
      const value = await reader.call(target.address, probe.data, blockNumber);
      probes.push({ id: probe.id, kind: "CALL", value, success: true });
    } catch (error) {
      probes.push({ id: probe.id, kind: "CALL", value: null, success: false, error: error instanceof Error ? error.message : String(error) });
    }
  }

  const snapshot: ContractStateSnapshot = {
    contractRefId: target.contractRefId,
    codeHash: bytecodeHash(code),
    codeBytes: bytecodeSize(code),
    implementationSlot: implementationRaw ? normalizeStorageAddress(implementationRaw) : null,
    adminSlot: adminRaw ? normalizeStorageAddress(adminRaw) : null,
    beaconSlot: beaconRaw ? normalizeStorageAddress(beaconRaw) : null,
    probes
  };
  return snapshot;
}

export async function capturePinnedStateSnapshot(opts: {
  reader: ReadOnlyChainReader;
  targets: SnapshotTarget[];
  blockNumber?: number;
}): Promise<PinnedStateSnapshot> {
  if (!opts.targets.length) throw new Error("Pinned state snapshot requires at least one contract target.");
  if (opts.targets.length > 128) throw new Error("Pinned state snapshot target limit is 128 contracts.");
  const chainId = await opts.reader.getChainId();
  if (chainId !== 1) throw new Error("Pinned state snapshots currently require Ethereum Mainnet chainId 1.");

  const block = await opts.reader.getBlock(opts.blockNumber ?? "latest");
  if (opts.blockNumber !== undefined && block.number !== opts.blockNumber) throw new Error("RPC did not return the requested pinned block.");
  const contracts: ContractStateSnapshot[] = [];
  let partial = false;
  const limitations: string[] = [];

  for (const target of opts.targets) {
    try {
      contracts.push(await captureContract(opts.reader, target, block.number));
    } catch (error) {
      partial = true;
      limitations.push(target.contractRefId + ": " + (error instanceof Error ? error.message : String(error)));
    }
  }

  const canonical = {
    chainId: 1,
    blockNumber: block.number,
    blockHash: block.hash,
    timestamp: block.timestamp,
    contracts: [...contracts].sort((a, b) => a.contractRefId.localeCompare(b.contractRefId))
  };

  return {
    version: 1,
    ...canonical,
    capturedAt: new Date().toISOString(),
    digest: digest(canonical),
    partial,
    limitations
  };
}
