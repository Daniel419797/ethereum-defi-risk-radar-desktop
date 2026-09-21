import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import type { MonitorDiff, PinnedStateSnapshot } from "./model.js";
import type { SnapshotTarget } from "./snapshot.js";
import type { ReadOnlyChainReader } from "./rpc.js";
import { runMonitorCycle } from "./monitor.js";

export type ProtocolWatch = {
  id: string;
  name: string;
  intervalMinutes: number;
  targets: SnapshotTarget[];
  createdAt: string;
  lastRunAt?: string;
  lastSnapshot?: PinnedStateSnapshot;
};

export type ProtocolMonitorRegistry = {
  version: 1;
  watches: ProtocolWatch[];
};

export type MonitorCycleResult = {
  watchId: string;
  name: string;
  snapshot: PinnedStateSnapshot;
  diff?: MonitorDiff;
};

function watchId(name: string, targets: SnapshotTarget[]) {
  return createHash("sha256")
    .update(name.trim().toLowerCase() + "|" + targets.map(target => target.contractRefId).sort().join("|"))
    .digest("hex")
    .slice(0, 16);
}

export async function readMonitorRegistry(filePath: string): Promise<ProtocolMonitorRegistry> {
  try {
    const parsed = JSON.parse(await fs.readFile(filePath, "utf8")) as ProtocolMonitorRegistry;
    if (parsed?.version !== 1 || !Array.isArray(parsed.watches)) throw new Error("unsupported monitor registry");
    return parsed;
  } catch {
    return { version: 1, watches: [] };
  }
}

export async function writeMonitorRegistry(filePath: string, registry: ProtocolMonitorRegistry) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(registry, null, 2), { encoding: "utf8", mode: 0o600 });
}

export async function upsertProtocolWatch(
  filePath: string,
  input: { name: string; intervalMinutes?: number; targets: SnapshotTarget[] }
) {
  const name = input.name.trim();
  if (!name) throw new Error("Monitor watch requires a name.");
  if (!input.targets.length || input.targets.length > 128) throw new Error("Monitor watch requires 1-128 targets.");
  const intervalMinutes = Math.max(5, Math.min(1440, Math.trunc(input.intervalMinutes ?? 15)));
  const registry = await readMonitorRegistry(filePath);
  const id = watchId(name, input.targets);
  const existing = registry.watches.find(watch => watch.id === id);
  const watch: ProtocolWatch = {
    id,
    name,
    intervalMinutes,
    targets: input.targets,
    createdAt: existing?.createdAt || new Date().toISOString(),
    lastRunAt: existing?.lastRunAt,
    lastSnapshot: existing?.lastSnapshot
  };
  registry.watches = [...registry.watches.filter(item => item.id !== id), watch];
  await writeMonitorRegistry(filePath, registry);
  return watch;
}

export async function removeProtocolWatch(filePath: string, idOrName: string) {
  const registry = await readMonitorRegistry(filePath);
  const before = registry.watches.length;
  registry.watches = registry.watches.filter(
    watch => watch.id !== idOrName && watch.name.toLowerCase() !== idOrName.toLowerCase()
  );
  await writeMonitorRegistry(filePath, registry);
  return before !== registry.watches.length;
}

export function watchIsDue(watch: ProtocolWatch, now = Date.now()) {
  if (!watch.lastRunAt) return true;
  return now - new Date(watch.lastRunAt).getTime() >= watch.intervalMinutes * 60_000;
}

export async function runProtocolWatch(
  filePath: string,
  reader: ReadOnlyChainReader,
  idOrName: string
): Promise<MonitorCycleResult> {
  const registry = await readMonitorRegistry(filePath);
  const watch = registry.watches.find(
    item => item.id === idOrName || item.name.toLowerCase() === idOrName.toLowerCase()
  );
  if (!watch) throw new Error("Protocol monitor watch not found.");

  const result = await runMonitorCycle({
    reader,
    targets: watch.targets,
    previous: watch.lastSnapshot
  });

  watch.lastRunAt = new Date().toISOString();
  watch.lastSnapshot = result.snapshot;
  await writeMonitorRegistry(filePath, registry);
  return { watchId: watch.id, name: watch.name, ...result };
}

export async function runDueProtocolWatches(
  filePath: string,
  reader: ReadOnlyChainReader
): Promise<MonitorCycleResult[]> {
  const registry = await readMonitorRegistry(filePath);
  const results: MonitorCycleResult[] = [];
  for (const watch of registry.watches) {
    if (!watchIsDue(watch)) continue;
    const result = await runMonitorCycle({
      reader,
      targets: watch.targets,
      previous: watch.lastSnapshot
    });
    watch.lastRunAt = new Date().toISOString();
    watch.lastSnapshot = result.snapshot;
    results.push({ watchId: watch.id, name: watch.name, ...result });
  }
  if (results.length) await writeMonitorRegistry(filePath, registry);
  return results;
}
