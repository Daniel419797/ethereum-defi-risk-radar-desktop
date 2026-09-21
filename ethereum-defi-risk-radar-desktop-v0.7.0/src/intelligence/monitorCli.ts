import fs from "node:fs/promises";
import path from "node:path";
import { monitorProtocolOnce, runContinuousProtocolMonitor } from "./monitoring.js";
import { readMonitorState, writeMonitorState } from "./upgrade.js";
import type { MonitorTarget } from "./model.js";

type MonitorSpec = Omit<MonitorTarget, "rpcUrl"> & { rpcUrl?: string };

function option(args: string[], name: string) {
  return args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
}

function intOption(args: string[], name: string, fallback: number, min: number, max: number) {
  const raw = option(args, name);
  const value = raw === undefined ? fallback : Number.parseInt(raw, 10);
  return Number.isSafeInteger(value) ? Math.max(min, Math.min(value, max)) : fallback;
}

async function readSpec(filePath: string): Promise<MonitorSpec> {
  const resolved = path.resolve(filePath);
  const stat = await fs.stat(resolved);
  if (!stat.isFile() || stat.size > 2_000_000) throw new Error("Monitor target must be JSON no larger than 2 MB.");
  const spec = JSON.parse(await fs.readFile(resolved, "utf8")) as MonitorSpec;
  if (!spec.id || !spec.protocolId || !spec.label || !Array.isArray(spec.contracts) || !spec.contracts.length) {
    throw new Error("Monitor target is missing id, protocolId, label or contracts.");
  }
  return spec;
}

export async function runMonitorCli(args: string[], defaultRpcUrl: string | undefined, defaultOutputDir: string) {
  const specArg = args.find(arg => !arg.startsWith("--"));
  if (!specArg) {
    throw new Error("Usage: risk-radar monitor <target.json> [--interval-seconds=300] [--iterations=1] [--state=<file>] [--use-target-rpc]");
  }

  const spec = await readSpec(specArg);
  const rpcUrl = args.includes("--use-target-rpc") ? spec.rpcUrl : defaultRpcUrl;
  if (!rpcUrl) {
    throw new Error("No Ethereum RPC is configured. Use `risk-radar config set rpc-url` or explicitly pass --use-target-rpc with a reviewed target file.");
  }

  const target: MonitorTarget = { ...spec, rpcUrl };
  const statePath = path.resolve(
    option(args, "state") ??
    path.join(defaultOutputDir, "monitors", `${target.id.replace(/[^A-Za-z0-9_.-]/g, "_")}.json`)
  );
  const previous = await readMonitorState(statePath);
  const iterations = intOption(args, "iterations", 1, 1, 100_000);
  const intervalMs = intOption(args, "interval-seconds", 300, 30, 86_400) * 1_000;

  if (iterations === 1) {
    const state = await monitorProtocolOnce(target, previous);
    await writeMonitorState(statePath, state);
    const newEvents = state.events.slice(previous?.events.length ?? 0);
    console.log(JSON.stringify({ statePath, snapshot: state.latestSnapshot, events: newEvents }, null, 2));
    return newEvents.some(event => event.severity === "CRITICAL" || event.severity === "HIGH") ? 3 : 0;
  }

  const controller = new AbortController();
  const abort = () => controller.abort(new Error("Monitoring interrupted by user."));
  process.once("SIGINT", abort);
  process.once("SIGTERM", abort);
  try {
    const state = await runContinuousProtocolMonitor(target, {
      initialState: previous,
      iterations,
      intervalMs,
      signal: controller.signal,
      onCycle: async (current, newEvents) => {
        await writeMonitorState(statePath, current);
        for (const event of newEvents) console.log(JSON.stringify(event));
      }
    });
    await writeMonitorState(statePath, state);
    return state.events.some(event => event.severity === "CRITICAL" || event.severity === "HIGH") ? 3 : 0;
  } finally {
    process.removeListener("SIGINT", abort);
    process.removeListener("SIGTERM", abort);
  }
}
