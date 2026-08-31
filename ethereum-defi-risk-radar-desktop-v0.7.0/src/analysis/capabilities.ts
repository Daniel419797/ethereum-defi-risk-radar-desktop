import { spawn } from "node:child_process";
import os from "node:os";
import type { ToolCapability } from "./model.js";

type ToolDefinition = { id: ToolCapability["id"]; executable: string; args: string[] };

const TOOLS: ToolDefinition[] = [
  { id: "slither", executable: "slither", args: ["--version"] },
  { id: "mythril", executable: "myth", args: ["version"] },
  { id: "foundry", executable: "forge", args: ["--version"] },
  { id: "anvil", executable: "anvil", args: ["--version"] },
  { id: "echidna", executable: "echidna", args: ["--version"] },
  { id: "python", executable: process.platform === "win32" ? "python" : "python3", args: ["--version"] },
  { id: "docker", executable: "docker", args: ["--version"] }
];

export async function probeTool(
  definition: ToolDefinition,
  opts: { timeoutMs?: number; spawnFn?: typeof spawn } = {}
): Promise<ToolCapability> {
  const spawnFn = opts.spawnFn ?? spawn;
  const timeoutMs = Math.max(100, Math.min(opts.timeoutMs ?? 2_000, 10_000));
  return await new Promise(resolve => {
    let output = "";
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (value: ToolCapability) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };
    let child;
    try {
      child = spawnFn(definition.executable, definition.args, {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: { PATH: process.env.PATH },
        cwd: os.tmpdir()
      });
    } catch (error) {
      finish({ id: definition.id, available: false, reason: error instanceof Error ? error.message : "spawn failed" });
      return;
    }
    timer = setTimeout(() => {
      child.kill();
      finish({ id: definition.id, available: false, reason: "version probe timed out" });
    }, timeoutMs);
    child.stdout?.on("data", chunk => { if (output.length < 4_096) output += String(chunk); });
    child.stderr?.on("data", chunk => { if (output.length < 4_096) output += String(chunk); });
    child.on("error", error => finish({ id: definition.id, available: false, reason: error.message }));
    child.on("close", code => finish(code === 0
      ? { id: definition.id, available: true, executable: definition.executable, version: output.trim().split(/\r?\n/)[0]?.slice(0, 200) }
      : { id: definition.id, available: false, reason: `version probe exited ${code ?? "unknown"}` }));
  });
}

export async function detectAnalysisCapabilities(ids?: ReadonlySet<ToolCapability["id"]>): Promise<ToolCapability[]> {
  const selected = ids ? TOOLS.filter(tool => ids.has(tool.id)) : TOOLS;
  return await Promise.all(selected.map(tool => probeTool(tool)));
}
