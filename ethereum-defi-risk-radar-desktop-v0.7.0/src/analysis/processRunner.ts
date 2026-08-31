import { spawn } from "node:child_process";
import path from "node:path";
import type { EngineRunState } from "./model.js";

const ALLOWED_EXECUTABLES = new Set(["slither", "slither.exe", "myth", "myth.exe", "forge", "forge.exe", "anvil", "anvil.exe", "echidna", "echidna.exe", "docker", "docker.exe"]);

export type ProcessRunResult = {
  state: Extract<EngineRunState, "complete" | "failed" | "timed_out" | "cancelled">;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  truncated: boolean;
};

function validateArgument(value: string) {
  if (value.includes("\0")) throw new Error("Process arguments cannot contain NUL bytes");
  if (value.length > 32_768) throw new Error("Process argument exceeds the safety limit");
}

export async function runBoundedProcess(opts: {
  executable: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
}): Promise<ProcessRunResult> {
  const executableName = path.basename(opts.executable).toLowerCase();
  if (opts.executable !== executableName && opts.executable.toLowerCase() !== executableName) {
    throw new Error("Analyzer executable must be an allowlisted bare command name");
  }
  if (!ALLOWED_EXECUTABLES.has(executableName)) throw new Error(`Executable is not allowlisted: ${executableName}`);
  opts.args.forEach(validateArgument);
  if (!path.isAbsolute(opts.cwd)) throw new Error("Analyzer working directory must be absolute");
  const timeoutMs = Math.max(100, Math.min(opts.timeoutMs, 3_600_000));
  const maxOutputBytes = Math.max(1_024, Math.min(opts.maxOutputBytes, 50_000_000));
  const started = Date.now();

  return await new Promise((resolve, reject) => {
    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let finalState: ProcessRunResult["state"] | undefined;
    let settled = false;
    const child = spawn(opts.executable, opts.args, {
      cwd: opts.cwd,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { PATH: process.env.PATH, HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE },
      detached: process.platform !== "win32"
    });
    const append = (current: Buffer<ArrayBufferLike>, chunk: Buffer<ArrayBufferLike>): Buffer<ArrayBufferLike> => {
      if (current.length >= maxOutputBytes) { truncated = true; return current; }
      if (current.length + chunk.length > maxOutputBytes) truncated = true;
      return Buffer.concat([current, chunk.subarray(0, maxOutputBytes - current.length)]);
    };
    child.stdout.on("data", chunk => { stdout = append(stdout, Buffer.from(chunk)); });
    child.stderr.on("data", chunk => { stderr = append(stderr, Buffer.from(chunk)); });
    const terminate = (state: ProcessRunResult["state"]) => {
      if (finalState) return;
      finalState = state;
      if (process.platform === "win32" && child.pid) {
        spawn("taskkill.exe", ["/pid", String(child.pid), "/t", "/f"], {
          shell: false, windowsHide: true, stdio: "ignore"
        }).unref();
      } else if (child.pid) {
        try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill(); }
        setTimeout(() => {
          try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already exited */ }
        }, 1_000).unref();
      } else {
        child.kill();
      }
    };
    const timer = setTimeout(() => terminate("timed_out"), timeoutMs);
    const abort = () => terminate("cancelled");
    opts.signal?.addEventListener("abort", abort, { once: true });
    child.on("error", error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", abort);
      reject(error);
    });
    child.on("close", exitCode => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", abort);
      resolve({
        state: finalState ?? (exitCode === 0 ? "complete" : "failed"),
        exitCode,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        durationMs: Date.now() - started,
        truncated
      });
    });
  });
}
