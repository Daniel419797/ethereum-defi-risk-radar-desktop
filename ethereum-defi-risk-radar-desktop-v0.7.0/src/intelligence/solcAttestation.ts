import { spawn } from "node:child_process";
import os from "node:os";

type StandardJsonSource = { content: string };
type StandardJsonInput = {
  language: "Solidity";
  sources: Record<string, StandardJsonSource>;
  settings: Record<string, unknown>;
};

export type LocalCompilationResult = {
  available: boolean;
  exactCompiler: boolean;
  compilerVersion?: string;
  expectedRuntime?: string;
  contractName?: string;
  diagnostics: string[];
};

const HEX_RUNTIME = /^(?:[a-fA-F0-9]{2})+$/;
const MAX_INPUT_BYTES = 8_000_000;
const MAX_OUTPUT_BYTES = 24_000_000;

function normalizeExplorerCompiler(value: string | undefined) {
  return (value ?? "").trim().replace(/^v/, "");
}

function compilerBuildMatches(expected: string | undefined, actualOutput: string) {
  const wanted = normalizeExplorerCompiler(expected);
  if (!wanted) return false;
  const match = actualOutput.match(/Version:\s*([^\s]+)/i);
  if (!match?.[1]) return false;
  const actual = match[1].replace(/^v/, "");
  return actual === wanted || actual.startsWith(wanted + ".");
}

async function runSolc(
  args: string[],
  stdin: string | undefined,
  opts: { timeoutMs: number; maxOutputBytes: number; signal?: AbortSignal }
) {
  return await new Promise<{ code: number | null; stdout: string; stderr: string; truncated: boolean }>((resolve, reject) => {
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let truncated = false;
    let settled = false;
    const child = spawn("solc", args, {
      cwd: os.tmpdir(),
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: { PATH: process.env.PATH },
      detached: process.platform !== "win32"
    });

    const append = (current: Buffer, chunk: Buffer) => {
      if (current.length >= opts.maxOutputBytes) {
        truncated = true;
        return current;
      }
      if (current.length + chunk.length > opts.maxOutputBytes) truncated = true;
      return Buffer.concat([current, chunk.subarray(0, Math.max(0, opts.maxOutputBytes - current.length))]);
    };

    child.stdout.on("data", chunk => { stdout = append(stdout, Buffer.from(chunk)); });
    child.stderr.on("data", chunk => { stderr = append(stderr, Buffer.from(chunk)); });

    const terminate = () => {
      if (process.platform === "win32" && child.pid) {
        spawn("taskkill.exe", ["/pid", String(child.pid), "/t", "/f"], {
          shell: false,
          windowsHide: true,
          stdio: "ignore"
        }).unref();
      } else if (child.pid) {
        try { process.kill(-child.pid, "SIGTERM"); } catch { child.kill(); }
        setTimeout(() => {
          try { process.kill(-child.pid!, "SIGKILL"); } catch { /* already exited */ }
        }, 750).unref();
      }
    };

    const timer = setTimeout(() => terminate(), opts.timeoutMs);
    const abort = () => terminate();
    opts.signal?.addEventListener("abort", abort, { once: true });

    child.on("error", error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", abort);
      reject(error);
    });
    child.on("close", code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      opts.signal?.removeEventListener("abort", abort);
      resolve({
        code,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        truncated
      });
    });

    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

function parseVerifiedSource(raw: string): { sources: Record<string, StandardJsonSource>; settings?: Record<string, unknown> } {
  const source = raw.trim();
  if (!source) throw new Error("Verified source is empty.");
  const attempts = [source];
  if (source.startsWith("{{") && source.endsWith("}}")) attempts.unshift(source.slice(1, -1));

  for (const attempt of attempts) {
    if (!attempt.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(attempt) as {
        sources?: Record<string, string | { content?: string; urls?: string[] }>;
        settings?: Record<string, unknown>;
        language?: string;
      };
      if (!parsed.sources || typeof parsed.sources !== "object") continue;
      const sources: Record<string, StandardJsonSource> = {};
      for (const [name, value] of Object.entries(parsed.sources)) {
        if (typeof value === "string") {
          sources[name] = { content: value };
          continue;
        }
        if (Array.isArray(value?.urls) && value.urls.length > 0) {
          throw new Error("Verified-source compiler input contains URL-backed sources; exact attestation requires in-memory source content only.");
        }
        if (typeof value?.content === "string") sources[name] = { content: value.content };
      }
      if (!Object.keys(sources).length) throw new Error("Verified-source compiler input contains no in-memory Solidity source.");
      return { sources, settings: parsed.settings && typeof parsed.settings === "object" ? parsed.settings : undefined };
    } catch (error) {
      if (error instanceof Error && /URL-backed|no in-memory/.test(error.message)) throw error;
    }
  }

  return { sources: { "Contract.sol": { content: source } } };
}

function buildStandardInput(input: {
  sourceText: string;
  optimizationUsed?: boolean;
  optimizationRuns?: number;
  evmVersion?: string;
  library?: string;
}) {
  const parsed = parseVerifiedSource(input.sourceText);
  const settings: Record<string, unknown> = { ...(parsed.settings ?? {}) };

  if (!parsed.settings) {
    settings.optimizer = {
      enabled: Boolean(input.optimizationUsed),
      runs: Number.isFinite(input.optimizationRuns) ? input.optimizationRuns : 200
    };
    const evmVersion = (input.evmVersion ?? "").trim();
    if (evmVersion && !/^default$/i.test(evmVersion)) settings.evmVersion = evmVersion;
  }

  if (input.library?.trim() && !(settings.libraries && typeof settings.libraries === "object")) {
    throw new Error("Explorer metadata reports linked libraries but does not provide an unambiguous Standard JSON library mapping.");
  }

  settings.outputSelection = {
    "*": {
      "*": ["evm.deployedBytecode.object"]
    }
  };
  settings.metadata = {
    ...((settings.metadata && typeof settings.metadata === "object") ? settings.metadata as Record<string, unknown> : {})
  };

  const standard: StandardJsonInput = {
    language: "Solidity",
    sources: parsed.sources,
    settings
  };
  const serialized = JSON.stringify(standard);
  if (Buffer.byteLength(serialized) > MAX_INPUT_BYTES) {
    throw new Error(`Solidity Standard JSON input exceeds ${MAX_INPUT_BYTES} bytes.`);
  }
  return serialized;
}

function compilerErrors(payload: unknown) {
  if (!payload || typeof payload !== "object") return [];
  const errors = (payload as { errors?: Array<{ severity?: string; formattedMessage?: string; message?: string }> }).errors;
  if (!Array.isArray(errors)) return [];
  return errors
    .filter(item => item.severity === "error")
    .map(item => (item.formattedMessage ?? item.message ?? "solc compilation error").slice(0, 1_000));
}

function selectRuntime(payload: unknown, requestedContractName?: string) {
  if (!payload || typeof payload !== "object") return undefined;
  const contracts = (payload as {
    contracts?: Record<string, Record<string, { evm?: { deployedBytecode?: { object?: string } } }>>;
  }).contracts;
  if (!contracts || typeof contracts !== "object") return undefined;

  const candidates: Array<{ name: string; runtime: string }> = [];
  for (const fileContracts of Object.values(contracts)) {
    if (!fileContracts || typeof fileContracts !== "object") continue;
    for (const [name, artifact] of Object.entries(fileContracts)) {
      const runtime = artifact?.evm?.deployedBytecode?.object;
      if (typeof runtime === "string" && runtime.length > 0 && HEX_RUNTIME.test(runtime)) {
        candidates.push({ name, runtime: "0x" + runtime.toLowerCase() });
      }
    }
  }

  if (requestedContractName) {
    const exact = candidates.filter(candidate => candidate.name === requestedContractName);
    if (exact.length === 1) return exact[0];
  }
  return candidates.length === 1 ? candidates[0] : undefined;
}

export async function compileVerifiedRuntimeExact(input: {
  sourceText?: string;
  contractName?: string;
  compilerVersion?: string;
  optimizationUsed?: boolean;
  optimizationRuns?: number;
  evmVersion?: string;
  library?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<LocalCompilationResult> {
  const diagnostics: string[] = [];
  if (!input.sourceText) {
    return { available: false, exactCompiler: false, diagnostics: ["Verified source text is unavailable for local recompilation."] };
  }
  if (!input.compilerVersion) {
    return { available: false, exactCompiler: false, diagnostics: ["Explorer metadata did not provide an exact compiler build."] };
  }

  let version;
  try {
    version = await runSolc(["--version"], undefined, {
      timeoutMs: Math.max(1_000, Math.min(input.timeoutMs ?? 10_000, 30_000)),
      maxOutputBytes: 16_384,
      signal: input.signal
    });
  } catch (error) {
    return {
      available: false,
      exactCompiler: false,
      diagnostics: [error instanceof Error ? `solc unavailable: ${error.message}` : "solc unavailable"]
    };
  }

  const versionText = [version.stdout, version.stderr].filter(Boolean).join("\n");
  if (version.code !== 0 || version.truncated) {
    return {
      available: false,
      exactCompiler: false,
      diagnostics: ["solc version probe did not complete cleanly."]
    };
  }
  const exactCompiler = compilerBuildMatches(input.compilerVersion, versionText);
  const compilerVersion = versionText.match(/Version:\s*([^\s]+)/i)?.[1];
  if (!exactCompiler) {
    return {
      available: true,
      exactCompiler: false,
      compilerVersion,
      diagnostics: [
        `Local solc build ${compilerVersion ?? "unknown"} does not exactly match explorer compiler ${normalizeExplorerCompiler(input.compilerVersion)}.`
      ]
    };
  }

  let standardInput: string;
  try {
    standardInput = buildStandardInput({
      sourceText: input.sourceText,
      optimizationUsed: input.optimizationUsed,
      optimizationRuns: input.optimizationRuns,
      evmVersion: input.evmVersion,
      library: input.library
    });
  } catch (error) {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: [error instanceof Error ? error.message : "Unable to reconstruct Solidity compiler input."]
    };
  }

  let compiled;
  try {
    compiled = await runSolc(["--standard-json"], standardInput, {
      timeoutMs: Math.max(2_000, Math.min(input.timeoutMs ?? 60_000, 180_000)),
      maxOutputBytes: MAX_OUTPUT_BYTES,
      signal: input.signal
    });
  } catch (error) {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: [error instanceof Error ? error.message : "solc compilation failed to start."]
    };
  }
  if (compiled.code !== 0 || compiled.truncated) {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: [
        compiled.truncated ? "solc output exceeded the attestation limit." : `solc exited with code ${compiled.code ?? "unknown"}.`,
        compiled.stderr.slice(0, 2_000)
      ].filter(Boolean)
    };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(compiled.stdout);
  } catch {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: ["solc returned non-JSON Standard JSON output."]
    };
  }

  const errors = compilerErrors(payload);
  if (errors.length) {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: errors.slice(0, 10)
    };
  }

  const selected = selectRuntime(payload, input.contractName);
  if (!selected) {
    return {
      available: true,
      exactCompiler: true,
      compilerVersion,
      diagnostics: [
        input.contractName
          ? `Compiled output did not contain a unique hex runtime for contract ${input.contractName}.`
          : "Compiled output contained zero or multiple runtime candidates; contract identity is ambiguous."
      ]
    };
  }

  return {
    available: true,
    exactCompiler: true,
    compilerVersion,
    expectedRuntime: selected.runtime,
    contractName: selected.name,
    diagnostics
  };
}
