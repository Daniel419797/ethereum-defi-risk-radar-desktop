import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { attestRuntimeBytecode } from "./bytecode.js";
import type { BytecodeAttestation } from "./model.js";

const execFileAsync = promisify(execFile);

type SolcOutput = {
  errors?: Array<{
    severity?: string;
    formattedMessage?: string;
    message?: string;
  }>;
  contracts?: Record<
    string,
    Record<string, { evm?: { deployedBytecode?: { object?: string } } }>
  >;
};

function parseSourceInput(
  rawSource: string,
  opts: { optimizerEnabled: boolean; runs: number; evmVersion?: string }
) {
  const source = rawSource.trim();
  const attempts =
    source.startsWith("{{") && source.endsWith("}}")
      ? [source.slice(1, -1), source]
      : [source];

  for (const attempt of attempts) {
    if (!attempt.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(attempt) as {
        language?: string;
        sources?: Record<string, unknown>;
        settings?: Record<string, unknown>;
      };
      if (parsed.sources && typeof parsed.sources === "object") {
        return {
          language: parsed.language || "Solidity",
          sources: parsed.sources,
          settings: {
            ...(parsed.settings || {}),
            outputSelection: {
              "*": { "*": ["evm.deployedBytecode.object"] }
            }
          }
        };
      }
    } catch {
      // Ordinary Solidity source is handled below.
    }
  }

  return {
    language: "Solidity",
    sources: { "Contract.sol": { content: rawSource } },
    settings: {
      optimizer: {
        enabled: opts.optimizerEnabled,
        runs: opts.runs
      },
      ...(opts.evmVersion ? { evmVersion: opts.evmVersion } : {}),
      outputSelection: {
        "*": { "*": ["evm.deployedBytecode.object"] }
      }
    }
  };
}

function normalizeVersion(value: string) {
  return value.replace(/^v/, "").trim();
}

async function localSolcVersion(executable: string) {
  const { stdout } = await execFileAsync(executable, ["--version"], {
    timeout: 10_000,
    maxBuffer: 1_000_000
  });
  const match =
    stdout.match(/Version:\s*([^\s]+)/i) ||
    stdout.match(/(\d+\.\d+\.\d+\+commit\.[0-9a-f]+)/i);
  return match?.[1] || "";
}

function findCompiledRuntime(output: SolcOutput, contractName: string) {
  const exact: string[] = [];
  const fallback: string[] = [];

  for (const contracts of Object.values(output.contracts || {})) {
    for (const [name, contract] of Object.entries(contracts)) {
      const object = contract.evm?.deployedBytecode?.object;
      if (!object || !/^[a-fA-F0-9]+$/.test(object)) continue;
      const hex = "0x" + object;
      if (name === contractName) exact.push(hex);
      fallback.push(hex);
    }
  }

  if (exact.length === 1) return exact[0];
  if (exact.length > 1) {
    throw new Error("Multiple compiled contracts matched the verified contract name.");
  }
  if (fallback.length === 1) return fallback[0];
  throw new Error(
    "Unable to identify a unique deployed runtime bytecode object from solc output."
  );
}

export async function attestVerifiedSourceWithLocalSolc(opts: {
  rawSource: string;
  contractName: string;
  compilerVersion: string;
  observedRuntimeBytecode: string;
  optimizationUsed?: boolean;
  runs?: number;
  evmVersion?: string;
  executable?: string;
}): Promise<BytecodeAttestation> {
  const executable = opts.executable || "solc";
  let version = "";

  try {
    version = await localSolcVersion(executable);
  } catch (error) {
    return attestRuntimeBytecode({
      observedRuntimeBytecode: opts.observedRuntimeBytecode,
      compilerVersion: opts.compilerVersion,
      unavailableReason:
        "Local solc is unavailable: " +
        (error instanceof Error ? error.message : String(error))
    });
  }

  const expected = normalizeVersion(opts.compilerVersion);
  if (!version.includes(expected)) {
    return attestRuntimeBytecode({
      observedRuntimeBytecode: opts.observedRuntimeBytecode,
      compilerVersion: opts.compilerVersion,
      unavailableReason:
        "Installed solc version " +
        version +
        " does not exactly match verified compiler " +
        expected +
        "."
    });
  }

  const input = parseSourceInput(opts.rawSource, {
    optimizerEnabled: Boolean(opts.optimizationUsed),
    runs: Math.max(0, opts.runs ?? 200),
    evmVersion:
      opts.evmVersion && opts.evmVersion !== "Default"
        ? opts.evmVersion
        : undefined
  });

  try {
    const { stdout } = await execFileAsync(executable, ["--standard-json"], {
      input: JSON.stringify(input),
      timeout: 60_000,
      maxBuffer: 20_000_000
    });
    const output = JSON.parse(stdout) as SolcOutput;
    const compileErrors = (output.errors || []).filter(
      item => item.severity === "error"
    );

    if (compileErrors.length) {
      return attestRuntimeBytecode({
        observedRuntimeBytecode: opts.observedRuntimeBytecode,
        compilerVersion: opts.compilerVersion,
        unavailableReason:
          "Exact-version solc compilation failed: " +
          (
            compileErrors[0].formattedMessage ||
            compileErrors[0].message ||
            "unknown compiler error"
          ).slice(0, 500)
      });
    }

    const compiledRuntimeBytecode = findCompiledRuntime(output, opts.contractName);
    return attestRuntimeBytecode({
      observedRuntimeBytecode: opts.observedRuntimeBytecode,
      compiledRuntimeBytecode,
      compilerVersion: opts.compilerVersion
    });
  } catch (error) {
    return attestRuntimeBytecode({
      observedRuntimeBytecode: opts.observedRuntimeBytecode,
      compilerVersion: opts.compilerVersion,
      unavailableReason:
        "Exact-version recompilation could not complete: " +
        (error instanceof Error ? error.message : String(error))
    });
  }
}
