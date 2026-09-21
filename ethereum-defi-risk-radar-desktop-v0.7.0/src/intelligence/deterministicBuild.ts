import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { runBoundedProcess } from "../analysis/processRunner.js";
import {
  attestRuntimeBytecode
} from "./bytecode.js";
import type { BytecodeAttestation } from "./model.js";

export type BuildLanguage =
  | "SOLIDITY"
  | "VYPER"
  | "YUL"
  | "HUFF"
  | "UNKNOWN";

export type DeterministicBuildRecipe = {
  language: BuildLanguage;
  compilerVersion: string;
  compilerSemanticVersion?: string;
  optimizerEnabled?: boolean;
  optimizerRuns?: number;
  evmVersion?: string;
  libraries?: Record<string, string>;
  remappings?: string[];
  sourceCount: number;
  standardJson: boolean;
  containerImage?: string;
};

export type BuildReproductionResult = {
  recipe: DeterministicBuildRecipe;
  strategy:
    | "LOCAL_EXACT"
    | "CACHED_CONTAINER_EXACT"
    | "UNAVAILABLE";
  attestation: BytecodeAttestation;
  diagnostics: string[];
};

type SolcOutput = {
  errors?: Array<{
    severity?: string;
    formattedMessage?: string;
    message?: string;
  }>;
  contracts?: Record<
    string,
    Record<
      string,
      { evm?: { deployedBytecode?: { object?: string } } }
    >
  >;
};

function semanticVersion(raw: string) {
  const match = raw.match(/(\d+\.\d+\.\d+)/);
  return match?.[1];
}

export function detectBuildLanguage(
  source: string,
  compilerVersion = ""
): BuildLanguage {
  const compiler = compilerVersion.toLowerCase();
  if (compiler.includes("vyper")) return "VYPER";
  if (compiler.includes("huff")) return "HUFF";
  if (
    /\bobject\s+"[^"]+"\s*\{[\s\S]*\bcode\s*\{/i.test(source) ||
    /\b(?:let|switch)\b[\s\S]*\bmstore\s*\(/i.test(source)
  ) {
    return "YUL";
  }
  if (
    /\bpragma\s+solidity\b/i.test(source) ||
    /\b(contract|library|interface)\s+[A-Za-z_$]/.test(source)
  ) {
    return "SOLIDITY";
  }
  if (
    /@external\b/.test(source) ||
    /\bdef\s+[A-Za-z_]\w*\s*\(/.test(source)
  ) {
    return "VYPER";
  }
  if (
    /#define\s+(macro|function|constant)\b/i.test(source)
  ) {
    return "HUFF";
  }
  return "UNKNOWN";
}

function parseEtherscanStandardJson(
  rawSource: string
): {
  language?: string;
  sources?: Record<string, unknown>;
  settings?: Record<string, unknown>;
} | undefined {
  const source = rawSource.trim();
  const attempts =
    source.startsWith("{{") && source.endsWith("}}")
      ? [source.slice(1, -1), source]
      : [source];

  for (const candidate of attempts) {
    if (!candidate.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(candidate);
      if (
        parsed &&
        typeof parsed === "object" &&
        parsed.sources &&
        typeof parsed.sources === "object"
      ) {
        return parsed;
      }
    } catch {
      // Flattened source falls through to a single-source build.
    }
  }
  return undefined;
}

export function buildRecipeFromVerifiedMetadata(opts: {
  rawSource: string;
  compilerVersion: string;
  optimizationUsed?: boolean;
  runs?: number;
  evmVersion?: string;
  libraries?: Record<string, string>;
}): DeterministicBuildRecipe {
  const parsed = parseEtherscanStandardJson(opts.rawSource);
  const language = detectBuildLanguage(
    opts.rawSource,
    opts.compilerVersion
  );
  const version = semanticVersion(opts.compilerVersion);
  const settings =
    parsed?.settings &&
    typeof parsed.settings === "object"
      ? (parsed.settings as Record<string, unknown>)
      : {};
  const remappings = Array.isArray(settings.remappings)
    ? settings.remappings
        .filter(value => typeof value === "string")
        .slice(0, 2_000)
    : undefined;
  const optimizer =
    settings.optimizer &&
    typeof settings.optimizer === "object"
      ? (settings.optimizer as Record<string, unknown>)
      : undefined;

  return {
    language,
    compilerVersion: opts.compilerVersion,
    compilerSemanticVersion: version,
    optimizerEnabled:
      typeof optimizer?.enabled === "boolean"
        ? optimizer.enabled
        : opts.optimizationUsed,
    optimizerRuns:
      typeof optimizer?.runs === "number"
        ? optimizer.runs
        : opts.runs,
    evmVersion:
      typeof settings.evmVersion === "string"
        ? settings.evmVersion
        : opts.evmVersion,
    libraries: opts.libraries,
    remappings,
    sourceCount: parsed?.sources
      ? Object.keys(parsed.sources).length
      : 1,
    standardJson:
      language === "SOLIDITY" ||
      language === "YUL",
    containerImage:
      language === "SOLIDITY" || language === "YUL"
        ? version
          ? "ethereum/solc:" + version
          : undefined
        : language === "VYPER"
          ? version
            ? "vyperlang/vyper:" + version
            : undefined
          : undefined
  };
}

function executableFor(language: BuildLanguage) {
  if (language === "SOLIDITY" || language === "YUL") {
    return "solc";
  }
  if (language === "VYPER") return "vyper";
  if (language === "HUFF") return "huffc";
  return undefined;
}

async function probeVersion(
  executable: string,
  language: BuildLanguage
) {
  const args =
    language === "SOLIDITY" || language === "YUL"
      ? ["--version"]
      : ["--version"];
  const result = await runBoundedProcess({
    executable,
    args,
    cwd: os.tmpdir(),
    timeoutMs: 10_000,
    maxOutputBytes: 1_000_000
  });
  return (result.stdout + "\n" + result.stderr).trim();
}

function exactCompilerMatch(
  output: string,
  expected: string
) {
  const semantic = semanticVersion(expected);
  if (!semantic) return false;
  return output.includes(semantic);
}

function solidityInput(
  rawSource: string,
  recipe: DeterministicBuildRecipe
) {
  const parsed = parseEtherscanStandardJson(rawSource);
  if (parsed) {
    return {
      language:
        parsed.language ||
        (recipe.language === "YUL" ? "Yul" : "Solidity"),
      sources: parsed.sources,
      settings: {
        ...(parsed.settings || {}),
        outputSelection: {
          "*": {
            "*": ["evm.deployedBytecode.object"]
          }
        }
      }
    };
  }

  return {
    language:
      recipe.language === "YUL" ? "Yul" : "Solidity",
    sources: {
      "Contract.sol": { content: rawSource }
    },
    settings: {
      optimizer: {
        enabled: Boolean(recipe.optimizerEnabled),
        runs: Math.max(
          0,
          recipe.optimizerRuns ?? 200
        )
      },
      ...(recipe.evmVersion &&
      recipe.evmVersion !== "Default"
        ? { evmVersion: recipe.evmVersion }
        : {}),
      ...(recipe.remappings?.length
        ? { remappings: recipe.remappings }
        : {}),
      outputSelection: {
        "*": {
          "*": ["evm.deployedBytecode.object"]
        }
      }
    }
  };
}

async function runWithInput(opts: {
  executable: string;
  args: string[];
  input: string;
  cwd: string;
  timeoutMs: number;
  maxOutputBytes: number;
}) {
  return await new Promise<{
    stdout: string;
    stderr: string;
    exitCode: number | null;
  }>((resolve, reject) => {
    const child = spawn(opts.executable, opts.args, {
      cwd: opts.cwd,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        USERPROFILE: process.env.USERPROFILE
      }
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    const finish = (
      error?: Error,
      value?: {
        stdout: string;
        stderr: string;
        exitCode: number | null;
      }
    ) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value!);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(
        new Error(
          "Compiler process timed out after " +
            opts.timeoutMs +
            "ms."
        )
      );
    }, opts.timeoutMs);

    child.stdout.on("data", chunk => {
      const row = Buffer.from(chunk);
      stdoutBytes += row.length;
      if (stdoutBytes > opts.maxOutputBytes) {
        child.kill("SIGKILL");
        finish(
          new Error(
            "Compiler stdout exceeded its output budget."
          )
        );
        return;
      }
      stdout.push(row);
    });
    child.stderr.on("data", chunk => {
      const row = Buffer.from(chunk);
      stderrBytes += row.length;
      if (stderrBytes <= opts.maxOutputBytes) {
        stderr.push(row);
      }
    });
    child.on("error", error => finish(error));
    child.on("close", exitCode => {
      finish(undefined, {
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exitCode
      });
    });
    child.stdin.on("error", error => finish(error));
    child.stdin.end(opts.input);
  });
}

function compiledRuntime(
  output: SolcOutput,
  contractName: string
) {
  const exact: string[] = [];
  const all: string[] = [];
  for (const contracts of Object.values(
    output.contracts || {}
  )) {
    for (const [name, contract] of Object.entries(
      contracts
    )) {
      const object =
        contract.evm?.deployedBytecode?.object;
      if (
        !object ||
        !/^[a-fA-F0-9]+$/.test(object)
      ) {
        continue;
      }
      const value = "0x" + object;
      all.push(value);
      if (name === contractName) exact.push(value);
    }
  }
  if (exact.length === 1) return exact[0];
  if (all.length === 1) return all[0];
  throw new Error(
    "Compiled output did not identify one unambiguous runtime object."
  );
}

async function localSolidityCompile(opts: {
  executable: string;
  rawSource: string;
  recipe: DeterministicBuildRecipe;
  contractName: string;
}) {
  const result = await runWithInput({
    executable: opts.executable,
    args: ["--standard-json"],
    input: JSON.stringify(
      solidityInput(opts.rawSource, opts.recipe)
    ),
    cwd: os.tmpdir(),
    timeoutMs: 90_000,
    maxOutputBytes: 30_000_000
  });
  if (
    result.exitCode !== 0 &&
    !result.stdout.trim()
  ) {
    throw new Error(
      result.stderr.slice(0, 1_000) ||
        "Compiler exited unsuccessfully."
    );
  }
  const output = JSON.parse(
    result.stdout
  ) as SolcOutput;
  const errors = (output.errors || []).filter(
    item => item.severity === "error"
  );
  if (errors.length) {
    throw new Error(
      (
        errors[0].formattedMessage ||
        errors[0].message ||
        "Compiler error"
      ).slice(0, 2_000)
    );
  }
  return compiledRuntime(
    output,
    opts.contractName
  );
}

async function containerImageAvailable(
  image: string
) {
  try {
    const result = await runBoundedProcess({
      executable: "docker",
      args: ["image", "inspect", image],
      cwd: os.tmpdir(),
      timeoutMs: 15_000,
      maxOutputBytes: 1_000_000
    });
    return result.state === "complete" &&
      result.exitCode === 0;
  } catch {
    return false;
  }
}

export async function prepareExactCompilerImage(opts: {
  recipe: DeterministicBuildRecipe;
  allowNetworkFetch: boolean;
}) {
  const image = opts.recipe.containerImage;
  if (!image) {
    throw new Error(
      "No deterministic compiler container is configured for " +
        opts.recipe.language +
        "."
    );
  }
  if (await containerImageAvailable(image)) {
    return { image, pulled: false };
  }
  if (!opts.allowNetworkFetch) {
    throw new Error(
      "Exact compiler image is not cached. Explicit allowNetworkFetch=true is required before downloading compiler images."
    );
  }
  const result = await runBoundedProcess({
    executable: "docker",
    args: ["pull", image],
    cwd: os.tmpdir(),
    timeoutMs: 15 * 60_000,
    maxOutputBytes: 10_000_000
  });
  if (
    result.state !== "complete" ||
    result.exitCode !== 0
  ) {
    throw new Error(
      "Unable to prepare exact compiler image: " +
        result.stderr.slice(0, 1_000)
    );
  }
  return { image, pulled: true };
}

async function containerSolidityCompile(opts: {
  image: string;
  rawSource: string;
  recipe: DeterministicBuildRecipe;
  contractName: string;
}) {
  const result = await runWithInput({
    executable: "docker",
    args: [
      "run",
      "--rm",
      "--network=none",
      "--read-only",
      "--memory=1g",
      "--cpus=2",
      "-i",
      opts.image,
      "--standard-json"
    ],
    input: JSON.stringify(
      solidityInput(opts.rawSource, opts.recipe)
    ),
    cwd: path.resolve(os.tmpdir()),
    timeoutMs: 120_000,
    maxOutputBytes: 30_000_000
  });
  if (
    result.exitCode !== 0 &&
    !result.stdout.trim()
  ) {
    throw new Error(
      result.stderr.slice(0, 1_000) ||
        "Containerized compiler failed."
    );
  }
  const output = JSON.parse(
    result.stdout
  ) as SolcOutput;
  const errors = (output.errors || []).filter(
    item => item.severity === "error"
  );
  if (errors.length) {
    throw new Error(
      (
        errors[0].formattedMessage ||
        errors[0].message ||
        "Compiler error"
      ).slice(0, 2_000)
    );
  }
  return compiledRuntime(
    output,
    opts.contractName
  );
}

export async function reproduceVerifiedBuild(opts: {
  rawSource: string;
  contractName: string;
  compilerVersion: string;
  observedRuntimeBytecode: string;
  optimizationUsed?: boolean;
  runs?: number;
  evmVersion?: string;
  libraries?: Record<string, string>;
  allowCachedContainer?: boolean;
}): Promise<BuildReproductionResult> {
  const recipe = buildRecipeFromVerifiedMetadata(
    opts
  );
  const diagnostics: string[] = [];
  const executable = executableFor(
    recipe.language
  );

  if (
    executable &&
    (recipe.language === "SOLIDITY" ||
      recipe.language === "YUL")
  ) {
    try {
      const version = await probeVersion(
        executable,
        recipe.language
      );
      if (
        exactCompilerMatch(
          version,
          recipe.compilerVersion
        )
      ) {
        const compiledRuntime =
          await localSolidityCompile({
            executable,
            rawSource: opts.rawSource,
            recipe,
            contractName: opts.contractName
          });
        return {
          recipe,
          strategy: "LOCAL_EXACT",
          attestation: attestRuntimeBytecode({
            observedRuntimeBytecode:
              opts.observedRuntimeBytecode,
            compiledRuntimeBytecode:
              compiledRuntime,
            compilerVersion:
              opts.compilerVersion
          }),
          diagnostics
        };
      }
      diagnostics.push(
        "Local " +
          executable +
          " version did not match " +
          opts.compilerVersion +
          "."
      );
    } catch (error) {
      diagnostics.push(
        "Local compiler unavailable: " +
          (error instanceof Error
            ? error.message
            : String(error))
      );
    }
  }

  if (
    opts.allowCachedContainer !== false &&
    recipe.containerImage &&
    (recipe.language === "SOLIDITY" ||
      recipe.language === "YUL")
  ) {
    try {
      if (
        await containerImageAvailable(
          recipe.containerImage
        )
      ) {
        const compiledRuntime =
          await containerSolidityCompile({
            image: recipe.containerImage,
            rawSource: opts.rawSource,
            recipe,
            contractName: opts.contractName
          });
        return {
          recipe,
          strategy:
            "CACHED_CONTAINER_EXACT",
          attestation: attestRuntimeBytecode({
            observedRuntimeBytecode:
              opts.observedRuntimeBytecode,
            compiledRuntimeBytecode:
              compiledRuntime,
            compilerVersion:
              opts.compilerVersion
          }),
          diagnostics
        };
      }
      diagnostics.push(
        "Exact compiler container " +
          recipe.containerImage +
          " is not cached."
      );
    } catch (error) {
      diagnostics.push(
        "Cached compiler container failed: " +
          (error instanceof Error
            ? error.message
            : String(error))
      );
    }
  }

  return {
    recipe,
    strategy: "UNAVAILABLE",
    attestation: attestRuntimeBytecode({
      observedRuntimeBytecode:
        opts.observedRuntimeBytecode,
      compilerVersion:
        opts.compilerVersion,
      unavailableReason:
        "No exact local or cached isolated compiler was available. " +
        diagnostics.join(" ")
    }),
    diagnostics
  };
}
