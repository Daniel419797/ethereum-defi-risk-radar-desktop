import type {
  BuildLanguage
} from "./deterministicBuild.js";
import {
  detectBuildLanguage
} from "./deterministicBuild.js";

export type SourceLanguageProfile = {
  language: BuildLanguage;
  functions: Array<{
    name: string;
    visibility?: string;
    mutability?: string;
  }>;
  storageVariables: Array<{
    name: string;
    typeHint: string;
  }>;
  executionSurfaces: Array<{
    kind:
      | "CALL"
      | "DELEGATECALL"
      | "CREATE"
      | "CREATE2"
      | "SLOAD"
      | "SSTORE"
      | "RAW_CALL";
    evidence: string;
  }>;
  selectorHints: string[];
  limitations: string[];
};

function solidityLikeProfile(
  source: string,
  language: BuildLanguage
): SourceLanguageProfile {
  const functions = [
    ...source.matchAll(
      /\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*([^{;]*)/g
    )
  ].slice(0, 2_000).map(match => {
    const suffix = match[2] || "";
    const visibility =
      /\bexternal\b/.test(suffix)
        ? "external"
        : /\bpublic\b/.test(suffix)
          ? "public"
          : /\binternal\b/.test(suffix)
            ? "internal"
            : /\bprivate\b/.test(suffix)
              ? "private"
              : undefined;
    const mutability =
      /\bview\b/.test(suffix)
        ? "view"
        : /\bpure\b/.test(suffix)
          ? "pure"
          : /\bpayable\b/.test(suffix)
            ? "payable"
            : undefined;
    return {
      name: match[1],
      visibility,
      mutability
    };
  });
  return {
    language,
    functions,
    storageVariables: [],
    executionSurfaces: [
      ...[...source.matchAll(/\bdelegatecall\s*\(/gi)]
        .slice(0, 100)
        .map(match => ({
          kind: "DELEGATECALL" as const,
          evidence: match[0]
        })),
      ...[...source.matchAll(/\bcreate2?\s*\(/gi)]
        .slice(0, 100)
        .map(match => ({
          kind: /create2/i.test(match[0])
            ? "CREATE2" as const
            : "CREATE" as const,
          evidence: match[0]
        }))
    ],
    selectorHints: [],
    limitations: [
      "Language profile is lightweight metadata; Solidity source security findings continue to come from the native source analyzer."
    ]
  };
}

function vyperProfile(
  source: string
): SourceLanguageProfile {
  const lines = source.split(/\r?\n/);
  const functions: SourceLanguageProfile["functions"] =
    [];
  const storageVariables: SourceLanguageProfile["storageVariables"] =
    [];
  const executionSurfaces: SourceLanguageProfile["executionSurfaces"] =
    [];
  let decorators: string[] = [];

  for (const raw of lines.slice(0, 100_000)) {
    const line = raw.trim();
    if (line.startsWith("@")) {
      decorators.push(line);
      continue;
    }
    const fn = line.match(
      /^def\s+([A-Za-z_]\w*)\s*\(/
    );
    if (fn) {
      functions.push({
        name: fn[1],
        visibility:
          decorators.some(value =>
            /@external/.test(value)
          )
            ? "external"
            : decorators.some(value =>
                /@internal/.test(value)
              )
              ? "internal"
              : undefined,
        mutability:
          decorators.some(value =>
            /@view/.test(value)
          )
            ? "view"
            : decorators.some(value =>
                /@pure/.test(value)
              )
              ? "pure"
              : decorators.some(value =>
                  /@payable/.test(value)
                )
                ? "payable"
                : undefined
      });
      decorators = [];
      continue;
    }
    decorators = [];

    const storage = line.match(
      /^([A-Za-z_]\w*)\s*:\s*([^=#]+)$/
    );
    if (
      storage &&
      !line.startsWith("event ") &&
      !line.startsWith("struct ")
    ) {
      storageVariables.push({
        name: storage[1],
        typeHint: storage[2].trim()
      });
    }

    if (/\braw_call\s*\(/.test(line)) {
      executionSurfaces.push({
        kind: /is_delegate_call\s*=\s*True/.test(
          line
        )
          ? "DELEGATECALL"
          : "RAW_CALL",
        evidence: line.slice(0, 300)
      });
    }
    if (/\bcreate_.*_to\b/.test(line)) {
      executionSurfaces.push({
        kind: "CREATE",
        evidence: line.slice(0, 300)
      });
    }
  }

  return {
    language: "VYPER",
    functions: functions.slice(0, 2_000),
    storageVariables:
      storageVariables.slice(0, 2_000),
    executionSurfaces:
      executionSurfaces.slice(0, 500),
    selectorHints: [],
    limitations: [
      "Vyper profile extracts declarations and raw-call surfaces but does not claim Solidity AST semantics.",
      "Deployed bytecode analysis remains the language-independent structural backstop."
    ]
  };
}

function yulProfile(
  source: string
): SourceLanguageProfile {
  const functions = [
    ...source.matchAll(
      /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g
    )
  ].slice(0, 2_000).map(match => ({
    name: match[1],
    visibility: undefined,
    mutability: undefined
  }));
  const surfaces: SourceLanguageProfile["executionSurfaces"] =
    [];
  for (const [pattern, kind] of [
    [/\bdelegatecall\s*\(/gi, "DELEGATECALL"],
    [/\bstaticcall\s*\(/gi, "CALL"],
    [/\bcall\s*\(/gi, "CALL"],
    [/\bcreate2\s*\(/gi, "CREATE2"],
    [/\bcreate\s*\(/gi, "CREATE"],
    [/\bsstore\s*\(/gi, "SSTORE"],
    [/\bsload\s*\(/gi, "SLOAD"]
  ] as Array<[RegExp, SourceLanguageProfile["executionSurfaces"][number]["kind"]]>) {
    for (const match of [
      ...source.matchAll(pattern)
    ].slice(0, 100)) {
      surfaces.push({
        kind,
        evidence: match[0]
      });
    }
  }
  return {
    language: "YUL",
    functions,
    storageVariables: [],
    executionSurfaces: surfaces,
    selectorHints: [],
    limitations: [
      "Yul has no Solidity-style storage declarations; slot meaning requires data-flow or compiler layout context.",
      "Runtime bytecode analysis remains authoritative for deployed control flow."
    ]
  };
}

function huffProfile(
  source: string
): SourceLanguageProfile {
  const functions = [
    ...source.matchAll(
      /#define\s+(?:macro|fn|function)\s+([A-Za-z_$][\w$]*)/gi
    )
  ].slice(0, 2_000).map(match => ({
    name: match[1],
    visibility: undefined,
    mutability: undefined
  }));
  const selectorHints = [
    ...source.matchAll(
      /__FUNC_SIG\s*\(\s*["']?([^)"']+)/g
    )
  ].slice(0, 2_000).map(match => match[1]);
  const surfaces: SourceLanguageProfile["executionSurfaces"] =
    [];
  for (const [pattern, kind] of [
    [/\bdelegatecall\b/gi, "DELEGATECALL"],
    [/\bstaticcall\b/gi, "CALL"],
    [/\bcall\b/gi, "CALL"],
    [/\bcreate2\b/gi, "CREATE2"],
    [/\bcreate\b/gi, "CREATE"],
    [/\bsstore\b/gi, "SSTORE"],
    [/\bsload\b/gi, "SLOAD"]
  ] as Array<[RegExp, SourceLanguageProfile["executionSurfaces"][number]["kind"]]>) {
    for (const match of [
      ...source.matchAll(pattern)
    ].slice(0, 100)) {
      surfaces.push({
        kind,
        evidence: match[0]
      });
    }
  }

  return {
    language: "HUFF",
    functions,
    storageVariables: [],
    executionSurfaces: surfaces,
    selectorHints,
    limitations: [
      "Huff macros are assembly-level and require bytecode/control-flow analysis for security semantics.",
      "Selector hints are source declarations, not proof of deployed dispatch behavior."
    ]
  };
}

export function profileVerifiedSourceLanguage(opts: {
  source: string;
  compilerVersion?: string;
}) {
  const language = detectBuildLanguage(
    opts.source,
    opts.compilerVersion || ""
  );
  if (language === "VYPER") {
    return vyperProfile(opts.source);
  }
  if (language === "YUL") {
    return yulProfile(opts.source);
  }
  if (language === "HUFF") {
    return huffProfile(opts.source);
  }
  return solidityLikeProfile(
    opts.source,
    language
  );
}
