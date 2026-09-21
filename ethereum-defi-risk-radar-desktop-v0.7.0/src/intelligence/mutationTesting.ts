import { createHash } from "node:crypto";
import { inspectVerifiedSource } from "../sourceAnalyzer.js";

export type MutationKind =
  | "REMOVE_ONLY_OWNER"
  | "REMOVE_NON_REENTRANT"
  | "REPLACE_MSG_SENDER_WITH_TX_ORIGIN"
  | "REMOVE_ORACLE_FRESHNESS_CHECK"
  | "MOVE_STATE_WRITE_AFTER_CALL"
  | "INVERT_BOUNDS_CHECK"
  | "REMOVE_DEADLINE_CHECK";

export type MutationSpec = {
  id: string;
  kind: MutationKind;
  expectedFindingKinds: string[];
  description: string;
};

export type MutationCase = {
  id: string;
  mutation: MutationSpec;
  source: string;
  changed: boolean;
  changeSummary: string;
};

export type MutationEvaluation = {
  id: string;
  mutationKind: MutationKind;
  detected: boolean;
  expectedFindingKinds: string[];
  observedFindingKinds: string[];
  sourceFindingKinds: string[];
  durationMs: number;
};

export type MutationSuiteResult = {
  generatedAt: string;
  total: number;
  detected: number;
  missed: number;
  mutationScore: number;
  results: MutationEvaluation[];
};

const MUTATIONS: MutationSpec[] = [
  {
    id: "remove-only-owner",
    kind: "REMOVE_ONLY_OWNER",
    expectedFindingKinds: ["authorization"],
    description:
      "Removes a common onlyOwner modifier from one function declaration."
  },
  {
    id: "remove-non-reentrant",
    kind: "REMOVE_NON_REENTRANT",
    expectedFindingKinds: ["reentrancy"],
    description:
      "Removes a nonReentrant modifier from one function declaration."
  },
  {
    id: "tx-origin-auth",
    kind: "REPLACE_MSG_SENDER_WITH_TX_ORIGIN",
    expectedFindingKinds: ["authorization"],
    description:
      "Replaces a msg.sender authorization operand with tx.origin."
  },
  {
    id: "remove-oracle-freshness",
    kind: "REMOVE_ORACLE_FRESHNESS_CHECK",
    expectedFindingKinds: ["oracle_risk"],
    description:
      "Deletes one require/check containing updatedAt, answeredInRound, heartbeat or staleness language."
  },
  {
    id: "move-state-write-after-call",
    kind: "MOVE_STATE_WRITE_AFTER_CALL",
    expectedFindingKinds: ["reentrancy", "cross_contract_calls"],
    description:
      "Moves one simple assignment from immediately before a low-level call to immediately after it."
  },
  {
    id: "invert-bounds-check",
    kind: "INVERT_BOUNDS_CHECK",
    expectedFindingKinds: ["arithmetic_precision", "authorization"],
    description:
      "Inverts one simple require inequality."
  },
  {
    id: "remove-deadline-check",
    kind: "REMOVE_DEADLINE_CHECK",
    expectedFindingKinds: ["mev_ordering"],
    description:
      "Deletes one require/check containing deadline or expiry."
  }
];

function replaceOnce(
  source: string,
  pattern: RegExp,
  replacement: string | ((substring: string, ...args: string[]) => string)
) {
  const match = pattern.exec(source);
  if (!match || match.index === undefined) {
    return { source, changed: false, summary: "pattern not present" };
  }
  const before = source.slice(0, match.index);
  const after = source.slice(match.index + match[0].length);
  const value =
    typeof replacement === "string"
      ? replacement
      : replacement(...match);
  return {
    source: before + value + after,
    changed: true,
    summary:
      "replaced source range " +
      match.index +
      "-" +
      (match.index + match[0].length)
  };
}

function applyMutation(
  source: string,
  mutation: MutationSpec
) {
  if (mutation.kind === "REMOVE_ONLY_OWNER") {
    return replaceOnce(
      source,
      /\bonlyOwner\b/,
      ""
    );
  }
  if (mutation.kind === "REMOVE_NON_REENTRANT") {
    return replaceOnce(
      source,
      /\bnonReentrant\b/,
      ""
    );
  }
  if (
    mutation.kind ===
    "REPLACE_MSG_SENDER_WITH_TX_ORIGIN"
  ) {
    return replaceOnce(
      source,
      /\bmsg\.sender\b/,
      "tx.origin"
    );
  }
  if (
    mutation.kind ===
    "REMOVE_ORACLE_FRESHNESS_CHECK"
  ) {
    return replaceOnce(
      source,
      /(?:require|assert)\s*\([^;\n]*(?:updatedAt|answeredInRound|heartbeat|stale|staleness)[^;\n]*\)\s*;/i,
      ""
    );
  }
  if (
    mutation.kind ===
    "REMOVE_DEADLINE_CHECK"
  ) {
    return replaceOnce(
      source,
      /(?:require|assert)\s*\([^;\n]*(?:deadline|expiry|expiration)[^;\n]*\)\s*;/i,
      ""
    );
  }
  if (
    mutation.kind ===
    "INVERT_BOUNDS_CHECK"
  ) {
    return replaceOnce(
      source,
      /require\s*\(\s*([A-Za-z_$][\w$.\[\]]*)\s*(<=|>=|<|>)\s*([A-Za-z_$0-9][\w$.\[\]]*)\s*(?:,\s*[^)]*)?\)\s*;/,
      (_whole, left, operator, right) => {
        const inverted =
          operator === "<="
            ? ">"
            : operator === ">="
              ? "<"
              : operator === "<"
                ? ">="
                : "<=";
        return (
          "require(" +
          left +
          " " +
          inverted +
          " " +
          right +
          ");"
        );
      }
    );
  }
  if (
    mutation.kind ===
    "MOVE_STATE_WRITE_AFTER_CALL"
  ) {
    const pattern =
      /([A-Za-z_$][\w$.\[\]]*\s*=\s*[^;\n]+;\s*)((?:\([^)]+\)\s*=\s*)?[A-Za-z_$][\w$.\[\]]*\.call(?:\{[^}]*\})?\s*\([^;]*\)\s*;)/;
    const match = pattern.exec(source);
    if (!match || match.index === undefined) {
      return {
        source,
        changed: false,
        summary: "assignment/call adjacency not present"
      };
    }
    const replacement =
      match[2] + "\n" + match[1];
    return {
      source:
        source.slice(0, match.index) +
        replacement +
        source.slice(
          match.index + match[0].length
        ),
      changed: true,
      summary:
        "moved assignment after low-level call"
    };
  }
  return {
    source,
    changed: false,
    summary: "unsupported mutation"
  };
}

export function generateMutations(
  source: string
): MutationCase[] {
  const rows: MutationCase[] = [];
  for (const mutation of MUTATIONS) {
    const applied = applyMutation(
      source,
      mutation
    );
    if (!applied.changed) continue;
    rows.push({
      id:
        "mut-" +
        createHash("sha256")
          .update(
            mutation.id +
              "|" +
              applied.source
          )
          .digest("hex")
          .slice(0, 16),
      mutation,
      source: applied.source,
      changed: true,
      changeSummary:
        applied.summary
    });
  }
  return rows;
}

export function evaluateMutations(
  cases: MutationCase[],
  opts: {
    maxBytes?: number;
    maxFindings?: number;
  } = {}
): MutationSuiteResult {
  const results: MutationEvaluation[] = [];

  for (const item of cases) {
    const started = Date.now();
    const inspection =
      inspectVerifiedSource(
        item.source,
        {
          maxBytes:
            opts.maxBytes ??
            5_000_000,
          maxFindings:
            opts.maxFindings ??
            500
        }
      );
    const observedFindingKinds = [
      ...new Set(
        inspection.advancedAnalysis
          .findings.map(
            finding =>
              finding.kind
          )
      )
    ];
    const sourceFindingKinds = [
      ...new Set(
        inspection.findings.map(
          finding =>
            finding.kind
        )
      )
    ];
    const detected =
      item.mutation.expectedFindingKinds.some(
        expected =>
          observedFindingKinds.includes(
            expected
          )
      ) ||
      (
        item.mutation.kind ===
          "REPLACE_MSG_SENDER_WITH_TX_ORIGIN" &&
        sourceFindingKinds.includes(
          "tx_origin"
        )
      );

    results.push({
      id: item.id,
      mutationKind:
        item.mutation.kind,
      detected,
      expectedFindingKinds:
        item.mutation
          .expectedFindingKinds,
      observedFindingKinds,
      sourceFindingKinds,
      durationMs:
        Date.now() - started
    });
  }

  const detected = results.filter(
    result => result.detected
  ).length;
  return {
    generatedAt:
      new Date().toISOString(),
    total: results.length,
    detected,
    missed:
      results.length - detected,
    mutationScore:
      results.length
        ? detected / results.length
        : 0,
    results
  };
}

export function builtInMutationSpecs() {
  return [...MUTATIONS];
}
