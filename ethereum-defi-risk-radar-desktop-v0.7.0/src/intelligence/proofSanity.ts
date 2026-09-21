export type ProofSanityIssue = {
  severity: "INFO" | "WARNING" | "BLOCKING";
  code:
    | "NO_ASSERTION"
    | "UNCONDITIONAL_ASSERT"
    | "IMPOSSIBLE_ASSUME"
    | "EXCESSIVE_ASSUMPTIONS"
    | "METHOD_FILTER"
    | "RULE_FILTER"
    | "EXCLUDED_METHODS"
    | "HAVOC_HEAVY"
    | "UNRESOLVED_PLACEHOLDER"
    | "MISSING_COVERAGE"
    | "DYNAMIC_CREATION_UNMODELED";
  message: string;
  evidence?: string;
};

export type ProofSanityReport = {
  tool: "HALMOS" | "CERTORA" | "KONTROL" | "FOUNDRY";
  passed: boolean;
  issues: ProofSanityIssue[];
  assumptions: string[];
  conclusion:
    | "SPEC_SANITY_ACCEPTABLE"
    | "SPEC_SANITY_REVIEW_REQUIRED"
    | "SPEC_SANITY_BLOCKING";
};

function countMatches(text: string, pattern: RegExp) {
  return [...text.matchAll(pattern)].length;
}

export function checkProofSanity(opts: {
  tool: ProofSanityReport["tool"];
  specification: string;
  configText?: string;
}) {
  const text = opts.specification;
  const config = opts.configText || "";
  const issues: ProofSanityIssue[] = [];
  const assumptions: string[] = [];

  const assertCount = countMatches(
    text,
    /\b(?:assert|assertEq|assertTrue|assertFalse)\s*\(/g
  );
  if (assertCount === 0) {
    issues.push({
      severity: "BLOCKING",
      code: "NO_ASSERTION",
      message:
        "No assertion/property obligation was detected. A successful tool exit cannot be treated as a proof."
    });
  }

  for (const match of text.matchAll(
    /\bassert(?:True)?\s*\(\s*true\s*\)/g
  )) {
    issues.push({
      severity: "BLOCKING",
      code: "UNCONDITIONAL_ASSERT",
      message:
        "An unconditional true assertion is vacuous.",
      evidence: match[0]
    });
  }

  for (const match of text.matchAll(
    /\b(?:vm\.)?assume\s*\(\s*false\s*\)|\brequire\s+false\b/g
  )) {
    issues.push({
      severity: "BLOCKING",
      code: "IMPOSSIBLE_ASSUME",
      message:
        "An impossible assumption eliminates all meaningful execution paths.",
      evidence: match[0]
    });
  }

  const assumeCount =
    countMatches(
      text,
      /\b(?:vm\.)?assume\s*\(/g
    ) +
    countMatches(
      text,
      /\brequire\b/g
    );
  if (
    assumeCount > Math.max(8, assertCount * 5)
  ) {
    issues.push({
      severity: "WARNING",
      code: "EXCESSIVE_ASSUMPTIONS",
      message:
        "The specification has many more assumptions than obligations; review for over-constrained proofs."
    });
  }
  if (assumeCount) {
    assumptions.push(
      assumeCount +
        " explicit assume/require constraints detected."
    );
  }

  if (
    /\bfilter\b/i.test(config) ||
    /--method\b/.test(config)
  ) {
    issues.push({
      severity: "WARNING",
      code: "METHOD_FILTER",
      message:
        "Method filtering is active; the proof covers only the selected execution surface."
    });
  }
  if (
    /--rule\b/.test(config) ||
    /"rule"\s*:/.test(config)
  ) {
    issues.push({
      severity: "INFO",
      code: "RULE_FILTER",
      message:
        "Rule filtering is active; only a subset of specification rules is being evaluated."
    });
  }
  if (
    /exclude_method|--exclude-method|--exclude_method/.test(
      config
    )
  ) {
    issues.push({
      severity: "WARNING",
      code: "EXCLUDED_METHODS",
      message:
        "Methods are excluded from verification. Review whether excluded methods can mutate property-relevant state."
    });
  }

  if (
    /\bhavoc\b/i.test(text) &&
    countMatches(text, /\bhavoc\b/gi) > 3
  ) {
    issues.push({
      severity: "WARNING",
      code: "HAVOC_HEAVY",
      message:
        "The specification uses multiple havoc operations; overly broad abstraction can hide state relationships."
    });
  }

  if (
    /\{\{[^}]+\}\}|TODO_RISK_RADAR|RISK_RADAR_BIND_ME/.test(
      text
    )
  ) {
    issues.push({
      severity: "BLOCKING",
      code: "UNRESOLVED_PLACEHOLDER",
      message:
        "Generated property contains unresolved Risk Radar binding placeholders."
    });
  }

  if (
    opts.tool === "CERTORA" &&
    !/rule_sanity|coverage_info|project_sanity/.test(
      config
    )
  ) {
    issues.push({
      severity: "WARNING",
      code: "MISSING_COVERAGE",
      message:
        "Certora sanity/coverage options are not visible in the supplied configuration."
    });
  }

  if (
    opts.tool === "CERTORA" &&
    /\bcreate2?\b/i.test(text) &&
    !/dynamic_bound/.test(config)
  ) {
    issues.push({
      severity: "WARNING",
      code: "DYNAMIC_CREATION_UNMODELED",
      message:
        "Contract creation appears relevant but dynamic creation bounds are not configured."
    });
  }

  const blocking = issues.some(
    issue => issue.severity === "BLOCKING"
  );
  const warning = issues.some(
    issue => issue.severity === "WARNING"
  );

  return {
    tool: opts.tool,
    passed: !blocking,
    issues,
    assumptions,
    conclusion: blocking
      ? "SPEC_SANITY_BLOCKING"
      : warning
        ? "SPEC_SANITY_REVIEW_REQUIRED"
        : "SPEC_SANITY_ACCEPTABLE"
  } satisfies ProofSanityReport;
}
