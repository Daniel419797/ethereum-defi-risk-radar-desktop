import type {
  AnalysisConfidence,
  AnalysisFinding,
  AnalysisSeverity,
  Counterexample,
  EvidenceScope,
  EvidenceStrength
} from "./model.js";

/**
 * The evidence ladder, weakest first. Every finding in the system is constructed through
 * {@link finalizeFinding}, which is the only place a rung is granted. The project's hard
 * correctness gate is that confidence never exceeds evidence, so that ceiling is enforced
 * mechanically here rather than trusted to each rule and adapter.
 */
export const EVIDENCE_ORDER: readonly EvidenceStrength[] = [
  "HEURISTIC",
  "STRUCTURAL",
  "EXECUTED",
  "REPRODUCED"
] as const;

export const SEVERITY_ORDER: readonly AnalysisSeverity[] = [
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL"
] as const;

const CONFIDENCE_ORDER: readonly AnalysisConfidence[] = ["LOW", "MEDIUM", "HIGH"] as const;

/** Highest confidence each evidence rung is permitted to claim. */
const CONFIDENCE_CEILING: Record<EvidenceStrength, AnalysisConfidence> = {
  HEURISTIC: "LOW",
  STRUCTURAL: "MEDIUM",
  EXECUTED: "HIGH",
  REPRODUCED: "HIGH"
};

/** Standing caveat attached to every finding at a given rung. */
const RUNG_LIMITATION: Record<EvidenceStrength, string> = {
  HEURISTIC:
    "Heuristic pattern match; not confirmed by program analysis and may be a false positive.",
  STRUCTURAL:
    "Derived from static program structure; no execution observed and exploitability is unproven.",
  EXECUTED:
    "An engine produced a counterexample; the sequence has not been replayed independently.",
  REPRODUCED: "A captured counterexample was replayed successfully."
};

const MODEL_SCOPE_LIMITATION =
  "Model scope: the sequence violates an invariant in this project's own model. It is not evidence about deployed bytecode.";

const FORK_SCOPE_LIMITATION =
  "Fork scope: replayed against forked chain state at a pinned block. Behaviour may differ at other blocks or under different configuration.";

export function evidenceRank(strength: EvidenceStrength): number {
  return EVIDENCE_ORDER.indexOf(strength);
}

export function severityRank(severity: AnalysisSeverity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function maxConfidenceFor(strength: EvidenceStrength): AnalysisConfidence {
  return CONFIDENCE_CEILING[strength];
}

/** Returns the stronger of two rungs; used when engines corroborate each other. */
export function strongestEvidence(a: EvidenceStrength, b: EvidenceStrength): EvidenceStrength {
  return evidenceRank(a) >= evidenceRank(b) ? a : b;
}

/** Moves a severity up or down the ladder, saturating at both ends. */
export function stepSeverity(severity: AnalysisSeverity, steps: number): AnalysisSeverity {
  const next = Math.max(0, Math.min(SEVERITY_ORDER.length - 1, severityRank(severity) + steps));
  return SEVERITY_ORDER[next]!;
}

export function clampConfidence(
  confidence: AnalysisConfidence,
  strength: EvidenceStrength
): AnalysisConfidence {
  const ceiling = CONFIDENCE_CEILING[strength];
  return CONFIDENCE_ORDER.indexOf(confidence) > CONFIDENCE_ORDER.indexOf(ceiling)
    ? ceiling
    : confidence;
}

export class EvidenceInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceInvariantError";
  }
}

export type FindingDraft = Omit<AnalysisFinding, "confidence" | "limitations"> & {
  confidence?: AnalysisConfidence;
  limitations?: string[];
};

/**
 * The single constructor for findings. Fails closed: claiming an execution-backed rung
 * without the artifact that backs it is a programming error, not a warning, because a
 * mislabelled claim is worse than a missing one.
 */
export function finalizeFinding(draft: FindingDraft): AnalysisFinding {
  const strength = draft.evidenceStrength;
  const needsArtifact = strength === "EXECUTED" || strength === "REPRODUCED";

  if (needsArtifact && !draft.counterexample) {
    throw new EvidenceInvariantError(
      `Finding ${draft.id} claims ${strength} without a counterexample. ` +
        "EXECUTED and REPRODUCED are earned by holding an artifact, not by engine identity."
    );
  }

  let scope: EvidenceScope | undefined = draft.evidenceScope ?? draft.counterexample?.scope;

  if (strength === "REPRODUCED") {
    if (!scope) {
      throw new EvidenceInvariantError(
        `Finding ${draft.id} claims REPRODUCED without an evidence scope. ` +
          "A reproduction must state whether it is model scope or fork scope."
      );
    }
    if (draft.counterexample && draft.counterexample.scope !== scope) {
      throw new EvidenceInvariantError(
        `Finding ${draft.id} declares ${scope} scope but its counterexample was produced at ` +
          `${draft.counterexample.scope} scope.`
      );
    }
    if (scope === "fork" && draft.counterexample?.blockNumber === undefined) {
      throw new EvidenceInvariantError(
        `Finding ${draft.id} claims fork-scope reproduction without a pinned block number, ` +
          "so the result would not be replayable."
      );
    }
  } else if (strength !== "EXECUTED") {
    // Scope is only meaningful for artifact-backed rungs.
    scope = undefined;
  }

  const limitations = [...(draft.limitations ?? [])];
  const note = (text: string) => {
    if (!limitations.includes(text)) limitations.push(text);
  };
  note(RUNG_LIMITATION[strength]);
  if (strength === "REPRODUCED") {
    note(scope === "fork" ? FORK_SCOPE_LIMITATION : MODEL_SCOPE_LIMITATION);
  }
  if (draft.reachableFromExternalEntry === false) {
    note("No externally callable path to this location was found; impact may be unreachable.");
  }
  if (draft.mitigations?.length) {
    note(
      `Mitigations observed on all paths: ${draft.mitigations.map(item => item.kind).join(", ")}.`
    );
  }

  const finding: AnalysisFinding = {
    ...draft,
    confidence: clampConfidence(draft.confidence ?? maxConfidenceFor(strength), strength),
    limitations
  };
  if (scope) finding.evidenceScope = scope;
  else delete finding.evidenceScope;
  return finding;
}

/**
 * Human-readable evidence label used by the renderer and reports. REPRODUCED always carries
 * its scope, so a bare "Reproduced" is unrepresentable in output — a model-scope replay can
 * never be misread as a statement about deployed code.
 */
export function describeEvidence(finding: {
  evidenceStrength: EvidenceStrength;
  evidenceScope?: EvidenceScope;
  counterexample?: Counterexample;
}): string {
  switch (finding.evidenceStrength) {
    case "HEURISTIC":
      return "Heuristic";
    case "STRUCTURAL":
      return "Structural";
    case "EXECUTED":
      return "Executed (counterexample captured)";
    case "REPRODUCED": {
      const scope = finding.evidenceScope ?? finding.counterexample?.scope;
      return scope === "fork" ? "Reproduced (fork scope)" : "Reproduced (model scope)";
    }
  }
}

/**
 * Verifies the ladder over an already-built set of findings. Used by the test suite to check
 * producers that bypass {@link finalizeFinding}, and cheap enough to run on any boundary.
 */
export function assertEvidenceInvariant(findings: readonly AnalysisFinding[]): void {
  for (const finding of findings) {
    const ceiling = CONFIDENCE_CEILING[finding.evidenceStrength];
    if (CONFIDENCE_ORDER.indexOf(finding.confidence) > CONFIDENCE_ORDER.indexOf(ceiling)) {
      throw new EvidenceInvariantError(
        `Finding ${finding.id} claims ${finding.confidence} confidence at ` +
          `${finding.evidenceStrength} evidence, whose ceiling is ${ceiling}.`
      );
    }
    if (
      (finding.evidenceStrength === "EXECUTED" || finding.evidenceStrength === "REPRODUCED") &&
      !finding.counterexample
    ) {
      throw new EvidenceInvariantError(
        `Finding ${finding.id} claims ${finding.evidenceStrength} without a counterexample.`
      );
    }
    if (
      finding.evidenceStrength === "REPRODUCED" &&
      !(finding.evidenceScope ?? finding.counterexample?.scope)
    ) {
      throw new EvidenceInvariantError(`Finding ${finding.id} claims REPRODUCED without a scope.`);
    }
  }
}
