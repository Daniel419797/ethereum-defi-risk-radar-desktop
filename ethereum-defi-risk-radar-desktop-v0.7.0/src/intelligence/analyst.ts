import type {
  Candidate
} from "../types.js";
import type {
  AnalysisFinding
} from "../analysis/model.js";

export type AnalystEvidenceKind =
  | "FINDING"
  | "GRAPH_NODE"
  | "GRAPH_EDGE"
  | "INVARIANT"
  | "SYNTHESIZED_INVARIANT"
  | "SNAPSHOT"
  | "ATTESTATION"
  | "ATTACK_PATH";

export type AnalystEvidence = {
  id: string;
  kind: AnalystEvidenceKind;
  title: string;
  text: string;
  importance: number;
  metadata?: Record<
    string,
    string | number | boolean | null
  >;
};

export type AnalystClaim = {
  text: string;
  citations: string[];
};

export type AnalystResponse = {
  answer: string;
  claims: AnalystClaim[];
  uncertainty: string[];
};

export type AnalystPrompt = {
  system: string;
  question: string;
  evidence: AnalystEvidence[];
  requiredOutputSchema: {
    answer: "string";
    claims: Array<{
      text: "string";
      citations: "string[]";
    }>;
    uncertainty: "string[]";
  };
};

function words(value: string) {
  return value
    .toLowerCase()
    .split(/[^a-z0-9_]+/)
    .filter(value => value.length > 2);
}

function score(
  query: Set<string>,
  evidence: AnalystEvidence
) {
  const haystack = new Set(
    words(
      evidence.title +
        " " +
        evidence.text
    )
  );
  let overlap = 0;
  for (const term of query) {
    if (haystack.has(term)) {
      overlap += 1;
    }
  }
  return (
    overlap * 10 +
    evidence.importance
  );
}

function findingEvidence(
  candidate: Candidate
) {
  const rows: AnalystEvidence[] = [];
  const add = (
    finding: AnalysisFinding,
    contractRefId: string
  ) => {
    rows.push({
      id:
        "finding:" +
        contractRefId +
        ":" +
        finding.id,
      kind: "FINDING",
      title: finding.title,
      text: [
        finding.description,
        "severity=" +
          finding.severity,
        "evidence=" +
          (
            finding.evidenceClass ||
            finding.evidenceStrength
          ),
        "exploitability=" +
          (
            finding.exploitabilityVerdict ||
            "UNKNOWN"
          ),
        ...finding.limitations.map(
          item =>
            "limitation=" + item
        )
      ].join(" "),
      importance:
        finding.severity ===
        "CRITICAL"
          ? 100
          : finding.severity ===
              "HIGH"
            ? 80
            : finding.severity ===
                "MEDIUM"
              ? 50
              : 20,
      metadata: {
        severity:
          finding.severity,
        evidence:
          finding.evidenceClass ||
          finding.evidenceStrength,
        contractRefId
      }
    });
  };

  for (const inspection of
    candidate.ethereum
      .sourceInspections) {
    for (const finding of
      inspection.inspection
        .advancedAnalysis
        .findings) {
      add(
        finding,
        inspection.contractRefId
      );
    }
  }
  for (const inspection of
    candidate.ethereum
      .bytecodeInspections || []) {
    for (const finding of
      inspection.bytecodeAnalysis
        .findings) {
      add(
        finding,
        inspection.contractRefId
      );
    }
  }
  return rows;
}

export function buildAnalystEvidenceIndex(
  candidate: Candidate
) {
  const evidence =
    findingEvidence(candidate);
  const intelligence =
    candidate.ethereum
      .intelligence;

  for (const node of
    intelligence?.graph.nodes || []) {
    evidence.push({
      id: "graph-node:" + node.id,
      kind: "GRAPH_NODE",
      title: node.label,
      text:
        node.kind +
        " " +
        (node.category || "") +
        " " +
        JSON.stringify(
          node.metadata || {}
        ),
      importance:
        node.kind === "FINDING"
          ? 70
          : node.kind === "PROTOCOL"
            ? 60
            : 30,
      metadata: {
        nodeKind: node.kind,
        contractRefId:
          node.contractRefId || null
      }
    });
  }

  for (const edge of
    intelligence?.graph.edges || []) {
    evidence.push({
      id: "graph-edge:" + edge.id,
      kind: "GRAPH_EDGE",
      title:
        edge.kind +
        " relationship",
      text:
        edge.from +
        " " +
        edge.kind +
        " " +
        edge.to +
        " confidence=" +
        edge.confidence,
      importance: 35
    });
  }

  for (const selected of
    intelligence?.invariants || []) {
    evidence.push({
      id:
        "invariant:" +
        selected.invariant.id,
      kind: "INVARIANT",
      title:
        selected.invariant.title,
      text:
        selected.invariant
          .statement +
        " rationale=" +
        selected.rationale.join(
          ", "
        ),
      importance: 60
    });
  }

  for (const invariant of
    intelligence
      ?.synthesizedInvariants ||
    []) {
    evidence.push({
      id:
        "synthesized:" +
        invariant.id,
      kind:
        "SYNTHESIZED_INVARIANT",
      title: invariant.title,
      text:
        invariant.statement +
        " formula=" +
        invariant.formula +
        " assumptions=" +
        invariant.assumptions.join(
          "; "
        ),
      importance:
        invariant.confidence ===
        "HIGH"
          ? 75
          : 55
    });
  }

  const snapshot =
    candidate.ethereum
      .pinnedStateSnapshot;
  if (snapshot) {
    evidence.push({
      id:
        "snapshot:" +
        snapshot.digest,
      kind: "SNAPSHOT",
      title:
        "Pinned state block " +
        snapshot.blockNumber,
      text:
        "blockHash=" +
        snapshot.blockHash +
        " contracts=" +
        snapshot.contracts.length +
        " partial=" +
        snapshot.partial +
        " limitations=" +
        snapshot.limitations.join(
          "; "
        ),
      importance: 90
    });
  }

  for (const inspection of
    candidate.ethereum
      .bytecodeInspections || []) {
    if (
      !inspection.bytecodeAttestation
    ) {
      continue;
    }
    const item =
      inspection.bytecodeAttestation;
    evidence.push({
      id:
        "attestation:" +
        inspection.contractRefId,
      kind: "ATTESTATION",
      title:
        "Bytecode attestation " +
        inspection.contractRefId,
      text:
        "status=" +
        item.status +
        " compiler=" +
        (
          item.compilerVersion ||
          "unknown"
        ) +
        " observed=" +
        (
          item.observedRuntimeHash ||
          ""
        ) +
        " limitations=" +
        item.limitations.join(
          "; "
        ),
      importance:
        item.status.startsWith(
          "SOURCE_RECOMPILED"
        )
          ? 95
          : 60
    });
  }

  for (const attack of
    intelligence?.attackPaths ||
    []) {
    evidence.push({
      id:
        "attack-path:" +
        attack.id,
      kind: "ATTACK_PATH",
      title: attack.title,
      text:
        attack.nodes
          .map(node => node.label)
          .join(" -> ") +
        " evidence=" +
        attack.evidenceStrength +
        " limitations=" +
        attack.limitations.join(
          "; "
        ),
      importance: 80
    });
  }

  return evidence;
}

export function retrieveAnalystEvidence(
  question: string,
  evidence: AnalystEvidence[],
  maxItems = 24
) {
  const query = new Set(
    words(question)
  );
  return [...evidence]
    .map(item => ({
      item,
      score: score(
        query,
        item
      )
    }))
    .sort(
      (a, b) =>
        b.score - a.score ||
        a.item.id.localeCompare(
          b.item.id
        )
    )
    .slice(
      0,
      Math.max(
        1,
        Math.min(maxItems, 100)
      )
    )
    .map(row => row.item);
}

export function buildAnalystPrompt(
  question: string,
  evidence: AnalystEvidence[]
): AnalystPrompt {
  return {
    system: [
      "You are the Risk Radar evidence analyst.",
      "Use only the supplied evidence objects.",
      "Every factual security claim must cite one or more evidence IDs.",
      "Never infer exploitability from severity alone.",
      "BYTECODE_STRUCTURAL and SOURCE_STRUCTURAL are review evidence, not exploit proof.",
      "MODEL_REPRODUCED is not deployed-bytecode proof.",
      "PROVED_UNDER_SPEC means only the exact property under its listed assumptions; never say the protocol is safe.",
      "If evidence is insufficient, state the uncertainty instead of filling the gap."
    ].join(" "),
    question,
    evidence,
    requiredOutputSchema: {
      answer: "string",
      claims: [
        {
          text: "string",
          citations: "string[]"
        }
      ],
      uncertainty: [
        "string[]"
      ]
    }
  };
}

export function validateAnalystResponse(
  response: AnalystResponse,
  suppliedEvidence: AnalystEvidence[]
) {
  const allowed = new Set(
    suppliedEvidence.map(
      item => item.id
    )
  );
  const errors: string[] = [];

  if (
    !response.answer ||
    typeof response.answer !==
      "string"
  ) {
    errors.push(
      "Analyst response has no answer."
    );
  }

  for (
    const [index, claim] of
    response.claims.entries()
  ) {
    if (
      !claim.text ||
      !claim.citations?.length
    ) {
      errors.push(
        "Claim " +
          index +
          " is uncited."
      );
      continue;
    }
    for (const citation of
      claim.citations) {
      if (!allowed.has(citation)) {
        errors.push(
          "Claim " +
            index +
            " cites unavailable evidence " +
            citation +
            "."
        );
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

export async function runEvidenceCalibratedAnalyst(opts: {
  candidate: Candidate;
  question: string;
  provider: (
    prompt: AnalystPrompt
  ) => Promise<AnalystResponse>;
  maxEvidence?: number;
}) {
  const index =
    buildAnalystEvidenceIndex(
      opts.candidate
    );
  const selected =
    retrieveAnalystEvidence(
      opts.question,
      index,
      opts.maxEvidence ?? 24
    );
  const prompt =
    buildAnalystPrompt(
      opts.question,
      selected
    );
  const response =
    await opts.provider(prompt);
  const validation =
    validateAnalystResponse(
      response,
      selected
    );
  if (!validation.valid) {
    throw new Error(
      "Analyst response failed evidence validation: " +
        validation.errors.join(
          " "
        )
    );
  }
  return {
    response,
    evidence: selected,
    validation
  };
}
