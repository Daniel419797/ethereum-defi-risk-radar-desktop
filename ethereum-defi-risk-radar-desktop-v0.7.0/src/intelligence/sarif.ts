import type { AnalysisFinding } from "../analysis/model.js";
import type { Candidate } from "../types.js";

function sarifLevel(severity: AnalysisFinding["severity"]) {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM" || severity === "LOW") return "warning";
  return "note";
}

function advancedFindings(candidate: Candidate) {
  return candidate.ethereum.sourceInspections.flatMap(inspection =>
    inspection.inspection.advancedAnalysis.findings.map(finding => ({
      candidate,
      inspection,
      finding
    }))
  );
}

export function candidatesToSarif(candidates: Candidate[]) {
  const rows = candidates.flatMap(advancedFindings);
  const rules = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      help: { text: string };
    }
  >();

  const results = rows.map(({ candidate, inspection, finding }) => {
    if (!rules.has(finding.kind)) {
      rules.set(finding.kind, {
        id: finding.kind,
        name: finding.kind.replaceAll("_", " "),
        shortDescription: { text: finding.title },
        help: { text: finding.remediation || finding.description }
      });
    }

    const location = finding.primaryLocation;
    return {
      ruleId: finding.kind,
      level: sarifLevel(finding.severity),
      message: {
        text:
          finding.title +
          " — " +
          finding.description +
          " Evidence: " +
          finding.evidenceStrength +
          (finding.evidenceScope
            ? " (" + finding.evidenceScope + ")"
            : "") +
          ". Protocol: " +
          candidate.label +
          "; contract ref: " +
          inspection.contractRefId +
          "."
      },
      properties: {
        severity: finding.severity,
        evidenceStrength: finding.evidenceStrength,
        evidenceScope: finding.evidenceScope,
        confidence: finding.confidence,
        exploitabilityVerdict:
          finding.exploitabilityVerdict || "UNKNOWN",
        protocolId: candidate.id,
        contractRefId: inspection.contractRefId
      },
      ...(location
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: location.file.replaceAll("\\", "/")
                  },
                  region: {
                    startLine: Math.max(1, location.line),
                    ...(location.column
                      ? { startColumn: Math.max(1, location.column) }
                      : {})
                  }
                }
              }
            ]
          }
        : {})
    };
  });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Ethereum DeFi Risk Radar",
            informationUri:
              "https://github.com/Daniel419797/ethereum-defi-risk-radar-desktop",
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}
