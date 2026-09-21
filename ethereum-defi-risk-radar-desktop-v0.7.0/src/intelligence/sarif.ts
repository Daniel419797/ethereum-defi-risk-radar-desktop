import fs from "node:fs/promises";
import path from "node:path";
import type { AnalysisFinding, AnalysisSeverity } from "../analysis/model.js";
import type { Candidate } from "../types.js";

type SarifLevel = "error" | "warning" | "note";

function sarifLevel(severity: AnalysisSeverity): SarifLevel {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM" || severity === "LOW") return "warning";
  return "note";
}

function safeUri(value: string) {
  return value.replaceAll("\\", "/").replace(/^\/+/, "") || "verified-source.sol";
}

function advancedFindings(candidates: Candidate[]) {
  return candidates.flatMap(candidate =>
    candidate.ethereum.sourceInspections.flatMap(inspection =>
      inspection.inspection.advancedAnalysis.findings.map(finding => ({
        candidate,
        inspection,
        finding
      }))
    )
  );
}

function ruleId(finding: AnalysisFinding) {
  return `risk-radar/${finding.kind}`;
}

function location(finding: AnalysisFinding) {
  const primary = finding.primaryLocation;
  if (!primary) return undefined;
  return {
    physicalLocation: {
      artifactLocation: { uri: safeUri(primary.file) },
      region: {
        startLine: Math.max(1, primary.line),
        ...(primary.column ? { startColumn: Math.max(1, primary.column) } : {})
      }
    }
  };
}

function codeFlows(finding: AnalysisFinding) {
  if (!finding.witnessPath?.length) return undefined;
  return [{
    threadFlows: [{
      locations: finding.witnessPath.slice(0, 128).map(step => ({
        location: {
          message: { text: `${step.role}: ${step.symbol}${step.detail ? ` — ${step.detail}` : ""}` },
          physicalLocation: {
            artifactLocation: { uri: safeUri(step.location.file) },
            region: {
              startLine: Math.max(1, step.location.line),
              ...(step.location.column ? { startColumn: Math.max(1, step.location.column) } : {})
            }
          }
        }
      }))
    }]
  }];
}

export function candidatesToSarif(candidates: Candidate[]) {
  const rows = advancedFindings(candidates);
  const kinds = new Map<string, AnalysisFinding>();
  for (const row of rows) if (!kinds.has(row.finding.kind)) kinds.set(row.finding.kind, row.finding);

  const rules = [...kinds.values()].map(finding => ({
    id: ruleId(finding),
    name: finding.kind,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description.slice(0, 1_000) },
    help: {
      text: finding.remediation || "Review the evidence path, limitations and protocol context before deciding remediation.",
      markdown: finding.remediation || "Review the evidence path, limitations and protocol context before deciding remediation."
    },
    defaultConfiguration: { level: sarifLevel(finding.severity) },
    properties: {
      tags: ["ethereum", "defi", "smart-contract", finding.kind],
      securitySeverity:
        finding.severity === "CRITICAL" ? "9.5" :
        finding.severity === "HIGH" ? "8.0" :
        finding.severity === "MEDIUM" ? "5.5" :
        finding.severity === "LOW" ? "3.0" : "0.0"
    }
  }));

  const results = rows.map(({ candidate, inspection, finding }) => ({
    ruleId: ruleId(finding),
    level: sarifLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.description}`
    },
    ...(location(finding) ? { locations: [location(finding)] } : {}),
    ...(codeFlows(finding) ? { codeFlows: codeFlows(finding) } : {}),
    partialFingerprints: {
      "riskRadarFinding/v1": [
        candidate.id,
        inspection.contractRefId,
        finding.kind,
        finding.primaryLocation?.file ?? "",
        finding.primaryLocation?.line ?? 0,
        finding.title
      ].join("|")
    },
    properties: {
      protocol: candidate.label,
      protocolId: candidate.id,
      contractRefId: inspection.contractRefId,
      sourceRole: inspection.sourceRole ?? (inspection.proxy ? "PROXY" : "DIRECT"),
      severity: finding.severity,
      confidence: finding.confidence,
      evidenceStrength: finding.evidenceStrength,
      evidenceScope: finding.evidenceScope ?? finding.counterexample?.scope ?? null,
      exploitabilityVerdict: finding.exploitabilityVerdict ?? "UNKNOWN",
      engine: finding.engine,
      correlatedEngines: finding.correlatedEngines ?? [],
      reachableFromExternalEntry: finding.reachableFromExternalEntry ?? null,
      limitations: finding.limitations,
      mitigations: finding.mitigations?.map(item => item.kind) ?? []
    }
  }));

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "Ethereum DeFi Risk Radar",
          informationUri: "https://github.com/Daniel419797/ethereum-defi-risk-radar-desktop",
          semanticVersion: "0.7.0",
          rules
        }
      },
      automationDetails: { id: "risk-radar/security-review" },
      results,
      properties: {
        chainId: 1,
        network: "ethereum-mainnet",
        evidencePolicy: "Severity and evidence strength are independent. SARIF results are review findings; only explicit pinned-fork confirmation establishes exploitability for a finding."
      }
    }]
  };
}

export async function writeSarif(candidates: Candidate[], outputPath: string) {
  const resolved = path.resolve(outputPath);
  if (!resolved.toLowerCase().endsWith(".sarif") && !resolved.toLowerCase().endsWith(".sarif.json")) {
    throw new Error("SARIF output path must end in .sarif or .sarif.json.");
  }
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  await fs.writeFile(resolved, JSON.stringify(candidatesToSarif(candidates), null, 2), "utf8");
  return resolved;
}
