import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";
import { writeReports } from "../dist/report.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const rendererDir = path.join(root, "desktop", "renderer");
const appJs = await fs.readFile(path.join(rendererDir, "app.js"), "utf8");
const html = await fs.readFile(path.join(rendererDir, "index.html"), "utf8");
const css = await fs.readFile(path.join(rendererDir, "styles.css"), "utf8");
const packageJson = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));

for (const unsafe of ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "Function("]) {
  assert.equal(appJs.includes(unsafe), false, `Unsafe renderer API found: ${unsafe}`);
}

for (const marker of [
  'const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }',
  "REPRODUCED_FORK",
  "REPRODUCED_MODEL",
  "findingEvidenceLabel",
  "analysisCompleteness",
  "sourceFindingShadowedByAdvanced",
  "Historical Audit Intelligence",
  "Recommended remediation",
  "Witness path",
  "Counterexample",
  "Limitations"
]) {
  assert.ok(appJs.includes(marker), `Finding-first renderer marker missing: ${marker}`);
}

assert.equal(
  appJs.includes('finding.severity === "CRITICAL" || finding.severity === "HIGH" ? "HIGH_REVIEW"'),
  false,
  "CRITICAL and HIGH findings must never be collapsed into HIGH_REVIEW."
);

for (const marker of [
  'id="findings-evidence-filter"',
  '<option value="CRITICAL">Critical</option>',
  '<option value="HIGH">High</option>',
  'id="candidate-analysis-warning"',
  'id="results-show-summary-csv"',
  'id="results-show-findings-csv"',
  'id="results-show-security-html"',
  "Severity and evidence strength are independent"
]) {
  assert.ok(html.includes(marker), `Finding-first HTML marker missing: ${marker}`);
}

for (const marker of [
  ".severity-block.critical",
  ".severity-block.high",
  ".finding-badge.evidence.reproduced_fork",
  ".finding-meta-grid",
  ".finding-history",
  ".analysis-completeness-warning"
]) {
  assert.ok(css.includes(marker), `Finding-first CSS marker missing: ${marker}`);
}

assert.ok(String(packageJson.scripts?.check || "").includes("security-review-check.mjs"), "npm run check must execute security-review-check.mjs.");
assert.equal(packageJson.scripts?.["test:security-review"], "npm run build && node scripts/security-review-check.mjs", "Dedicated security review regression command is missing.");

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "risk-radar-security-review-"));
try {
  const source = `
    pragma solidity ^0.8.20;
    contract ReviewFixture {
      address public owner;
      function unsafeCall(address target, bytes calldata data) external {
        require(tx.origin == owner, "auth");
        (bool ok,) = target.call(data);
        require(ok, "call");
      }
    }
  `;
  const inspection = inspectVerifiedSource(source, { maxBytes: 500000, maxFindings: 80 });
  const rawAddress = "0x1111111111111111111111111111111111111111";
  const candidate = {
    id: "security-review-fixture",
    entityKind: "PROTOCOL",
    resolutionStatus: "SOURCE_ANALYZED",
    label: '=HYPERLINK("https://example.invalid") <img src=x onerror=alert(1)>',
    hostname: "fixture.example",
    chain: "ethereum",
    network: "mainnet",
    researchScore: 88,
    ethereumConfidence: 95,
    signalCount: 3,
    sourceDiversity: 2,
    kinds: ["public_audit_finding"],
    evidence: [{
      kind: "public_audit_finding",
      weight: 1,
      sourceUrl: `https://fixture.example/report/${rawAddress}`,
      sourceTitle: `Fixture report ${rawAddress}`,
      sourceHost: "fixture.example",
      sourceTrust: "HIGH",
      snippet: `Contract ${rawAddress}`,
      year: 2026,
      query: "fixture",
      ethereumTerms: ["ethereum"],
      contractReferenceCount: 1
    }],
    resolutionEvidence: [],
    ethereum: {
      chainId: 1,
      network: "ethereum-mainnet",
      contractReferencesObserved: 1,
      etherscanLookupsAttempted: 1,
      verifiedSourceContracts: 1,
      proxyContracts: 0,
      proxyImplementationsResolved: 0,
      sourceContractsInspected: 1,
      sourceFindingCount: inspection.findings.length,
      sourceHighReviewCount: inspection.severityCounts.HIGH_REVIEW,
      advancedFindingCount: inspection.advancedAnalysis.findings.length,
      sourceInspections: [{
        contractRefId: "contract-ref-security-review",
        contractName: "ReviewFixture",
        sourceRole: "DIRECT",
        compilerVersion: "v0.8.20",
        proxy: false,
        inspection
      }]
    },
    classification: "HIGH_RESEARCH_PRIORITY"
  };

  const reports = await writeReports({ candidates: [candidate], outputDir: tempDir, startYear: 2026, endYear: 2026 });
  for (const key of ["jsonPath", "csvPath", "summaryCsvPath", "findingsCsvPath", "securityReviewPath"]) {
    assert.ok(reports[key], `Missing report path: ${key}`);
    await fs.access(reports[key]);
  }

  const json = await fs.readFile(reports.jsonPath, "utf8");
  const detailedCsv = await fs.readFile(reports.csvPath, "utf8");
  const summaryCsv = await fs.readFile(reports.summaryCsvPath, "utf8");
  const findingsCsv = await fs.readFile(reports.findingsCsvPath, "utf8");
  const securityHtml = await fs.readFile(reports.securityReviewPath, "utf8");

  for (const output of [json, detailedCsv, summaryCsv, findingsCsv, securityHtml]) {
    assert.equal(output.includes(rawAddress), false, "Raw EVM address leaked into a report artifact.");
  }
  assert.ok(json.includes('"findingRows"'), "Detailed JSON finding rows are missing.");
  assert.ok(detailedCsv.includes('"analysis_finding"') || detailedCsv.includes('"legacy_review_signal"'), "Detailed CSV finding rows are missing.");
  assert.ok(summaryCsv.includes('"assessmentStatus"') && summaryCsv.includes('"analysisPartial"'), "Summary CSV assessment/completeness fields are missing.");
  assert.ok(findingsCsv.includes('"severity"') && findingsCsv.includes('"evidenceKey"') && findingsCsv.includes('"exploitabilityVerdict"'), "Finding CSV evidence schema is incomplete.");
  assert.ok(securityHtml.includes("Finding-first security review"), "Standalone HTML security review is missing its title.");
  assert.ok(securityHtml.includes("&lt;img src=x onerror=alert(1)&gt;"), "Standalone HTML report must escape protocol labels.");
  assert.equal(securityHtml.includes("<img src=x onerror=alert(1)>"), false, "Standalone HTML report rendered unescaped protocol content.");
  assert.ok(summaryCsv.includes("'=HYPERLINK"), "CSV formula-injection protection was not applied to protocol labels.");
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
}

console.log("Security review checks passed: native severity preserved, evidence separated, partial-analysis warnings retained, reports escaped/redacted, and exports generated.");
