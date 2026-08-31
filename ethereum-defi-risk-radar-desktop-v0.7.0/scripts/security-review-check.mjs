import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";
import { writeReports } from "../dist/report.js";

const source = `
pragma solidity ^0.8.20;
contract ReviewFixture {
  address public owner;
  mapping(address => uint256) public balances;
  function route(address target, bytes calldata payload) external {
    require(tx.origin == owner, "origin");
    target.call(payload);
    balances[msg.sender] = 1;
  }
}
`;

const inspection = inspectVerifiedSource(source);
assert.ok(inspection.advancedAnalysis.findings.length > 0, "fixture must emit advanced findings");
assert.ok(inspection.findings.length > 0, "fixture must emit source-review findings");

const candidate = {
  id: "review-fixture",
  label: "Review Fixture Protocol",
  hostname: "example.invalid",
  chain: "ethereum",
  network: "mainnet",
  researchScore: 81,
  ethereumConfidence: 95,
  signalCount: 3,
  sourceDiversity: 2,
  kinds: ["public_audit_finding", "historical_incident", "admin_governance_risk"],
  evidence: [],
  ethereum: {
    chainId: 1,
    network: "ethereum-mainnet",
    contractReferencesObserved: 1,
    etherscanLookupsAttempted: 1,
    verifiedSourceContracts: 1,
    proxyContracts: 0,
    sourceContractsInspected: 1,
    sourceFindingCount: inspection.findingCount,
    sourceHighReviewCount: inspection.severityCounts.HIGH_REVIEW,
    advancedFindingCount: inspection.advancedAnalysis.findings.length,
    sourceInspections: [{
      contractRefId: "fixture-contract",
      contractName: "ReviewFixture",
      compilerVersion: "0.8.20",
      proxy: false,
      inspection
    }]
  },
  classification: "HIGH_RESEARCH_PRIORITY"
};

const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), "risk-radar-security-review-"));
try {
  const paths = await writeReports({ candidates: [candidate], outputDir, startYear: 2020, endYear: 2026 });
  assert.ok(paths.securityReviewPath.endsWith("-security-review.html"));
  assert.ok(paths.findingsCsvPath.endsWith("-findings.csv"));

  const [summaryCsv, findingsCsv, html, json] = await Promise.all([
    fs.readFile(paths.csvPath, "utf8"),
    fs.readFile(paths.findingsCsvPath, "utf8"),
    fs.readFile(paths.securityReviewPath, "utf8"),
    fs.readFile(paths.jsonPath, "utf8")
  ]);

  assert.match(summaryCsv, /securityFindingCount/);
  assert.match(summaryCsv, /assessmentStatus/);
  assert.match(summaryCsv, /STRUCTURAL_SECURITY_FINDINGS|HEURISTIC_REVIEW_SIGNALS/);
  assert.match(findingsCsv, /evidenceKey/);
  assert.match(findingsCsv, /source_review/);
  assert.match(findingsCsv, /advanced/);
  assert.match(findingsCsv, /STRUCTURAL/);
  assert.match(html, /Finding-first security review/);
  assert.match(html, /Severity and evidence strength are independent/);
  assert.match(html, /Review Fixture Protocol/);
  assert.match(html, /tx\.origin|Transaction origin/);
  assert.doesNotMatch(json, /0x[a-fA-F0-9]{40}/, "reports must not retain full EVM addresses");

  console.log(`Security review checks passed: ${inspection.advancedAnalysis.findings.length} advanced findings, ${inspection.findings.length} source-review findings, detailed CSV + HTML exports generated.`);
} finally {
  await fs.rm(outputDir, { recursive: true, force: true });
}
