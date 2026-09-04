import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { cleanAuditRecord } from "../dist/auditIntelligence/taxonomy.js";
import { AuditIntelligenceEngine } from "../dist/auditIntelligence/engine.js";
import { evaluateAuditCorpus } from "../dist/auditIntelligence/evaluation.js";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";

const rawRows = [
  { id: 1, bug_title: "Reentrancy Risk in Pool::invest() Submitted by auditor", bug_desc: "The function performs an external call before it updates internal accounting state, allowing possible re-entrancy.", bug_poc: "no poc", bug_rec: "Use checks-effects-interactions and nonReentrant.", bug_sev: "High", bug_sev_raw: "High Risk", bug_weight: 0.8 },
  { id: 2, bug_title: "Incompatibility With Deflationary Tokens", bug_desc: "The protocol assumes transferFrom moves the exact requested amount and can mis-account fee-on-transfer tokens.", bug_poc: "N/A", bug_rec: "Compare balances before and after transfer and account for the actual amount received.", bug_sev: "Medium", bug_sev_raw: "Medium", bug_weight: 0.6 },
  { id: 3, bug_title: "Stale oracle price can liquidate healthy accounts", bug_desc: "latestRoundData is consumed without checking updatedAt, heartbeat or answeredInRound before collateral liquidation.", bug_poc: "no poc", bug_rec: "Validate oracle freshness and round metadata.", bug_sev: "Critical", bug_sev_raw: "Critical", bug_weight: 0.9 },
  { id: 4, bug_title: "Permit nonce can be griefed", bug_desc: "Permit signatures and nonce consumption can be replayed or invalidated unexpectedly during liquidity removal.", bug_poc: "no poc", bug_rec: "Bind signatures to nonce, expiry and domain separator.", bug_sev: "Medium", bug_sev_raw: "Medium", bug_weight: 0.55 },
  { id: 5, bug_title: "Cross-chain message replay", bug_desc: "Bridge message validation does not sufficiently bind source chain, sender and message nonce.", bug_poc: "no poc", bug_rec: "Bind source chain, sender, nonce and payload before execution.", bug_sev: "High", bug_sev_raw: "High", bug_weight: 0.7 },
  { id: 6, bug_title: "Liquidation rounding creates bad debt", bug_desc: "Collateral liquidation rounds in the wrong direction and can leave protocol bad debt.", bug_poc: "no poc", bug_rec: "Define conservative rounding and enforce solvency invariants.", bug_sev: "High", bug_sev_raw: "High", bug_weight: 0.75 },
  { id: 7, bug_title: "Admin can upgrade implementation without timelock", bug_desc: "The privileged owner can change proxy implementation immediately without governance delay.", bug_poc: "no poc", bug_rec: "Require multisig and timelocked upgrade authorization.", bug_sev: "High", bug_sev_raw: "High", bug_weight: 0.68 },
  { id: 8, bug_title: "Missing slippage protection permits front-running", bug_desc: "Swap output is accepted without a user-defined minimum amount or deadline and can be sandwiched.", bug_poc: "no poc", bug_rec: "Require minimum output and deadline.", bug_sev: "Medium", bug_sev_raw: "Medium", bug_weight: 0.59 },
  { id: 9, bug_title: "Unbounded user loop can DoS settlement", bug_desc: "A loop over user-controlled array length can exceed the block gas limit and prevent settlement.", bug_poc: "no poc", bug_rec: "Bound or paginate work per transaction.", bug_sev: "Medium", bug_sev_raw: "Medium", bug_weight: 0.52 },
  { id: 10, bug_title: "Execution fee ignores settlement token decimals", bug_desc: "A hard-coded execution fee assumes six decimals and charges inconsistent amounts for other settlement tokens.", bug_poc: "no poc", bug_rec: "Normalize token decimals and make fee configuration asset-aware.", bug_sev: "Medium", bug_sev_raw: "Medium", bug_weight: 0.53 },
  { id: 11, bug_title: "Missing group index validation", bug_desc: "A caller supplied group index is not checked against zero and the current maximum before state access.", bug_poc: "no poc", bug_rec: "Validate index bounds before lookup.", bug_sev: "Low", bug_sev_raw: "Low", bug_weight: 0.32 },
  { id: 12, bug_title: "Incorrect share accounting after donation", bug_desc: "Direct asset donations can inflate exchange-rate accounting and allow share manipulation for later depositors.", bug_poc: "no poc", bug_rec: "Use virtual shares/assets or donation-resistant accounting.", bug_sev: "High", bug_sev_raw: "High", bug_weight: 0.7 }
];

const records = rawRows.map(cleanAuditRecord).filter(Boolean);
assert.equal(records.length, rawRows.length);
assert.equal(records[0].title.includes("Submitted by"), false, "researcher handles should be removed from titles");
assert.equal(records[0].hasPoc, false, "PoC placeholders must not be treated as real PoCs");
assert.equal(records.find(row => row.id === "2")?.category, "token_integration");
assert.equal(records.find(row => row.id === "3")?.category, "oracle_price");
assert.equal(records.find(row => row.id === "5")?.category, "bridge_cross_chain");

const engine = new AuditIntelligenceEngine(records, { sourceName: "fixture", generatedAt: new Date(0).toISOString(), trainCount: records.filter(r => r.split === "train").length, benchmarkCount: records.filter(r => r.split === "benchmark").length });
const context = engine.analyzeFinding({ id: "current:1", title: "Fee-on-transfer accounting mismatch", description: "safeTransferFrom is followed by accounting that assumes the requested amount was received.", kind: "token_integration" });
assert.ok(context, "historical context should be returned");
assert.equal(context.predictedCategory, "token_integration");
assert.ok(context.analogues.some(match => /deflationary/i.test(match.title)), "token analogue should be retrieved");
assert.ok(context.historicalRiskScore >= 0 && context.historicalRiskScore <= 100);
assert.equal("poc" in context.analogues[0], false, "historical UI model must never expose PoC code");

const full = engine.analyzeFindings([{ id: "f", title: "stale oracle", description: "latestRoundData freshness is unchecked" }]);
assert.equal(full.corpus.redistributionAllowed, false);
assert.ok(full.limitations.some(value => /not proof/i.test(value)));

const temp = await fs.mkdtemp(path.join(os.tmpdir(), "risk-radar-audit-check-"));
try {
  const corpusPath = path.join(temp, "cleaned-audit-findings.jsonl");
  await fs.writeFile(corpusPath, records.map(row => JSON.stringify(row)).join("\n") + "\n", "utf8");
  process.env.RISK_RADAR_AUDIT_CORPUS = corpusPath;
  const inspection = inspectVerifiedSource(`pragma solidity ^0.8.20; contract Vault { function deposit(address token, uint amount) external { IERC20(token).transferFrom(msg.sender, address(this), amount); } }`);
  assert.ok(inspection.historicalIntelligence?.matchedFindings, "verified-source analysis should attach historical intelligence when a local corpus is configured");
  assert.ok(inspection.findings.some(finding => finding.description.includes("Historical Audit Intelligence")), "existing Source Findings UI should receive historical context without a new exploitability claim");
} finally {
  delete process.env.RISK_RADAR_AUDIT_CORPUS;
  await fs.rm(temp, { recursive: true, force: true });
}

// Holdout mechanics are tested with an explicit split so the fixture can never become
// degenerate merely because its SHA buckets happen to land on one side.
const evaluationRecords = records.map((record, index) => ({ ...record, split: index < 8 ? "train" : "benchmark" }));
const evaluation = evaluateAuditCorpus(evaluationRecords);
assert.equal(evaluation.trainRecords, 8);
assert.equal(evaluation.benchmarkRecords, 4);
assert.ok(evaluation.categoryAccuracy >= 0 && evaluation.categoryAccuracy <= 1);
assert.ok(evaluation.limitations.some(value => /not.*vulnerability-detection accuracy/i.test(value)));

console.log("Audit intelligence checks passed.");
