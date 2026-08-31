import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import path from "node:path";
import { analyzeSoliditySources } from "../dist/analysis/native/analyzer.js";
import { DEFI_CATEGORIES, simulateEconomicScenario } from "../dist/analysis/economic/simulator.js";
import { ECONOMIC_SCENARIO_PACKS, scenariosForCategory } from "../dist/analysis/economic/scenarios.js";
import { probeTool } from "../dist/analysis/capabilities.js";
import { runBoundedProcess } from "../dist/analysis/processRunner.js";
import { runAnalysisPlan } from "../dist/analysis/orchestrator.js";
import { DEFAULT_ANALYSIS_BUDGET } from "../dist/analysis/model.js";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";

const source = `
pragma solidity ^0.8.20;
interface IOracle { function price() external view returns (uint256); }
contract RiskFixture {
  address public owner;
  address public implementation;
  mapping(address => uint256) public balances;
  function route(address target, bytes calldata payload, uint256 amount) external {
    if (amount > 0) { balances[msg.sender] = amount; }
    target.call(payload);
  }
  function upgrade(address next) external { implementation = next; implementation.delegatecall(msg.data); }
  function loop(uint256 n) external { for (uint256 i = 0; i < n; i++) { balances[msg.sender] += i; } }
}
`;
const fixtureRoot = path.resolve("tests/analysis/fixtures");

const started = performance.now();
const report = analyzeSoliditySources([{ name: "RiskFixture.sol", content: source }]);
assert.ok(report.functionsAnalyzed >= 3, "functions should be represented in CFG output");
assert.ok(report.graphs.some(graph => graph.nodes.some(node => node.kind === "branch")), "branch node missing");
assert.ok(report.graphs.some(graph => graph.nodes.some(node => node.kind === "loop")), "loop node missing");
assert.ok(report.dependencies.some(item => item.variable === "implementation"), "data dependency missing");
assert.ok(report.storage.some(item => item.variable === "balances" && item.dynamic), "storage surface missing");
assert.ok(report.calls.some(call => call.operation === "call"), "external call missing");
assert.ok(report.calls.some(call => call.operation === "delegatecall"), "delegatecall missing");
assert.ok(report.findings.some(finding => finding.kind === "taint"), "taint finding missing");
assert.ok(report.findings.some(finding => finding.kind === "cross_contract_calls"), "unchecked call finding missing");
assert.ok(report.findings.some(finding => finding.kind === "reentrancy"), "reentrancy review surface missing");
assert.ok(report.findings.some(finding => finding.kind === "upgradeability"), "upgradeability review surface missing");
assert.ok(performance.now() - started < 2_000, "native fixture analysis exceeded performance budget");
const integrated = inspectVerifiedSource(source);
assert.equal(integrated.advancedAnalysis.functionsAnalyzed, report.functionsAnalyzed, "verified-source integration missing");

assert.deepEqual(new Set(DEFI_CATEGORIES), new Set([
  "lending", "amm", "dex", "vault", "staking", "bridge", "governance",
  "derivatives", "stablecoin", "yield_aggregator", "token_wrapper", "liquidation"
]));
for (const category of DEFI_CATEGORIES) {
  assert.ok(scenariosForCategory(category).length > 0, `missing economic scenario coverage for ${category}`);
}
assert.ok(ECONOMIC_SCENARIO_PACKS.length >= 8, "economic scenario registry is unexpectedly narrow");

const simulation = simulateEconomicScenario({
  step: 0,
  prices: { ETH: 2_000, USD: 1 },
  actors: { attacker: { id: "attacker", balances: { ETH: 10, USD: 0 }, debt: {} } },
  pools: { lending: { id: "lending", category: "lending", reserves: { ETH: 100, USD: 100_000 }, liabilities: {}, feesAccrued: 0 } }
}, [
  { type: "transfer", actor: "attacker", pool: "lending", asset: "ETH", amount: 2 },
  { type: "borrow", actor: "attacker", pool: "lending", asset: "USD", amount: 5_000 },
  { type: "price_shock", asset: "ETH", multiplier: 0.5 }
]);
assert.equal(simulation.finalState.step, 3);
assert.equal(simulation.actorNetWorth.attacker, 8_000);
assert.ok(simulation.invariants.every(item => item.passed));

const missing = await probeTool(
  { id: "slither", executable: "definitely-not-installed-risk-radar-tool", args: ["--version"] },
  { timeoutMs: 500 }
);
assert.equal(missing.available, false, "missing optional tool must be a normal unavailable state");

await assert.rejects(
  runBoundedProcess({ executable: "node", args: ["--version"], cwd: process.cwd(), timeoutMs: 500, maxOutputBytes: 1_024 }),
  /not allowlisted/,
  "arbitrary executable must be rejected"
);
await assert.rejects(
  runBoundedProcess({ executable: path.resolve("forge.exe"), args: ["--version"], cwd: process.cwd(), timeoutMs: 500, maxOutputBytes: 1_024 }),
  /bare command name/,
  "an allowed basename at a caller-selected path must be rejected"
);
const nativeOnly = await runAnalysisPlan({
  target: { type: "local_project", path: fixtureRoot, framework: "unknown", trusted: false },
  engines: ["native"],
  budget: DEFAULT_ANALYSIS_BUDGET
});
assert.equal(nativeOnly.capabilities.length, 0, "native-only analysis must not execute optional capability probes");
await assert.rejects(
  runAnalysisPlan({
    target: { type: "local_project", path: process.cwd(), framework: "unknown", trusted: false },
    engines: ["slither"],
    budget: DEFAULT_ANALYSIS_BUDGET
  }),
  /explicit trusted=true/,
  "external project execution must require explicit trust"
);

console.log(`Analysis checks passed: ${report.graphs.length} CFGs, ${report.dependencies.length} dependencies, ${report.storage.length} storage surfaces, ${report.calls.length} calls, ${report.findings.length} findings, ${DEFI_CATEGORIES.length} DeFi categories, ${ECONOMIC_SCENARIO_PACKS.length} scenario packs.`);
