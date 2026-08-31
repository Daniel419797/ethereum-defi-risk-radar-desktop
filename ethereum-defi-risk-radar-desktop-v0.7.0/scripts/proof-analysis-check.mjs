import assert from "node:assert/strict";
import { analyzeSoliditySources } from "../dist/analysis/native/analyzer.js";
import { normalizeExternalFindings } from "../dist/analysis/adapters/external.js";
import { assertEvidenceInvariant, EvidenceInvariantError, finalizeFinding } from "../dist/analysis/evidence.js";
import { buildProtocolModel, runProtocolScenarios } from "../dist/analysis/protocol.js";
import { replayOnPinnedAnvil } from "../dist/analysis/reproduction.js";
import { runAnalysisPlan } from "../dist/analysis/orchestrator.js";
import { DEFAULT_ANALYSIS_BUDGET } from "../dist/analysis/model.js";
import { inspectVerifiedSource } from "../dist/sourceAnalyzer.js";

const source = `
pragma solidity ^0.8.20;
interface IOracle { function latestRoundData() external view returns (uint80,int256,uint256,uint256,uint80); }
contract LendingPool {
  IOracle public oracle;
  address public owner;
  mapping(address => uint256) public balances;
  modifier onlyOwner() { require(msg.sender == owner); _; }
  function safePrice() external view returns (uint256) {
    (,int256 answer,,uint256 updatedAt,uint80 answeredInRound) = oracle.latestRoundData();
    require(updatedAt > 0 && answeredInRound > 0 && answer > 0);
    return uint256(answer);
  }
  function guardedUpgrade(address next) external onlyOwner { owner = next; }
  function calls(address target) external {
    helper();
    if (false) { balances[msg.sender] = 9; }
    target.call(""); target.call(""); target.call(""); target.call(""); target.call("");
  }
  function helper() internal pure returns (uint256) { return 1; }
  function unused() internal { owner = address(0); }
}
contract Router { LendingPool public pool; function route() external { pool.safePrice(); } }
`;

const report = analyzeSoliditySources([{ name: "Protocol.sol", content: source }]);
for (const graph of report.graphs) {
  const ids = new Set(graph.nodes.map(node => node.id));
  assert.ok(graph.edges.every(edge => ids.has(edge.from) && ids.has(edge.to)), `dangling CFG edge in ${graph.id}`);
  assert.ok(graph.entryId && graph.immediateDominators && graph.nodes.some(node => node.kind === "exit"));
}
assert.ok(report.graphs.some(graph => graph.unreachableNodeIds?.length), "literal false branch should be unreachable");
assert.equal(report.graphs.find(graph => graph.id.endsWith(":helper"))?.nodes[0].reachable, true, "internal helper called by an external entry must be reachable");
assert.equal(report.graphs.find(graph => graph.id.endsWith(":unused"))?.nodes[0].reachable, false, "uncalled internal function must remain unreachable");
assert.equal(report.findings.filter(item => item.title.includes("Oracle freshness")).length, 0, "complete same-function oracle validation must suppress stale-oracle review");
assert.ok(report.findings.some(item => item.mitigations?.some(value => value.kind === "access_control")), "function-scoped access control should be recorded");
assert.ok(report.truncations?.some(item => item.ruleId === "external-call" && item.dropped === 2), "rule cap must report dropped results");
assert.equal(report.partial, true, "capped native output must be marked partial");
const cappedLegacy = inspectVerifiedSource(`pragma solidity ^0.8.20; contract C { function f() external { tx.origin; tx.origin; tx.origin; tx.origin; } }`, { maxFindings: 2 });
assert.ok(cappedLegacy.findings.length <= 2);
assert.ok(cappedLegacy.truncatedFindingCount > 0 && cappedLegacy.partial, "legacy caps must be explicit and partial");

assert.throws(() => finalizeFinding({ id: "bad", kind: "fuzzing", engine: "echidna", severity: "HIGH", evidenceStrength: "EXECUTED", title: "bad", description: "bad" }), EvidenceInvariantError);
const slither = normalizeExternalFindings("slither", JSON.stringify({ results: [{ check: "x", impact: "High" }] }), 10, 7);
assert.equal(slither.findings[0].evidenceStrength, "STRUCTURAL");
assert.equal(slither.findings[0].confidence, "MEDIUM");
const mythril = normalizeExternalFindings("mythril", JSON.stringify({ issues: [{ swcID: "107", severity: "High", error: "assertion violated", transactions: [{ from: "0x1", to: "0x2", data: "0x" }] }] }), 10, 77);
assert.equal(mythril.findings[0].evidenceStrength, "EXECUTED");
assert.equal(mythril.findings[0].counterexample.seed, 77);
assert.ok(mythril.findings[0].counterexample.sequence.length);
const passingForge = normalizeExternalFindings("foundry", JSON.stringify({ tests: [{ name: "test_ok", passed: true }] }), 10, 1);
assert.equal(passingForge.findings[0].evidenceStrength, "STRUCTURAL", "passing unrelated tests cannot earn EXECUTED");
assertEvidenceInvariant([...slither.findings, ...mythril.findings, ...passingForge.findings]);

const model = buildProtocolModel([{ name: "Protocol.sol", content: source }], report.findings);
assert.equal(model.contracts.length, 3);
assert.ok(model.calls.some(edge => edge.resolved && edge.to?.endsWith(":LendingPool")), "typed cross-contract link should resolve");
const scenarios = runProtocolScenarios(model, { prices: { ETH: 1_000, USD: 1 }, pools: { LendingPool: { reserves: { ETH: 1 }, liabilities: { USD: 750 } } }, actor: { id: "researcher", balances: { ETH: 1 }, debt: {} } }, 11);
assert.ok(scenarios.length > 0, "scenario registry must be consumed for matching protocol categories");
const modelProof = scenarios.find(item => item.finding)?.finding;
assert.equal(modelProof?.evidenceStrength, "REPRODUCED");
assert.equal(modelProof?.evidenceScope, "model");

const rpcCalls = [];
const rpc = async (method, params) => {
  rpcCalls.push([method, params]);
  if (method === "eth_blockNumber") return "0x64";
  if (method === "eth_call") return rpcCalls.filter(item => item[0] === "eth_call").length === 1 ? "0x01" : "0x00";
  if (method === "eth_sendTransaction") return "0xabc";
  return true;
};
const forkProof = await replayOnPinnedAnvil({ rpcUrl: "http://127.0.0.1:8545", blockNumber: 100, transactions: [{ from: "0x0000000000000000000000000000000000000001", to: "0x0000000000000000000000000000000000000002", data: "0x" }], invariant: { to: "0x0000000000000000000000000000000000000002", data: "0x1234", violation: "changed" }, invariantId: "balance-preserved" }, { rpc });
assert.equal(forkProof?.evidenceStrength, "REPRODUCED");
assert.equal(forkProof?.evidenceScope, "fork");
assert.equal(forkProof?.counterexample.blockNumber, 100);
await assert.rejects(replayOnPinnedAnvil({ rpcUrl: "https://mainnet.example", blockNumber: 100, transactions: [{ from: "a", to: "b" }], invariant: { to: "b", data: "0x", violation: "changed" }, invariantId: "x" }, { rpc }), /loopback/);

const verified = await runAnalysisPlan({ target: { type: "verified_source", chainId: 1, addressRef: "[contract-address]", sources: [{ name: "Protocol.sol", content: source }] }, engines: ["native", "foundry", "slither"], budget: DEFAULT_ANALYSIS_BUDGET });
assert.ok(verified.engines.some(item => item.engine === "foundry" && item.unavailableReason === "project-only engine"));
assert.ok(verified.engines.some(item => item.engine === "slither" && item.unavailableReason === "execution trust not confirmed"));
assert.ok(verified.protocol?.contracts.length);

console.log(`Proof analysis checks passed: ${report.graphs.length} closed CFGs, ${report.truncations.length} truncation record, ${model.contracts.length} protocol nodes, model and fork scoped reproduction evidence.`);
