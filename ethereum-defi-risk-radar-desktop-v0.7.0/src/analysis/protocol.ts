import { createHash } from "node:crypto";
import { finalizeFinding } from "./evidence.js";
import type { AnalysisFinding, ProtocolCallEdge, ProtocolContractNode, ProtocolModel } from "./model.js";
import type { SoliditySourceFile } from "./native/analyzer.js";
import { ECONOMIC_SCENARIO_PACKS } from "./economic/scenarios.js";
import { simulateEconomicScenario, type DefiCategory, type EconomicAction, type EconomicState } from "./economic/simulator.js";

const CONTRACT_RE = /\b(contract|interface|library)\s+([A-Za-z_$][\w$]*)[^\{]*\{/g;
const TYPED_TARGET_RE = /\b([A-Z][A-Za-z0-9_$]*)\s+(?:public\s+|private\s+|internal\s+)?([a-zA-Z_$][\w$]*)\s*(?:[;=])/g;
const ASSET_RE = /\b(?:IERC20|ERC20|IERC4626)\s+(?:(?:public|private|internal|immutable)\s+)*([A-Za-z_$][\w$]*)|\b(?:IERC20|ERC20|IERC4626)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g;

function category(text: string): DefiCategory {
  const rules: Array<[RegExp, DefiCategory]> = [
    [/lend|borrow|collateral/i, "lending"], [/amm|pair|liquidity|reserve/i, "amm"], [/swap|router|exchange/i, "dex"],
    [/vault|4626|share/i, "vault"], [/stake|reward/i, "staking"], [/bridge|message/i, "bridge"],
    [/govern|vote|quorum/i, "governance"], [/perp|option|derivative|funding/i, "derivatives"],
    [/stable|peg|mint/i, "stablecoin"], [/yield|strategy|harvest/i, "yield_aggregator"],
    [/wrapper|wrapped/i, "token_wrapper"], [/liquidat/i, "liquidation"]
  ];
  return rules.find(([pattern]) => pattern.test(text))?.[1] ?? "vault";
}

function lineAt(content: string, index: number) { return content.slice(0, index).split("\n").length; }

export function buildProtocolModel(files: SoliditySourceFile[], findings: AnalysisFinding[] = []): ProtocolModel {
  const contracts: ProtocolContractNode[] = []; const calls: ProtocolCallEdge[] = []; const assets = new Set<string>();
  const variableTypes = new Map<string, string>();
  for (const file of files) {
    for (const match of file.content.matchAll(CONTRACT_RE)) {
      const name = match[2];
      contracts.push({ id: `${file.name}:${name}`, name, file: file.name, kind: match[1] as ProtocolContractNode["kind"], category: category(`${name} ${file.content}`), storageVariables: findings.filter(item => item.primaryLocation?.file === file.name && item.kind === "storage_state").map(item => item.title) });
    }
    for (const match of file.content.matchAll(TYPED_TARGET_RE)) variableTypes.set(match[2], match[1]);
    for (const match of file.content.matchAll(ASSET_RE)) assets.add(match[1] || match[2]);
  }
  for (const file of files) for (const match of file.content.matchAll(/([A-Za-z_$][\w$]*)\.(call|delegatecall|staticcall|transfer|send|[A-Za-z_$][\w$]*)\s*\(/g)) {
    const target = match[1]; const resolvedType = variableTypes.get(target); const callee = contracts.find(item => item.name === resolvedType); const source = contracts.find(item => item.file === file.name);
    if (source) calls.push({ from: source.id, to: callee?.id, targetExpression: target, operation: match[2], location: { file: file.name, line: lineAt(file.content, match.index ?? 0) }, resolved: Boolean(callee) });
  }
  return { contracts, calls, assets: [...assets].sort(), categories: [...new Set(contracts.map(item => item.category))].sort(), unresolvedCallCount: calls.filter(item => !item.resolved).length, assumptions: ["Contract links are resolved from declared Solidity types; dynamic addresses and assembly calls remain unresolved.", "Economic values require explicit observations or pinned fork state; source text alone does not establish balances."] };
}

export type ProtocolObservations = { prices: Record<string, number>; pools: Record<string, { reserves: Record<string, number>; liabilities: Record<string, number> }>; actor: { id: string; balances: Record<string, number>; debt: Record<string, number> } };
export type ProtocolScenarioResult = { scenarioId: string; state: "complete" | "skipped"; reason?: string; finding?: AnalysisFinding };

function scenarioActions(id: string, state: EconomicState): EconomicAction[] {
  const asset = Object.keys(state.prices)[0]; const pool = Object.keys(state.pools)[0]; const actor = Object.keys(state.actors)[0];
  if (!asset || !pool || !actor) return [];
  const reserve = state.pools[pool].reserves[asset] ?? 0; const balance = state.actors[actor].balances[asset] ?? 0;
  if (id === "oracle-price-shock" || id === "funding-liquidation-cascade") return [{ type: "price_shock", asset, multiplier: 0.5 }];
  if (id === "flash-liquidity-composition" && reserve > 0) return [{ type: "borrow", actor, pool, asset, amount: reserve * 0.1 }];
  if (id === "liquidity-run" && balance > 0) return [{ type: "transfer", actor, pool, asset, amount: balance * 0.5 }, { type: "price_shock", asset, multiplier: 0.5 }];
  if (["rounding-donation", "cross-domain-replay", "mev-ordering"].includes(id) && balance > 0) return [{ type: "transfer", actor, pool, asset, amount: balance * 0.1 }];
  return [];
}

export function runProtocolScenarios(model: ProtocolModel, observations: ProtocolObservations, seed = 1): ProtocolScenarioResult[] {
  const numericValues = [
    ...Object.values(observations.prices ?? {}),
    ...Object.values(observations.pools ?? {}).flatMap(pool => [...Object.values(pool.reserves ?? {}), ...Object.values(pool.liabilities ?? {})]),
    ...Object.values(observations.actor?.balances ?? {}), ...Object.values(observations.actor?.debt ?? {})
  ];
  if (!observations.actor?.id || numericValues.some(value => !Number.isFinite(value) || value < 0)) throw new Error("Protocol observations require an actor id and finite non-negative numeric values");
  const poolEntries = Object.entries(observations.pools).filter(([id]) => model.contracts.some(contract => contract.name === id || contract.id === id));
  if (!poolEntries.length || !Object.keys(observations.prices).length) return ECONOMIC_SCENARIO_PACKS.map(pack => ({ scenarioId: pack.id, state: "skipped", reason: "Protocol-linked pool observations and prices are required." }));
  const state: EconomicState = { step: 0, prices: observations.prices, actors: { [observations.actor.id]: observations.actor }, pools: Object.fromEntries(poolEntries.map(([id, value]) => { const contract = model.contracts.find(item => item.name === id || item.id === id)!; return [id, { id, category: contract.category as DefiCategory, reserves: value.reserves, liabilities: value.liabilities, feesAccrued: 0 }]; })) };
  const baseline = simulateEconomicScenario(state, []);
  return ECONOMIC_SCENARIO_PACKS.filter(pack => pack.categories.some(item => model.categories.includes(item))).map(pack => {
    const actions = scenarioActions(pack.id, state); if (!actions.length) return { scenarioId: pack.id, state: "skipped", reason: "No valid protocol-derived action sequence could be formed." };
    const simulation = simulateEconomicScenario(state, actions); const failed = simulation.invariants.find(item => !item.passed && baseline.invariants.find(before => before.id === item.id)?.passed);
    if (!failed) return { scenarioId: pack.id, state: "complete" };
    const sequence = actions.map(action => JSON.stringify(action));
    const finding = finalizeFinding({ id: createHash("sha256").update(`${pack.id}:${sequence.join("|")}`).digest("hex").slice(0, 16), kind: "economic_simulation", engine: "native", severity: "HIGH", evidenceStrength: "REPRODUCED", evidenceScope: "model", title: `${pack.name}: ${failed.id} violated`, description: `${failed.description} Actual ${failed.actual}; required minimum ${failed.expectedMinimum}.`, counterexample: { engine: "native", scope: "model", sequence, observedViolation: `${failed.id}: ${failed.actual} < ${failed.expectedMinimum}`, invariantId: failed.id, seed } });
    return { scenarioId: pack.id, state: "complete", finding };
  });
}
