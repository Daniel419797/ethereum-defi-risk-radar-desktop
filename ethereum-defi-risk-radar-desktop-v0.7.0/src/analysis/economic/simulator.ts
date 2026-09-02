export const DEFI_CATEGORIES = [
  "lending", "amm", "dex", "vault", "staking", "bridge", "governance",
  "derivatives", "stablecoin", "yield_aggregator", "token_wrapper", "liquidation"
] as const;

export type DefiCategory = typeof DEFI_CATEGORIES[number];
export type EconomicActor = { id: string; balances: Record<string, number>; debt: Record<string, number> };
export type EconomicPool = { id: string; category: DefiCategory; reserves: Record<string, number>; liabilities: Record<string, number>; feesAccrued: number };
export type EconomicState = { actors: Record<string, EconomicActor>; pools: Record<string, EconomicPool>; prices: Record<string, number>; step: number };
export type EconomicAction =
  | { type: "price_shock"; asset: string; multiplier: number }
  | { type: "transfer"; actor: string; pool: string; asset: string; amount: number }
  | { type: "borrow"; actor: string; pool: string; asset: string; amount: number }
  | { type: "repay"; actor: string; pool: string; asset: string; amount: number }
  | { type: "fee"; pool: string; asset: string; amount: number };
export type EconomicInvariant = { id: string; passed: boolean; actual: number; expectedMinimum: number; description: string };
export type EconomicSimulation = { finalState: EconomicState; invariants: EconomicInvariant[]; actorNetWorth: Record<string, number>; protocolSolvency: Record<string, number> };

function cloneState(state: EconomicState): EconomicState {
  return JSON.parse(JSON.stringify(state)) as EconomicState;
}

function finiteNonNegative(value: number, label: string) {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${label} must be finite and non-negative`);
}

function valueOf(amounts: Record<string, number>, prices: Record<string, number>) {
  return Object.entries(amounts).reduce((sum, [asset, amount]) => sum + amount * (prices[asset] ?? 0), 0);
}

export function simulateEconomicScenario(initial: EconomicState, actions: EconomicAction[], maxSteps = 10_000): EconomicSimulation {
  if (actions.length > maxSteps) throw new Error(`Simulation exceeds ${maxSteps} steps`);
  for (const [asset, price] of Object.entries(initial.prices)) finiteNonNegative(price, `price ${asset}`);
  for (const actor of Object.values(initial.actors)) {
    for (const [asset, amount] of Object.entries(actor.balances)) finiteNonNegative(amount, `actor balance ${asset}`);
    for (const [asset, amount] of Object.entries(actor.debt)) finiteNonNegative(amount, `actor debt ${asset}`);
  }
  for (const pool of Object.values(initial.pools)) {
    finiteNonNegative(pool.feesAccrued, `pool fees ${pool.id}`);
    for (const [asset, amount] of Object.entries(pool.reserves)) finiteNonNegative(amount, `pool reserve ${asset}`);
    for (const [asset, amount] of Object.entries(pool.liabilities)) finiteNonNegative(amount, `pool liability ${asset}`);
  }
  const state = cloneState(initial);
  for (const action of actions) {
    state.step += 1;
    if (action.type === "price_shock") {
      finiteNonNegative(action.multiplier, "price multiplier");
      if (!(action.asset in state.prices)) throw new Error(`Unknown asset: ${action.asset}`);
      state.prices[action.asset] *= action.multiplier;
      continue;
    }
    finiteNonNegative(action.amount, "action amount");
    const pool = state.pools[action.pool];
    if (!pool) throw new Error(`Unknown pool: ${action.pool}`);
    if (action.type === "fee") {
      pool.reserves[action.asset] = (pool.reserves[action.asset] ?? 0) + action.amount;
      pool.feesAccrued += action.amount * (state.prices[action.asset] ?? 0);
      continue;
    }
    const actor = state.actors[action.actor];
    if (!actor) throw new Error(`Unknown actor: ${action.actor}`);
    if (action.type === "transfer") {
      if ((actor.balances[action.asset] ?? 0) < action.amount) throw new Error("Insufficient actor balance");
      actor.balances[action.asset] -= action.amount;
      pool.reserves[action.asset] = (pool.reserves[action.asset] ?? 0) + action.amount;
    } else if (action.type === "borrow") {
      if ((pool.reserves[action.asset] ?? 0) < action.amount) throw new Error("Insufficient pool reserve");
      pool.reserves[action.asset] -= action.amount;
      pool.liabilities[action.asset] = (pool.liabilities[action.asset] ?? 0) + action.amount;
      actor.balances[action.asset] = (actor.balances[action.asset] ?? 0) + action.amount;
      actor.debt[action.asset] = (actor.debt[action.asset] ?? 0) + action.amount;
    } else {
      if ((actor.balances[action.asset] ?? 0) < action.amount || (actor.debt[action.asset] ?? 0) < action.amount) throw new Error("Invalid repayment");
      actor.balances[action.asset] -= action.amount;
      actor.debt[action.asset] -= action.amount;
      pool.reserves[action.asset] = (pool.reserves[action.asset] ?? 0) + action.amount;
      pool.liabilities[action.asset] = Math.max(0, (pool.liabilities[action.asset] ?? 0) - action.amount);
    }
  }

  const actorNetWorth = Object.fromEntries(Object.values(state.actors).map(actor => [actor.id, valueOf(actor.balances, state.prices) - valueOf(actor.debt, state.prices)]));
  const protocolSolvency = Object.fromEntries(Object.values(state.pools).map(pool => [pool.id, valueOf(pool.reserves, state.prices) - valueOf(pool.liabilities, state.prices)]));
  const invariants: EconomicInvariant[] = [
    ...Object.entries(protocolSolvency).map(([pool, value]) => ({ id: `solvency:${pool}`, passed: value >= 0, actual: value, expectedMinimum: 0, description: "Pool marked assets must cover marked liabilities." })),
    ...Object.values(state.actors).map(actor => {
      const minimum = -valueOf(actor.debt, state.prices);
      return { id: `finite-net-worth:${actor.id}`, passed: Number.isFinite(actorNetWorth[actor.id]), actual: actorNetWorth[actor.id], expectedMinimum: minimum, description: "Actor net worth must remain finite and accountable." };
    })
  ];
  return { finalState: state, invariants, actorNetWorth, protocolSolvency };
}
