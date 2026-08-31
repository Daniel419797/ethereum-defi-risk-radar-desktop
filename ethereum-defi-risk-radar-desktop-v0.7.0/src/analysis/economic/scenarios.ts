import type { DefiCategory, EconomicAction } from "./simulator.js";

export type EconomicScenarioPack = {
  id: string;
  name: string;
  categories: DefiCategory[];
  description: string;
  requiredState: string[];
  actions: EconomicAction["type"][];
  invariants: string[];
};

export const ECONOMIC_SCENARIO_PACKS: EconomicScenarioPack[] = [
  { id: "oracle-price-shock", name: "Oracle and spot-price shock", categories: ["lending", "amm", "dex", "vault", "derivatives", "stablecoin", "liquidation"], description: "Reprice collateral and liquidity to expose bad debt, unfair shares, or liquidation discontinuities.", requiredState: ["prices", "reserves", "positions"], actions: ["price_shock", "borrow"], invariants: ["solvency", "bounded-profit", "collateralization"] },
  { id: "flash-liquidity-composition", name: "Atomic flash-liquidity composition", categories: ["lending", "amm", "dex", "vault", "yield_aggregator", "liquidation"], description: "Compose temporary liquidity with swaps, accounting updates, and repayment.", requiredState: ["reserves", "fees", "actor-balances"], actions: ["borrow", "transfer", "fee", "repay"], invariants: ["asset-conservation", "fee-payment", "bounded-profit"] },
  { id: "liquidity-run", name: "Liquidity withdrawal and insolvency run", categories: ["lending", "amm", "vault", "staking", "stablecoin", "token_wrapper"], description: "Stress simultaneous withdrawals and impaired backing.", requiredState: ["reserves", "liabilities"], actions: ["transfer", "price_shock"], invariants: ["solvency", "withdrawal-liveness", "share-accounting"] },
  { id: "governance-capture", name: "Governance power and execution capture", categories: ["governance", "bridge", "lending", "vault", "stablecoin"], description: "Stress temporary voting power, quorum, delay, and privileged execution.", requiredState: ["governance-power", "timelock"], actions: ["borrow", "transfer", "repay"], invariants: ["quorum-snapshot", "execution-delay", "privilege-boundary"] },
  { id: "cross-domain-replay", name: "Cross-domain delay and replay", categories: ["bridge", "token_wrapper"], description: "Model duplicate, delayed, reordered, or invalid-origin messages.", requiredState: ["message-nonces", "wrapped-supply"], actions: ["transfer"], invariants: ["single-execution", "supply-conservation", "origin-authentication"] },
  { id: "rounding-donation", name: "Rounding, inflation, and donation", categories: ["vault", "staking", "yield_aggregator", "token_wrapper"], description: "Stress first-depositor, donation, rounding-direction, and share-price discontinuities.", requiredState: ["shares", "assets"], actions: ["transfer"], invariants: ["share-monotonicity", "bounded-rounding", "redeemability"] },
  { id: "funding-liquidation-cascade", name: "Funding and liquidation cascade", categories: ["derivatives", "lending", "liquidation", "stablecoin"], description: "Reprice positions and recursively apply liquidation losses.", requiredState: ["positions", "prices", "insurance-fund"], actions: ["price_shock", "fee"], invariants: ["bounded-bad-debt", "insurance-solvency", "position-accounting"] },
  { id: "mev-ordering", name: "Transaction ordering and sandwich stress", categories: ["amm", "dex", "lending", "liquidation"], description: "Compare victim outcomes under adversarial ordering and liquidity changes.", requiredState: ["reserves", "fees"], actions: ["transfer", "fee"], invariants: ["slippage-bound", "deadline", "bounded-extraction"] }
];

export function scenariosForCategory(category: DefiCategory) {
  return ECONOMIC_SCENARIO_PACKS.filter(pack => pack.categories.includes(category));
}
