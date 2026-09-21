import type { AnalysisFinding, ProtocolModel } from "../analysis/model.js";
import type { DefiInvariant, SelectedInvariant } from "./model.js";

export const DEFI_INVARIANTS: readonly DefiInvariant[] = [
  { id: "generic-no-unprotected-value-exit", title: "Privileged value exits remain authorized", category: "GENERIC", statement: "Any path that transfers protocol-controlled value through a privileged operation remains authorization-gated.", severityIfViolated: "CRITICAL", executionKinds: ["STRUCTURAL", "FUZZ", "PINNED_FORK"], applicableCategories: [], requiredSignals: ["authorization", "cross_contract_calls"], rationale: "Unprotected value-moving paths are a protocol-wide loss primitive.", source: "BUILT_IN" },
  { id: "generic-external-call-effects", title: "External calls preserve state-transition safety", category: "GENERIC", statement: "Externally reachable value-bearing or callback-capable calls cannot re-enter before critical accounting effects are committed.", severityIfViolated: "HIGH", executionKinds: ["STRUCTURAL", "FUZZ", "PINNED_FORK"], applicableCategories: [], requiredSignals: ["reentrancy", "cross_contract_calls"], rationale: "Checks-effects-interactions violations remain a common cross-protocol exploit primitive.", source: "BUILT_IN" },
  { id: "vault-share-conservation", title: "Vault share accounting conserves value", category: "VAULT", statement: "Deposits and redemptions cannot create disproportionate share claims through rounding, donation, or first-depositor state.", severityIfViolated: "CRITICAL", executionKinds: ["ECONOMIC_MODEL", "FUZZ", "PINNED_FORK"], applicableCategories: ["vault", "yield_aggregator"], rationale: "Share-price manipulation can externalize losses to later depositors.", source: "BUILT_IN" },
  { id: "vault-roundtrip-bound", title: "Vault round trips respect bounded loss", category: "VAULT", statement: "Deposit then redeem without external price movement cannot yield value above the configured fee/rounding bound.", severityIfViolated: "HIGH", executionKinds: ["ECONOMIC_MODEL", "FUZZ"], applicableCategories: ["vault", "yield_aggregator"], rationale: "A round-trip gain is evidence of accounting or rounding asymmetry.", source: "BUILT_IN" },
  { id: "lending-solvency", title: "Lending solvency gates value extraction", category: "LENDING", statement: "Borrowing and collateral withdrawal cannot leave an account below required solvency while value is extracted.", severityIfViolated: "CRITICAL", executionKinds: ["ECONOMIC_MODEL", "FUZZ", "PINNED_FORK"], applicableCategories: ["lending", "liquidation"], rationale: "Solvency enforcement is the core conservation property of lending markets.", source: "BUILT_IN" },
  { id: "lending-liquidation-health", title: "Liquidation respects health state", category: "LIQUIDATION", statement: "Healthy positions cannot be profitably liquidated and unhealthy positions cannot escape required debt/collateral accounting.", severityIfViolated: "HIGH", executionKinds: ["ECONOMIC_MODEL", "FUZZ", "PINNED_FORK"], applicableCategories: ["lending", "liquidation"], rationale: "Liquidation edge cases often combine oracle, rounding and bad-debt errors.", source: "BUILT_IN" },
  { id: "amm-reserve-accounting", title: "AMM reserve accounting remains coherent", category: "AMM", statement: "Token balance transitions, internal reserves, LP accounting and fee accounting remain coherent after swaps, joins, exits and callbacks.", severityIfViolated: "CRITICAL", executionKinds: ["ECONOMIC_MODEL", "FUZZ", "PINNED_FORK"], applicableCategories: ["amm", "dex"], rationale: "Reserve desynchronization enables repeated extraction and mispricing.", source: "BUILT_IN" },
  { id: "dex-slippage-deadline", title: "Swap execution honors user price bounds", category: "DEX", statement: "Externally submitted swaps cannot bypass caller-defined minimum output, maximum input or expiry constraints.", severityIfViolated: "HIGH", executionKinds: ["STRUCTURAL", "FUZZ"], applicableCategories: ["dex", "amm"], requiredSignals: ["mev_ordering"], rationale: "Missing execution bounds convert ordinary ordering risk into deterministic user loss.", source: "BUILT_IN" },
  { id: "oracle-freshness-consistency", title: "Oracle observations are fresh and normalized", category: "GENERIC", statement: "Security-critical price reads enforce freshness, valid answers and consistent decimal normalization before value-moving decisions.", severityIfViolated: "HIGH", executionKinds: ["STRUCTURAL", "STATE_SNAPSHOT", "FUZZ"], applicableCategories: ["lending", "vault", "stablecoin", "derivatives", "liquidation"], requiredSignals: ["oracle_risk"], rationale: "Stale or mis-scaled prices corrupt collateral, share and liquidation calculations.", source: "BUILT_IN" },
  { id: "bridge-message-once", title: "Bridge messages execute at most once", category: "BRIDGE", statement: "A cross-domain message is bound to its source domain/sender and cannot be replayed after successful consumption.", severityIfViolated: "CRITICAL", executionKinds: ["STRUCTURAL", "FUZZ", "PINNED_FORK"], applicableCategories: ["bridge"], requiredSignals: ["bridge_messaging", "signature_replay"], rationale: "Replay and domain-confusion failures can duplicate privileged cross-chain actions.", source: "BUILT_IN" },
  { id: "governance-authority-path", title: "Governance authority follows the declared delay path", category: "GOVERNANCE", statement: "Governance-controlled upgrades and privileged actions cannot bypass quorum, snapshot and timelock constraints.", severityIfViolated: "CRITICAL", executionKinds: ["STRUCTURAL", "STATE_SNAPSHOT", "PINNED_FORK"], applicableCategories: ["governance"], requiredSignals: ["governance_risk", "authorization"], rationale: "Bypassing the governance path turns distributed control into unilateral privilege.", source: "BUILT_IN" },
  { id: "upgrade-storage-continuity", title: "Upgrades preserve storage semantics", category: "UPGRADEABILITY", statement: "A new implementation does not reinterpret or collide with live proxy storage and does not remove required initialization or authorization guards.", severityIfViolated: "CRITICAL", executionKinds: ["STRUCTURAL", "STATE_SNAPSHOT"], applicableCategories: [], requiredSignals: ["upgradeability", "storage_state"], rationale: "Storage-layout corruption can permanently compromise proxy state at upgrade time.", source: "BUILT_IN" },
  { id: "stablecoin-backing", title: "Stablecoin liabilities remain backed by declared accounting", category: "STABLECOIN", statement: "Minting and redemption cannot increase circulating liabilities without the protocol's declared backing or debt accounting transition.", severityIfViolated: "CRITICAL", executionKinds: ["ECONOMIC_MODEL", "FUZZ", "PINNED_FORK"], applicableCategories: ["stablecoin"], rationale: "Unbacked mint paths directly violate the monetary invariant.", source: "BUILT_IN" },
  { id: "staking-reward-conservation", title: "Staking rewards cannot be claimed twice", category: "STAKING", statement: "Reward entitlement decreases or checkpoints atomically so repeated claims cannot exceed accrued rewards.", severityIfViolated: "HIGH", executionKinds: ["ECONOMIC_MODEL", "FUZZ"], applicableCategories: ["staking"], rationale: "Checkpoint and claim-order bugs are a repeated staking/reward failure mode.", source: "BUILT_IN" }
] as const;

function findingSignals(findings: AnalysisFinding[]) {
  return new Set(findings.map(finding => finding.kind));
}

export function selectDefiInvariants(model: ProtocolModel, findings: AnalysisFinding[] = []): SelectedInvariant[] {
  const categories = new Set(model.categories);
  const signals = findingSignals(findings);
  const selected: SelectedInvariant[] = [];

  for (const invariant of DEFI_INVARIANTS) {
    const categoryMatches = invariant.applicableCategories.length === 0 || invariant.applicableCategories.some(category => categories.has(category));
    const signalMatches = (invariant.requiredSignals ?? []).some(signal => signals.has(signal as AnalysisFinding["kind"]));
    if (!categoryMatches && !signalMatches) continue;
    const rationale: string[] = [];
    if (invariant.applicableCategories.some(category => categories.has(category))) rationale.push("protocol category match");
    if (signalMatches) rationale.push("security-signal match");
    if (invariant.applicableCategories.length === 0 && signalMatches) rationale.push("cross-protocol invariant");
    if (!rationale.length && invariant.applicableCategories.length === 0) continue;
    selected.push({
      invariant,
      confidence: rationale.includes("protocol category match") && signalMatches ? "HIGH" : rationale.includes("protocol category match") ? "MEDIUM" : "LOW",
      rationale
    });
  }

  return selected.sort((a, b) => a.invariant.id.localeCompare(b.invariant.id));
}
