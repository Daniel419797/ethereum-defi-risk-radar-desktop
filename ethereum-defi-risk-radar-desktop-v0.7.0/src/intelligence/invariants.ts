import type {
  AnalysisFinding,
  EvidenceStrength
} from "../analysis/model.js";
import type {
  EvidenceEscalationPlan,
  EvidenceEscalationStep,
  InvariantApplicability,
  InvariantCategory,
  InvariantDefinition,
  ProtocolKnowledgeGraph
} from "./model.js";

export const DEFI_INVARIANT_LIBRARY: readonly InvariantDefinition[] = [
  {
    id: "vault.share-accounting-conservation",
    title: "Vault share accounting remains economically conservative",
    description: "Deposits, mints, withdrawals and redemptions must not create redeemable value through rounding, donation, or first-depositor price manipulation.",
    categories: ["vault", "yield_aggregator"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "ECONOMIC", "FUZZ", "FORK_REPLAY"],
    rationale: "Share-price discontinuities and asymmetric rounding are a recurring source of ERC-4626 and vault losses.",
    remediationHint: "Use conservative rounding, virtual shares/assets or equivalent anti-inflation defenses, and invariant-test deposit/redeem round trips.",
    sourceKinds: ["arithmetic_precision", "token_integration", "economic_simulation"],
    generatedProperty: "For bounded honest deposit/redeem round trips, attacker-owned assets must not increase beyond configured fees/yield and totalAssets/share accounting must remain internally consistent."
  },
  {
    id: "vault.first-depositor-donation-resistance",
    title: "First depositor cannot capture donated assets disproportionately",
    description: "An attacker must not be able to manipulate initial exchange rates or donations so later depositors receive materially fewer shares.",
    categories: ["vault", "yield_aggregator"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "ECONOMIC", "FUZZ", "FORK_REPLAY"],
    rationale: "Empty-vault exchange-rate manipulation can convert rounding into a value-transfer primitive.",
    remediationHint: "Use virtual assets/shares or minimum-liquidity defenses and explicitly test donation/front-run sequences.",
    sourceKinds: ["arithmetic_precision", "mev_ordering", "token_integration"],
    generatedProperty: "For an empty or near-empty vault, arbitrary donations before a victim deposit must not let an attacker redeem more value than contributed plus permitted yield."
  },
  {
    id: "lending.solvency-preservation",
    title: "Borrowing and withdrawal preserve protocol solvency",
    description: "Debt creation and collateral withdrawal must preserve collateralization and protocol accounting constraints.",
    categories: ["lending", "liquidation"],
    severity: "CRITICAL",
    checks: ["STRUCTURAL", "STATE", "ECONOMIC", "FUZZ", "FORK_REPLAY"],
    rationale: "Incorrect debt, collateral, decimal, or price accounting can turn a local calculation error into protocol insolvency.",
    remediationHint: "Centralize normalized valuation, enforce post-state health checks, and invariant-test debt/collateral conservation across all entry points.",
    sourceKinds: ["oracle_risk", "arithmetic_precision", "token_integration", "economic_simulation"],
    generatedProperty: "After every borrow/withdraw sequence, each account and the aggregate protocol must satisfy the configured collateralization and debt-accounting constraints."
  },
  {
    id: "lending.liquidation-health-boundary",
    title: "Liquidations respect the health boundary",
    description: "Healthy accounts must not be liquidatable and unhealthy accounts must not bypass liquidation or create unbounded bad debt.",
    categories: ["lending", "liquidation"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "STATE", "ECONOMIC", "FUZZ", "FORK_REPLAY"],
    rationale: "Boundary, rounding and stale-price errors can invert liquidation eligibility.",
    remediationHint: "Use one canonical health-factor implementation, conservative rounding and fresh prices; fuzz values around exact liquidation thresholds.",
    sourceKinds: ["oracle_risk", "arithmetic_precision", "economic_simulation"],
    generatedProperty: "Liquidation eligibility must be monotonic around the configured health threshold and settlement must not increase system bad debt unexpectedly."
  },
  {
    id: "oracle.freshness-and-normalization",
    title: "Oracle prices are fresh, normalized and manipulation-resistant",
    description: "Security-sensitive valuation must reject stale/invalid data and normalize decimals consistently before use.",
    categories: ["lending", "vault", "amm", "dex", "stablecoin", "derivatives", "liquidation", "generic"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "STATE", "FUZZ", "FORK_REPLAY"],
    rationale: "Price freshness, decimal and source-selection mistakes can compromise every downstream solvency decision.",
    remediationHint: "Validate answer bounds, timestamps/round completion, decimal scaling and fallback behavior; prefer manipulation-resistant aggregation.",
    sourceKinds: ["oracle_risk", "arithmetic_precision"],
    requiredGraphKinds: ["oracle"],
    generatedProperty: "Every security-sensitive price read must satisfy freshness, positivity/completeness and decimal-normalization constraints before affecting state."
  },
  {
    id: "amm.reserve-accounting-conservation",
    title: "AMM reserve accounting remains synchronized",
    description: "Swaps, liquidity changes, fee collection and callbacks must preserve the pool's reserve/accounting invariant.",
    categories: ["amm", "dex"],
    severity: "CRITICAL",
    checks: ["STRUCTURAL", "STATE", "ECONOMIC", "FUZZ", "FORK_REPLAY"],
    rationale: "Balance/reserve divergence and callback accounting defects can enable repeated extraction.",
    remediationHint: "Check post-callback balances, account for fee-on-transfer/rebasing tokens, and invariant-test reserve conservation over transaction sequences.",
    sourceKinds: ["token_integration", "reentrancy", "arithmetic_precision", "economic_simulation"],
    generatedProperty: "After every successful swap/liquidity/callback sequence, recorded reserves and actual balances must satisfy the protocol's invariant and fee rules."
  },
  {
    id: "bridge.message-single-consumption",
    title: "Cross-domain messages are authenticated and consumed once",
    description: "Message origin, source domain, sender and nonce must be bound so an accepted message cannot be replayed.",
    categories: ["bridge"],
    severity: "CRITICAL",
    checks: ["STRUCTURAL", "STATE", "FUZZ", "SYMBOLIC", "FORK_REPLAY"],
    rationale: "Replay or domain-binding failures can turn one authorized message into repeated mint/unlock actions.",
    remediationHint: "Bind chain/domain and sender into the signed/verified message identity and mark message hashes/nonces consumed before external effects.",
    sourceKinds: ["bridge_messaging", "signature_replay", "authorization"],
    generatedProperty: "A successfully consumed cross-domain message must fail on every subsequent replay and must fail when source domain or authenticated sender changes."
  },
  {
    id: "governance.delay-and-authority",
    title: "Privileged changes obey intended governance delay and authority",
    description: "Upgrade, pause, parameter and treasury powers must not bypass the protocol's intended authorization and delay model.",
    categories: ["governance", "generic"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "STATE", "FUZZ", "FORK_REPLAY"],
    rationale: "Administrative shortcuts can invalidate otherwise strong contract-level controls.",
    remediationHint: "Route sensitive changes through explicit role separation, multisig/timelock governance and test unauthorized/direct-call paths.",
    sourceKinds: ["governance_risk", "authorization", "upgradeability"],
    requiredGraphKinds: ["governance"],
    generatedProperty: "No sensitive state transition or implementation change may succeed without the configured authority and delay conditions."
  },
  {
    id: "upgrade.storage-layout-compatibility",
    title: "Upgradeable storage layout remains compatible",
    description: "Implementation changes must not reinterpret occupied proxy storage or collide with standardized proxy slots.",
    categories: ["generic"],
    severity: "CRITICAL",
    checks: ["STRUCTURAL", "STATE"],
    rationale: "Storage corruption can silently transfer authority or destroy accounting after an otherwise authorized upgrade.",
    remediationHint: "Compare authoritative compiler storage layouts when available, preserve variable order/types, use namespaced storage deliberately, and test upgrade migrations.",
    sourceKinds: ["upgradeability", "storage_state"],
    generatedProperty: "Every occupied storage location retains compatible semantics across implementation versions and no implementation variable overlaps proxy control slots."
  },
  {
    id: "token.actual-received-accounting",
    title: "Token accounting uses actual received value where required",
    description: "Accounting must tolerate fee-on-transfer, rebasing, false-return and other non-standard token behavior when such assets are supported.",
    categories: ["vault", "lending", "amm", "dex", "staking", "yield_aggregator", "token_wrapper", "generic"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "FUZZ", "FORK_REPLAY"],
    rationale: "Assuming transfer amount equals balance delta can mint claims against assets the protocol never received.",
    remediationHint: "Use safe transfer wrappers and measure balance deltas when protocol semantics require actual-received accounting.",
    sourceKinds: ["token_integration"],
    generatedProperty: "Credited deposits and reserves must never exceed the value actually received from supported token transfers."
  },
  {
    id: "signature.domain-and-nonce-replay",
    title: "Signed authorization is domain-separated and single-use",
    description: "Permit/meta-transaction signatures must be bound to the correct domain and nonce and must not replay across chains, contracts or upgrades.",
    categories: ["generic"],
    severity: "HIGH",
    checks: ["STRUCTURAL", "STATE", "FUZZ", "SYMBOLIC", "FORK_REPLAY"],
    rationale: "Weak domain separation or nonce handling can convert a valid signature into reusable authority.",
    remediationHint: "Use EIP-712 domain separation, monotonic/non-reusable nonces, expiry checks and explicit chain/contract binding.",
    sourceKinds: ["signature_replay", "authorization"],
    generatedProperty: "After a signed authorization succeeds once, the identical authorization must fail and must also fail under a different domain, chain or verifying contract."
  }
] as const;

const CATEGORY_SET = new Set<string>([
  "vault", "lending", "amm", "dex", "staking", "bridge", "governance",
  "stablecoin", "derivatives", "yield_aggregator", "token_wrapper", "liquidation"
]);

function normalizedCategories(graph: ProtocolKnowledgeGraph): Set<InvariantCategory> {
  const categories = new Set<InvariantCategory>();
  for (const value of graph.categories) {
    if (CATEGORY_SET.has(value)) categories.add(value as InvariantCategory);
  }
  if (!categories.size) categories.add("generic");
  return categories;
}

function invariantReasons(
  definition: InvariantDefinition,
  graph: ProtocolKnowledgeGraph,
  findings: AnalysisFinding[]
) {
  const categories = normalizedCategories(graph);
  const reasons: string[] = [];
  const categoryMatch =
    definition.categories.includes("generic") ||
    definition.categories.some(category => categories.has(category));
  if (categoryMatch) reasons.push(`Protocol categories: ${[...categories].join(", ")}`);

  const graphKinds = new Set(graph.nodes.map(node => node.kind));
  const graphMatch =
    !definition.requiredGraphKinds?.length ||
    definition.requiredGraphKinds.every(kind => graphKinds.has(kind));
  if (graphMatch && definition.requiredGraphKinds?.length) {
    reasons.push(`Knowledge graph contains: ${definition.requiredGraphKinds.join(", ")}`);
  }

  const findingMatch = findings.some(finding => definition.sourceKinds.includes(finding.kind));
  if (findingMatch) {
    const kinds = [...new Set(findings.filter(f => definition.sourceKinds.includes(f.kind)).map(f => f.kind))];
    reasons.push(`Source findings: ${kinds.join(", ")}`);
  }

  const applicable = categoryMatch && graphMatch && (findingMatch || definition.categories.some(category => categories.has(category)));
  return { applicable, reasons };
}

export function evaluateInvariantApplicability(
  graph: ProtocolKnowledgeGraph,
  findings: AnalysisFinding[]
): InvariantApplicability[] {
  return DEFI_INVARIANT_LIBRARY.map(definition => {
    const result = invariantReasons(definition, graph, findings);
    const refs = new Set<string>();
    if (result.applicable) {
      for (const node of graph.nodes) {
        if (node.contractRefId && (
          node.kind === "contract" ||
          node.kind === "proxy" ||
          node.kind === "implementation" ||
          definition.requiredGraphKinds?.includes(node.kind)
        )) refs.add(node.contractRefId);
      }
    }
    return {
      invariantId: definition.id,
      state: result.applicable ? "APPLICABLE" : "NOT_APPLICABLE",
      reasons: result.reasons,
      contractRefIds: [...refs].slice(0, 64),
      confidence:
        result.reasons.length >= 2 ? "HIGH" :
        result.reasons.length === 1 ? "MEDIUM" : "LOW"
    };
  });
}

const EVIDENCE_RANK: Record<EvidenceStrength, number> = {
  HEURISTIC: 0,
  STRUCTURAL: 1,
  EXECUTED: 2,
  REPRODUCED: 3
};

function relatedInvariants(finding: AnalysisFinding, applicability: InvariantApplicability[]) {
  return DEFI_INVARIANT_LIBRARY
    .filter(definition =>
      definition.sourceKinds.includes(finding.kind) &&
      applicability.find(item => item.invariantId === definition.id)?.state === "APPLICABLE"
    )
    .map(definition => definition.id);
}

function strongestEvidence(findings: AnalysisFinding[]) {
  return findings.reduce<EvidenceStrength>(
    (strongest, finding) =>
      EVIDENCE_RANK[finding.evidenceStrength] > EVIDENCE_RANK[strongest]
        ? finding.evidenceStrength
        : strongest,
    "HEURISTIC"
  );
}

function escalationSteps(
  finding: AnalysisFinding,
  invariantIds: string[],
  strongest: EvidenceStrength
): EvidenceEscalationStep[] {
  const definitions = DEFI_INVARIANT_LIBRARY.filter(item => invariantIds.includes(item.id));
  const checkKinds = new Set(definitions.flatMap(item => item.checks));
  const steps: EvidenceEscalationStep[] = [];
  let order = 1;

  if (EVIDENCE_RANK[strongest] < EVIDENCE_RANK.STRUCTURAL) {
    steps.push({
      order: order++,
      stage: "STRUCTURAL",
      engine: "native",
      automatic: true,
      requiresTrust: false,
      requiresRpc: false,
      description: "Resolve external reachability, data dependencies, dominating guards, storage effects and cross-contract edges.",
      successEvidence: "STRUCTURAL"
    });
  }

  if (checkKinds.has("FUZZ") && EVIDENCE_RANK[strongest] < EVIDENCE_RANK.EXECUTED) {
    steps.push({
      order: order++,
      stage: "FUZZ",
      engine: "echidna",
      automatic: true,
      requiresTrust: true,
      requiresRpc: false,
      description: "Generate a bounded property harness from the applicable DeFi invariant and search transaction sequences for a concrete counterexample.",
      successEvidence: "EXECUTED"
    });
  }

  if (checkKinds.has("SYMBOLIC") && EVIDENCE_RANK[strongest] < EVIDENCE_RANK.EXECUTED) {
    steps.push({
      order: order++,
      stage: "SYMBOLIC",
      engine: "mythril",
      automatic: true,
      requiresTrust: true,
      requiresRpc: false,
      description: "Run bounded symbolic exploration focused on the finding sink and invariant preconditions; retain only concrete counterexample artifacts.",
      successEvidence: "EXECUTED"
    });
  }

  if (finding.counterexample && finding.counterexample.scope === "model" && strongest !== "REPRODUCED") {
    steps.push({
      order: order++,
      stage: "MODEL_REPLAY",
      engine: "foundry",
      automatic: true,
      requiresTrust: true,
      requiresRpc: false,
      description: "Replay the captured sequence deterministically in a local model/test harness before escalating to fork evidence.",
      successEvidence: "REPRODUCED"
    });
  }

  if (checkKinds.has("FORK_REPLAY") && finding.exploitabilityVerdict !== "CONFIRMED_AT_PINNED_BLOCK") {
    steps.push({
      order: order++,
      stage: "FORK_REPLAY",
      engine: "anvil",
      automatic: false,
      requiresTrust: true,
      requiresRpc: true,
      description: "Replay the bounded counterexample against explicitly pinned Ethereum Mainnet state and confirm block hash, receipts and invariant observation.",
      successEvidence: "CONFIRMED_AT_PINNED_BLOCK"
    });
  }

  if (checkKinds.has("ECONOMIC")) {
    steps.push({
      order: order++,
      stage: "ECONOMIC_IMPACT",
      automatic: true,
      requiresTrust: false,
      requiresRpc: false,
      description: "Estimate protocol-level impact under bounded observed balances, liquidity, prices and liabilities without upgrading exploitability evidence.",
      successEvidence: strongest
    });
  }

  return steps;
}

function correlationKey(finding: AnalysisFinding) {
  return [
    finding.kind,
    finding.primaryLocation?.file ?? "",
    finding.primaryLocation?.line ?? 0
  ].join("|");
}

export function buildEvidenceEscalationPlans(
  findings: AnalysisFinding[],
  applicability: InvariantApplicability[]
): EvidenceEscalationPlan[] {
  const groups = new Map<string, AnalysisFinding[]>();
  for (const finding of findings) {
    const key = correlationKey(finding);
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }

  const plans: EvidenceEscalationPlan[] = [];
  for (const group of groups.values()) {
    const primary = [...group].sort((a, b) =>
      EVIDENCE_RANK[b.evidenceStrength] - EVIDENCE_RANK[a.evidenceStrength]
    )[0];
    const invariantIds = relatedInvariants(primary, applicability);
    const strongest = strongestEvidence(group);
    const engines = [...new Set(group.map(finding => finding.engine))];

    plans.push({
      findingId: primary.id,
      invariantIds,
      currentEvidence: primary.evidenceStrength,
      strongestEvidence: strongest,
      correlatedEngines: engines,
      steps: escalationSteps(primary, invariantIds, strongest),
      stoppedReason:
        primary.exploitabilityVerdict === "CONFIRMED_AT_PINNED_BLOCK"
          ? "Finding is already confirmed at the recorded pinned block; further automatic escalation is unnecessary."
          : undefined
    });
  }

  return plans.sort((a, b) =>
    EVIDENCE_RANK[b.strongestEvidence] - EVIDENCE_RANK[a.strongestEvidence]
  );
}

export function correlateFindingEvidence(findings: AnalysisFinding[]) {
  const groups = new Map<string, AnalysisFinding[]>();
  for (const finding of findings) {
    const key = correlationKey(finding);
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }

  return findings.map(finding => {
    const peers = groups.get(correlationKey(finding)) ?? [finding];
    const correlatedEngines = [...new Set(peers.map(item => item.engine))];
    const confidence =
      correlatedEngines.length >= 2 && finding.confidence !== "HIGH"
        ? "HIGH"
        : finding.confidence;
    return {
      ...finding,
      confidence,
      correlatedEngines
    };
  });
}
