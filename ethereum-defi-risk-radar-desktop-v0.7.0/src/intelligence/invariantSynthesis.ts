import { createHash } from "node:crypto";
import type {
  AnalysisFinding,
  AnalysisGraph,
  CrossContractCall,
  ProtocolModel,
  StorageSurface
} from "../analysis/model.js";

export type SynthesizedInvariantKind =
  | "SOLVENCY"
  | "ASSET_CONSERVATION"
  | "SHARE_ACCOUNTING"
  | "AUTHORITY"
  | "ORACLE_VALIDITY"
  | "MESSAGE_REPLAY"
  | "REWARD_ACCOUNTING"
  | "UPGRADE_STORAGE"
  | "AMM_ACCOUNTING"
  | "SUPPLY_BACKING";

export type SynthesizedInvariant = {
  id: string;
  kind: SynthesizedInvariantKind;
  title: string;
  statement: string;
  formula: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  variables: string[];
  functions: string[];
  evidenceBasis: string[];
  assumptions: string[];
  executableBy: Array<
    "ECONOMIC_MODEL" | "FOUNDRY" | "ECHIDNA" | "HALMOS" | "CERTORA" | "KONTROL"
  >;
  source: "SYNTHESIZED";
};

function names(
  storage: StorageSurface[],
  pattern: RegExp
) {
  return storage
    .filter(item =>
      pattern.test(
        item.variable + " " + item.typeHint
      )
    )
    .map(item => item.variable)
    .slice(0, 20);
}

function functionNames(graphs: AnalysisGraph[]) {
  return [
    ...new Set(
      graphs.flatMap(graph =>
        graph.nodes
          .filter(node =>
            node.kind === "function" ||
            node.kind === "entry"
          )
          .map(node => node.label)
      )
    )
  ];
}

function matchingFunctions(
  functions: string[],
  pattern: RegExp
) {
  return functions
    .filter(value => pattern.test(value))
    .slice(0, 20);
}

function id(
  protocol: ProtocolModel,
  kind: SynthesizedInvariantKind,
  variables: string[],
  functions: string[]
) {
  return (
    "syn-" +
    createHash("sha256")
      .update(
        kind +
          "|" +
          protocol.categories.join(",") +
          "|" +
          variables.sort().join(",") +
          "|" +
          functions.sort().join(",")
      )
      .digest("hex")
      .slice(0, 14)
  );
}

function pushUnique(
  rows: SynthesizedInvariant[],
  invariant: SynthesizedInvariant
) {
  if (!rows.some(row => row.id === invariant.id)) {
    rows.push(invariant);
  }
}

export function synthesizeProtocolInvariants(opts: {
  protocol: ProtocolModel;
  storage?: StorageSurface[];
  graphs?: AnalysisGraph[];
  calls?: CrossContractCall[];
  findings?: AnalysisFinding[];
}) {
  const storage = opts.storage || [];
  const graphs = opts.graphs || [];
  const calls = opts.calls || [];
  const findings = opts.findings || [];
  const functions = functionNames(graphs);
  const categories = new Set(
    opts.protocol.categories
  );
  const rows: SynthesizedInvariant[] = [];

  const debt = names(
    storage,
    /debt|borrow|liabil|loan/i
  );
  const collateral = names(
    storage,
    /collateral|reserve|asset|cash|liquid/i
  );
  const shares = names(
    storage,
    /share|supply/i
  );
  const totalAssets = names(
    storage,
    /totalassets|underlying|asset/i
  );
  const nonces = names(
    storage,
    /nonce|processed|executed|message/i
  );
  const rewards = names(
    storage,
    /reward|accru|claim/i
  );
  const authority = names(
    storage,
    /owner|admin|guardian|pauser|govern|role/i
  );

  if (
    categories.has("lending") ||
    categories.has("liquidation") ||
    debt.length
  ) {
    const vars = [
      ...debt,
      ...collateral
    ];
    const methods = matchingFunctions(
      functions,
      /borrow|withdraw|liquidat|repay|collateral/i
    );
    pushUnique(rows, {
      id: id(opts.protocol, "SOLVENCY", vars, methods),
      kind: "SOLVENCY",
      title:
        "Protocol-derived debt remains covered by modeled collateral/reserves",
      statement:
        "Every value-extracting lending transition must preserve the protocol's declared solvency condition.",
      formula:
        "marked_assets(protocol) - marked_liabilities(protocol) >= 0",
      confidence:
        debt.length && collateral.length
          ? "HIGH"
          : "MEDIUM",
      variables: vars,
      functions: methods,
      evidenceBasis: [
        "category:lending/liquidation",
        ...vars.map(value => "storage:" + value)
      ],
      assumptions: [
        "Price observations and decimal normalization are supplied by pinned state or an explicit economic model.",
        "The synthesized aggregate maps semantically corresponding debt and asset variables; unresolved aliases remain a review item."
      ],
      executableBy: [
        "ECONOMIC_MODEL",
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA",
        "KONTROL"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    categories.has("vault") ||
    categories.has("yield_aggregator") ||
    shares.length
  ) {
    const vars = [
      ...shares,
      ...totalAssets
    ];
    const methods = matchingFunctions(
      functions,
      /deposit|mint|withdraw|redeem|convert|preview/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "SHARE_ACCOUNTING",
        vars,
        methods
      ),
      kind: "SHARE_ACCOUNTING",
      title:
        "Vault share conversion cannot create unbacked caller value",
      statement:
        "Absent external yield, a deposit/mint/redeem/withdraw round trip must not increase caller value beyond declared fees and rounding bounds.",
      formula:
        "caller_value_after <= caller_value_before + declared_yield + rounding_bound",
      confidence:
        shares.length && totalAssets.length
          ? "HIGH"
          : "MEDIUM",
      variables: vars,
      functions: methods,
      evidenceBasis: [
        "category:vault/yield_aggregator",
        ...vars.map(value => "storage:" + value)
      ],
      assumptions: [
        "External yield is held constant during the round-trip property.",
        "Asset/share decimals are resolved before numeric execution."
      ],
      executableBy: [
        "ECONOMIC_MODEL",
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    categories.has("amm") ||
    categories.has("dex")
  ) {
    const methods = matchingFunctions(
      functions,
      /swap|mint|burn|join|exit|sync|skim/i
    );
    const vars = names(
      storage,
      /reserve|balance|liquidity|fee/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "AMM_ACCOUNTING",
        vars,
        methods
      ),
      kind: "AMM_ACCOUNTING",
      title:
        "AMM reserve and fee accounting remain coherent across external callbacks",
      statement:
        "After each swap/liquidity transition, modeled reserves and liabilities must agree with the protocol's accounting invariant.",
      formula:
        "reserve_accounting_after >= required_reserve_accounting_after_fees",
      confidence:
        vars.length ? "HIGH" : "MEDIUM",
      variables: vars,
      functions: methods,
      evidenceBasis: [
        "category:amm/dex",
        ...calls
          .filter(call => call.valueBearing)
          .slice(0, 10)
          .map(
            call =>
              "external-call:" +
              call.location.file +
              ":" +
              call.location.line
          )
      ],
      assumptions: [
        "Protocol-specific AMM curve parameters must be supplied for exact numeric proof."
      ],
      executableBy: [
        "ECONOMIC_MODEL",
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    categories.has("bridge") ||
    findings.some(
      finding =>
        finding.kind === "bridge_messaging" ||
        finding.kind === "signature_replay"
    ) ||
    nonces.length
  ) {
    const methods = matchingFunctions(
      functions,
      /message|relay|execute|receive|finalize|bridge/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "MESSAGE_REPLAY",
        nonces,
        methods
      ),
      kind: "MESSAGE_REPLAY",
      title:
        "Cross-domain messages execute at most once for one authenticated origin",
      statement:
        "Once a message identifier is consumed, the same origin/message tuple cannot cause a second privileged state transition.",
      formula:
        "processed(message_id) => next_execute(message_id) reverts_or_noops",
      confidence:
        nonces.length ? "HIGH" : "MEDIUM",
      variables: nonces,
      functions: methods,
      evidenceBasis: [
        "category:bridge",
        ...nonces.map(value => "storage:" + value)
      ],
      assumptions: [
        "Message identity includes the protocol's source-domain and source-sender fields."
      ],
      executableBy: [
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA",
        "KONTROL"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    categories.has("governance") ||
    authority.length ||
    findings.some(
      finding =>
        finding.kind === "governance_risk" ||
        finding.kind === "authorization"
    )
  ) {
    const methods = matchingFunctions(
      functions,
      /upgrade|admin|owner|pause|mint|execute|govern|set[A-Z_]/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "AUTHORITY",
        authority,
        methods
      ),
      kind: "AUTHORITY",
      title:
        "Privileged state transitions stay inside the declared authority path",
      statement:
        "Every upgrade, pause, mint, asset-movement or governance execution path must be dominated by the intended authority/timelock condition.",
      formula:
        "privileged_transition => authorized(caller) && delay_requirements_satisfied",
      confidence:
        authority.length ? "HIGH" : "MEDIUM",
      variables: authority,
      functions: methods,
      evidenceBasis: [
        ...authority.map(value => "storage:" + value),
        ...findings
          .filter(
            finding =>
              finding.kind === "authorization" ||
              finding.kind === "governance_risk"
          )
          .slice(0, 10)
          .map(finding => "finding:" + finding.id)
      ],
      assumptions: [
        "Multisig threshold and timelock delay require pinned-state or event-history resolution."
      ],
      executableBy: [
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA",
        "KONTROL"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    findings.some(
      finding => finding.kind === "oracle_risk"
    )
  ) {
    const methods = matchingFunctions(
      functions,
      /price|oracle|quote|value|health|liquidat/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "ORACLE_VALIDITY",
        [],
        methods
      ),
      kind: "ORACLE_VALIDITY",
      title:
        "Security-critical price reads remain fresh, valid and normalized",
      statement:
        "Value-moving decisions must reject stale/invalid observations and normalize price decimals before arithmetic.",
      formula:
        "value_move => oracle_answer_valid && age <= max_age && decimals_normalized",
      confidence: "HIGH",
      variables: [],
      functions: methods,
      evidenceBasis: findings
        .filter(
          finding => finding.kind === "oracle_risk"
        )
        .map(finding => "finding:" + finding.id),
      assumptions: [
        "The acceptable maximum age is protocol configuration, not inferred by Risk Radar."
      ],
      executableBy: [
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    categories.has("staking") ||
    rewards.length
  ) {
    const methods = matchingFunctions(
      functions,
      /claim|reward|stake|unstake|harvest/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "REWARD_ACCOUNTING",
        rewards,
        methods
      ),
      kind: "REWARD_ACCOUNTING",
      title:
        "Reward claims cannot exceed accrued entitlement",
      statement:
        "A successful claim must atomically reduce/checkpoint entitlement so replayed claims cannot exceed accrued rewards.",
      formula:
        "cumulative_claimed(actor) <= cumulative_accrued(actor)",
      confidence:
        rewards.length ? "HIGH" : "MEDIUM",
      variables: rewards,
      functions: methods,
      evidenceBasis: rewards.map(
        value => "storage:" + value
      ),
      assumptions: [
        "External reward emissions/yield are held constant during a single atomic claim transition."
      ],
      executableBy: [
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (
    findings.some(
      finding => finding.kind === "upgradeability"
    ) ||
    storage.some(item => item.proxySlotStandard)
  ) {
    const methods = matchingFunctions(
      functions,
      /upgrade|implement|initializ/i
    );
    const vars = storage
      .filter(item => item.occupiesSlot !== false)
      .map(item => item.variable)
      .slice(0, 50);
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "UPGRADE_STORAGE",
        vars,
        methods
      ),
      kind: "UPGRADE_STORAGE",
      title:
        "Upgrade storage interpretation remains compatible",
      statement:
        "A new implementation must preserve live storage slot/type semantics and initialization/authorization invariants.",
      formula:
        "for_each_live_slot: meaning_before(slot) == meaning_after(slot) || explicit_namespaced_migration(slot)",
      confidence:
        storage.some(
          item =>
            item.proxySlotStandard ||
            item.byteSize !== undefined
        )
          ? "HIGH"
          : "MEDIUM",
      variables: vars,
      functions: methods,
      evidenceBasis: [
        ...storage
          .filter(item => item.proxySlotStandard)
          .map(
            item =>
              "proxy-slot:" +
              item.proxySlotStandard
          )
      ],
      assumptions: [
        "Authoritative proof requires compiler storage layouts or standardized namespaced-storage metadata."
      ],
      executableBy: [
        "FOUNDRY",
        "CERTORA",
        "KONTROL"
      ],
      source: "SYNTHESIZED"
    });
  }

  if (categories.has("stablecoin")) {
    const methods = matchingFunctions(
      functions,
      /mint|burn|redeem|issue/i
    );
    const vars = names(
      storage,
      /supply|debt|back|reserve|collateral/i
    );
    pushUnique(rows, {
      id: id(
        opts.protocol,
        "SUPPLY_BACKING",
        vars,
        methods
      ),
      kind: "SUPPLY_BACKING",
      title:
        "Stablecoin liabilities cannot increase without declared backing/debt accounting",
      statement:
        "Minting must correspond to the protocol's declared collateral, reserve or debt-accounting transition.",
      formula:
        "delta(liabilities) <= accounted_backing_delta + permitted_unbacked_delta",
      confidence:
        vars.length ? "HIGH" : "MEDIUM",
      variables: vars,
      functions: methods,
      evidenceBasis: [
        "category:stablecoin",
        ...vars.map(value => "storage:" + value)
      ],
      assumptions: [
        "The permitted unbacked delta is zero unless protocol governance explicitly defines another bounded mechanism."
      ],
      executableBy: [
        "ECONOMIC_MODEL",
        "FOUNDRY",
        "ECHIDNA",
        "HALMOS",
        "CERTORA"
      ],
      source: "SYNTHESIZED"
    });
  }

  return rows.sort((a, b) =>
    a.id.localeCompare(b.id)
  );
}
