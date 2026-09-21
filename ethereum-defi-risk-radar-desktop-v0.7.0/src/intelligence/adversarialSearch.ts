import { createHash } from "node:crypto";
import { finalizeFinding } from "../analysis/evidence.js";
import type { AnalysisFinding } from "../analysis/model.js";
import {
  simulateEconomicScenario,
  type EconomicAction,
  type EconomicSimulation,
  type EconomicState
} from "../analysis/economic/simulator.js";

export type AdversarialSearchObjective = {
  actorId: string;
  maximizeActorProfit: boolean;
  maximizeProtocolLoss: boolean;
};

export type AdversarialSearchConfig = {
  maxDepth: number;
  beamWidth: number;
  maxStates: number;
  seed: number;
};

export type AdversarialSequence = {
  actions: EconomicAction[];
  actorProfit: number;
  protocolLoss: number;
  violatedInvariants: string[];
  score: number;
  finalStateDigest: string;
};

export type AdversarialSearchResult = {
  exploredStates: number;
  sequences: AdversarialSequence[];
  finding?: AnalysisFinding;
  limitations: string[];
};

function canonical(value: unknown) {
  return JSON.stringify(value, (_key, item) => {
    if (
      item &&
      typeof item === "object" &&
      !Array.isArray(item)
    ) {
      return Object.fromEntries(
        Object.entries(item).sort(([a], [b]) =>
          a.localeCompare(b)
        )
      );
    }
    return item;
  });
}

function digest(value: unknown) {
  return createHash("sha256")
    .update(canonical(value))
    .digest("hex");
}

function totalProtocolSolvency(
  simulation: EconomicSimulation
) {
  return Object.values(
    simulation.protocolSolvency
  ).reduce((sum, value) => sum + value, 0);
}

function actionKey(action: EconomicAction) {
  return canonical(action);
}

function generateActions(
  state: EconomicState,
  actorId: string
) {
  const actor = state.actors[actorId];
  if (!actor) {
    throw new Error(
      "Adversarial-search actor is not present in economic state."
    );
  }
  const rows: EconomicAction[] = [];

  for (const asset of Object.keys(state.prices)) {
    for (const multiplier of [
      0.5,
      0.8,
      1.2,
      2
    ]) {
      rows.push({
        type: "price_shock",
        asset,
        multiplier
      });
    }
  }

  for (const pool of Object.values(state.pools)) {
    for (const [asset, reserve] of Object.entries(
      pool.reserves
    )) {
      for (const ratio of [0.01, 0.1, 0.3, 0.6]) {
        const amount = reserve * ratio;
        if (amount > 0) {
          rows.push({
            type: "borrow",
            actor: actorId,
            pool: pool.id,
            asset,
            amount
          });
        }
      }
    }

    for (const [asset, balance] of Object.entries(
      actor.balances
    )) {
      for (const ratio of [0.01, 0.1, 0.5]) {
        const amount = balance * ratio;
        if (amount > 0) {
          rows.push({
            type: "transfer",
            actor: actorId,
            pool: pool.id,
            asset,
            amount
          });
        }
      }
    }

    for (const [asset, debt] of Object.entries(
      actor.debt
    )) {
      const balance =
        actor.balances[asset] ?? 0;
      const repayable = Math.min(
        debt,
        balance
      );
      for (const ratio of [0.25, 1]) {
        const amount = repayable * ratio;
        if (amount > 0) {
          rows.push({
            type: "repay",
            actor: actorId,
            pool: pool.id,
            asset,
            amount
          });
        }
      }
    }
  }

  const seen = new Set<string>();
  return rows.filter(action => {
    const key = actionKey(action);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function scoreSequence(
  baseline: EconomicSimulation,
  result: EconomicSimulation,
  objective: AdversarialSearchObjective
) {
  const actorBefore =
    baseline.actorNetWorth[objective.actorId] ?? 0;
  const actorAfter =
    result.actorNetWorth[objective.actorId] ?? 0;
  const actorProfit = actorAfter - actorBefore;
  const protocolLoss =
    totalProtocolSolvency(baseline) -
    totalProtocolSolvency(result);
  const violatedInvariants = result.invariants
    .filter(invariant => {
      const prior = baseline.invariants.find(
        before => before.id === invariant.id
      );
      return prior?.passed && !invariant.passed;
    })
    .map(invariant => invariant.id);
  const violationWeight =
    violatedInvariants.length * 1_000_000;
  const score =
    violationWeight +
    (objective.maximizeActorProfit
      ? actorProfit
      : 0) +
    (objective.maximizeProtocolLoss
      ? protocolLoss
      : 0);
  return {
    actorProfit,
    protocolLoss,
    violatedInvariants,
    score
  };
}

export function searchEconomicAttackSpace(opts: {
  initialState: EconomicState;
  objective: AdversarialSearchObjective;
  config?: Partial<AdversarialSearchConfig>;
}): AdversarialSearchResult {
  const config: AdversarialSearchConfig = {
    maxDepth: Math.max(
      1,
      Math.min(opts.config?.maxDepth ?? 5, 8)
    ),
    beamWidth: Math.max(
      1,
      Math.min(opts.config?.beamWidth ?? 32, 128)
    ),
    maxStates: Math.max(
      10,
      Math.min(opts.config?.maxStates ?? 3_000, 20_000)
    ),
    seed: opts.config?.seed ?? 1
  };
  const baseline = simulateEconomicScenario(
    opts.initialState,
    []
  );

  type Node = {
    actions: EconomicAction[];
    simulation: EconomicSimulation;
    score: number;
  };
  let frontier: Node[] = [
    {
      actions: [],
      simulation: baseline,
      score: 0
    }
  ];
  const seen = new Set<string>([
    digest(baseline.finalState)
  ]);
  const winners: AdversarialSequence[] = [];
  let exploredStates = 1;

  for (
    let depth = 0;
    depth < config.maxDepth &&
    exploredStates < config.maxStates;
    depth += 1
  ) {
    const candidates: Node[] = [];
    for (const node of frontier) {
      const actions = generateActions(
        node.simulation.finalState,
        opts.objective.actorId
      );
      for (const action of actions) {
        if (
          exploredStates >= config.maxStates
        ) {
          break;
        }
        try {
          const sequence = [
            ...node.actions,
            action
          ];
          const simulation =
            simulateEconomicScenario(
              opts.initialState,
              sequence,
              config.maxDepth
            );
          const stateKey = digest(
            simulation.finalState
          );
          if (seen.has(stateKey)) continue;
          seen.add(stateKey);
          exploredStates += 1;

          const scored = scoreSequence(
            baseline,
            simulation,
            opts.objective
          );
          candidates.push({
            actions: sequence,
            simulation,
            score: scored.score
          });

          if (
            scored.violatedInvariants.length
          ) {
            winners.push({
              actions: sequence,
              actorProfit:
                scored.actorProfit,
              protocolLoss:
                scored.protocolLoss,
              violatedInvariants:
                scored.violatedInvariants,
              score: scored.score,
              finalStateDigest:
                "sha256:" + stateKey
            });
          }
        } catch {
          // Invalid model transitions are not candidate attack sequences.
        }
      }
    }

    frontier = candidates
      .sort((a, b) => b.score - a.score)
      .slice(0, config.beamWidth);
    if (!frontier.length) break;
  }

  winners.sort((a, b) => b.score - a.score);
  const best = winners[0];
  const finding = best
    ? finalizeFinding({
        id: createHash("sha256")
          .update(
            "adversarial-economic-search|" +
              canonical(best.actions)
          )
          .digest("hex")
          .slice(0, 18),
        kind: "economic_simulation",
        engine: "native",
        severity:
          best.protocolLoss > 0
            ? "CRITICAL"
            : "HIGH",
        confidence: "HIGH",
        evidenceStrength: "REPRODUCED",
        evidenceClass:
          "MODEL_REPRODUCED",
        evidenceScope: "model",
        title:
          "Bounded adversarial search found a model invariant violation",
        description:
          "Risk Radar searched " +
          exploredStates +
          " unique economic states and found a sequence that newly violated: " +
          best.violatedInvariants.join(", ") +
          ".",
        counterexample: {
          engine: "native",
          scope: "model",
          sequence: best.actions.map(action =>
            JSON.stringify(action)
          ),
          observedViolation:
            best.violatedInvariants.join(", "),
          invariantId:
            best.violatedInvariants[0],
          seed: config.seed
        },
        limitations: [
          "This is a deterministic protocol/economic-model counterexample, not deployed-bytecode exploit proof.",
          "The search is bounded by depth, beam width and state budget.",
          "Pinned-fork reproduction is required before a deployed exploitability claim."
        ]
      })
    : undefined;

  return {
    exploredStates,
    sequences: winners.slice(0, 20),
    finding,
    limitations: [
      "Search is intentionally confined to the local deterministic economic model.",
      "No transaction is signed or broadcast to a live network.",
      "Failure to find a sequence does not prove the model or protocol safe."
    ]
  };
}
