import type {
  BenchmarkCase,
  BenchmarkPrediction
} from "./model.js";

export type VulnerabilityCalibration = {
  category: string;
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  trueNegative: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  falsePositiveRate: number | null;
  support: number;
  predicted: number;
  calibratedEvidence:
    | "INSUFFICIENT_DATA"
    | "LOW"
    | "MEDIUM"
    | "HIGH";
};

export type CalibrationReport = {
  generatedAt: string;
  cases: number;
  categories: VulnerabilityCalibration[];
  macroPrecision: number | null;
  macroRecall: number | null;
  macroF1: number | null;
};

function normalized(value: string) {
  const text = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_");
  const map: Array<
    [RegExp, string]
  > = [
    [
      /access|authori[sz]|owner|permission/,
      "authorization"
    ],
    [/reentran/, "reentrancy"],
    [
      /arith|overflow|underflow|precision|round/,
      "arithmetic_precision"
    ],
    [/oracle|price/, "oracle_risk"],
    [/signature|replay/, "signature_replay"],
    [
      /delegate|proxy|upgrade|initializ/,
      "upgradeability"
    ],
    [
      /bridge|cross_chain|message/,
      "bridge_messaging"
    ],
    [
      /front.?run|mev|ordering|slippage/,
      "mev_ordering"
    ],
    [
      /token|transfer/,
      "token_integration"
    ]
  ];
  return (
    map.find(([pattern]) =>
      pattern.test(text)
    )?.[1] || text
  );
}

function ratio(
  numerator: number,
  denominator: number
) {
  return denominator
    ? numerator / denominator
    : null;
}

function mean(
  values: Array<number | null>
) {
  const present = values.filter(
    (value): value is number =>
      value !== null
  );
  return present.length
    ? present.reduce(
        (sum, value) =>
          sum + value,
        0
      ) / present.length
    : null;
}

export function calibrateByVulnerability(
  cases: BenchmarkCase[],
  predictions: BenchmarkPrediction[]
): CalibrationReport {
  const predictedByCase = new Map(
    predictions.map(item => [
      item.caseId,
      item
    ])
  );
  const universe = new Set<string>();
  for (const item of cases) {
    for (const label of item.labels) {
      universe.add(
        normalized(label.category)
      );
    }
    for (const finding of
      predictedByCase.get(item.id)
        ?.findings || []) {
      universe.add(
        normalized(finding.category)
      );
    }
    const family =
      item.metadata?.family;
    if (
      typeof family === "string"
    ) {
      universe.add(
        normalized(family)
      );
    }
  }

  const categories: VulnerabilityCalibration[] =
    [];
  for (const category of [
    ...universe
  ].sort()) {
    let truePositive = 0;
    let falsePositive = 0;
    let falseNegative = 0;
    let trueNegative = 0;

    for (const item of cases) {
      const expected = new Set(
        item.labels.map(label =>
          normalized(
            label.category
          )
        )
      );
      const negativeFamily =
        typeof item.metadata?.family ===
          "string"
          ? normalized(
              item.metadata.family
            )
          : undefined;
      const explicitlyNegative =
        item.labels.length === 0 &&
        negativeFamily === category;
      const expectedPositive =
        expected.has(category);
      const relevant =
        expectedPositive ||
        explicitlyNegative ||
        item.labels.length > 0;
      if (!relevant) continue;

      const predicted = new Set(
        (
          predictedByCase.get(
            item.id
          )?.findings || []
        ).map(finding =>
          normalized(
            finding.category
          )
        )
      );
      const predictedPositive =
        predicted.has(category);

      if (
        expectedPositive &&
        predictedPositive
      ) {
        truePositive += 1;
      } else if (
        expectedPositive
      ) {
        falseNegative += 1;
      } else if (
        predictedPositive
      ) {
        falsePositive += 1;
      } else {
        trueNegative += 1;
      }
    }

    const precision = ratio(
      truePositive,
      truePositive +
        falsePositive
    );
    const recall = ratio(
      truePositive,
      truePositive +
        falseNegative
    );
    const f1 =
      precision !== null &&
      recall !== null &&
      precision + recall > 0
        ? (2 *
            precision *
            recall) /
          (precision + recall)
        : null;
    const falsePositiveRate =
      ratio(
        falsePositive,
        falsePositive +
          trueNegative
      );
    const support =
      truePositive +
      falseNegative;
    const predicted =
      truePositive +
      falsePositive;
    const calibratedEvidence =
      support < 20 ||
      truePositive +
        falsePositive <
        20
        ? "INSUFFICIENT_DATA"
        : precision !== null &&
            recall !== null &&
            precision >= 0.9 &&
            recall >= 0.8
          ? "HIGH"
          : precision !== null &&
              recall !== null &&
              precision >= 0.75 &&
              recall >= 0.6
            ? "MEDIUM"
            : "LOW";

    categories.push({
      category,
      truePositive,
      falsePositive,
      falseNegative,
      trueNegative,
      precision,
      recall,
      f1,
      falsePositiveRate,
      support,
      predicted,
      calibratedEvidence
    });
  }

  return {
    generatedAt:
      new Date().toISOString(),
    cases: cases.length,
    categories,
    macroPrecision: mean(
      categories.map(
        item => item.precision
      )
    ),
    macroRecall: mean(
      categories.map(
        item => item.recall
      )
    ),
    macroF1: mean(
      categories.map(
        item => item.f1
      )
    )
  };
}
