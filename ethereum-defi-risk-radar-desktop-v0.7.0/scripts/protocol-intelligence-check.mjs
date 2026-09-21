import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  attestRuntimeBytecode,
  stripSolidityMetadata
} from "../dist/intelligence/bytecode.js";
import {
  capturePinnedStateSnapshot,
  EIP1967_ADMIN_SLOT,
  EIP1967_BEACON_SLOT,
  EIP1967_IMPLEMENTATION_SLOT
} from "../dist/intelligence/snapshot.js";
import { buildProtocolIntelligence } from "../dist/intelligence/platform.js";
import { diffPinnedSnapshots } from "../dist/intelligence/monitor.js";
import { compareProtocolUpgrade } from "../dist/intelligence/upgrade.js";
import {
  BENCHMARK_CORPUS_COMMITS,
  evaluateBenchmark
} from "../dist/intelligence/benchmark.js";
import { candidatesToSarif } from "../dist/intelligence/sarif.js";

const root = fileURLToPath(new URL("..", import.meta.url));

assert.equal(
  stripSolidityMetadata("0x6001a00001"),
  "0x6001",
  "Solidity metadata trailer should be stripped by declared byte length."
);

const exact = attestRuntimeBytecode({
  observedRuntimeBytecode: "0x60016000",
  compiledRuntimeBytecode: "0x60016000",
  compilerVersion: "v0.8.30"
});
assert.equal(exact.status, "SOURCE_RECOMPILED_EXACT");

const metadataEquivalent = attestRuntimeBytecode({
  observedRuntimeBytecode: "0x6001a00001",
  compiledRuntimeBytecode: "0x6001800001",
  compilerVersion: "v0.8.30"
});
assert.equal(
  metadataEquivalent.status,
  "SOURCE_RECOMPILED_METADATA_EQUIVALENT"
);
assert.equal(metadataEquivalent.metadataStripped, true);

const mismatch = attestRuntimeBytecode({
  observedRuntimeBytecode: "0x60016000",
  compiledRuntimeBytecode: "0x60026000",
  compilerVersion: "v0.8.30"
});
assert.equal(mismatch.status, "RECOMPILE_MISMATCH");

const implementation =
  "0x1111111111111111111111111111111111111111";
const admin =
  "0x2222222222222222222222222222222222222222";

function storageWord(address) {
  return "0x" + "0".repeat(24) + address.slice(2).toLowerCase();
}

const fakeReader = {
  async getChainId() {
    return 1;
  },
  async getBlock(block) {
    assert.equal(block, 123456);
    return {
      number: 123456,
      hash:
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      timestamp: 1_799_999_999
    };
  },
  async getCode(address, blockNumber) {
    assert.equal(
      address,
      "0x3333333333333333333333333333333333333333"
    );
    assert.equal(blockNumber, 123456);
    return "0x6001600055";
  },
  async getStorageAt(_address, slot) {
    if (slot === EIP1967_IMPLEMENTATION_SLOT) return storageWord(implementation);
    if (slot === EIP1967_ADMIN_SLOT) return storageWord(admin);
    if (slot === EIP1967_BEACON_SLOT) return "0x" + "0".repeat(64);
    throw new Error("unexpected slot");
  },
  async call(_address, data) {
    assert.equal(data, "0x1234");
    return "0x01";
  }
};

const snapshot = await capturePinnedStateSnapshot({
  reader: fakeReader,
  blockNumber: 123456,
  targets: [
    {
      address: "0x3333333333333333333333333333333333333333",
      contractRefId: "vault-proxy",
      callProbes: [{ id: "paused", data: "0x1234" }]
    }
  ]
});
assert.equal(snapshot.chainId, 1);
assert.equal(snapshot.blockNumber, 123456);
assert.equal(snapshot.contracts[0].implementationSlot, implementation);
assert.equal(snapshot.contracts[0].adminSlot, admin);
assert.equal(snapshot.contracts[0].beaconSlot, null);
assert.equal(snapshot.contracts[0].probes[0].value, "0x01");
assert.equal(snapshot.partial, false);
assert.match(snapshot.digest, /^sha256:[a-f0-9]{64}$/);

const finding = {
  id: "oracle-1",
  kind: "oracle_risk",
  engine: "native",
  severity: "HIGH",
  confidence: "HIGH",
  evidenceStrength: "STRUCTURAL",
  title: "Stale oracle value can reach borrow accounting",
  description: "Price freshness is not established on the witness path.",
  primaryLocation: { file: "Pool.sol", line: 88, column: 5 },
  limitations: ["Requires state validation and execution evidence."],
  reachableFromExternalEntry: true,
  witnessPath: [
    {
      symbol: "borrow",
      role: "source",
      location: { file: "Pool.sol", line: 40 }
    },
    {
      symbol: "readPrice",
      role: "propagation",
      location: { file: "Pool.sol", line: 72 }
    },
    {
      symbol: "debtAccounting",
      role: "sink",
      location: { file: "Pool.sol", line: 88 }
    }
  ],
  exploitabilityVerdict: "UNKNOWN"
};

const protocolModel = {
  contracts: [
    {
      id: "Pool.sol:Pool",
      name: "Pool",
      file: "Pool.sol",
      category: "lending",
      kind: "contract",
      storageVariables: ["totalDebt"]
    }
  ],
  calls: [],
  assets: ["collateralToken"],
  categories: ["lending"],
  unresolvedCallCount: 0,
  assumptions: []
};

const intelligence = buildProtocolIntelligence({
  protocolId: "fixture-protocol",
  label: "Fixture Protocol",
  contractInspections: [
    {
      contractRefId: "pool-ref",
      sourceRole: "DIRECT",
      contractName: "Pool",
      proxy: false,
      protocolModel,
      findings: [finding]
    }
  ]
});

assert.ok(
  intelligence.graph.nodes.some(node => node.kind === "PROTOCOL"),
  "Protocol graph root missing."
);
assert.ok(
  intelligence.graph.nodes.some(node => node.kind === "FINDING"),
  "Finding graph node missing."
);
assert.ok(
  intelligence.invariants.some(
    item => item.invariant.id === "lending-solvency"
  ),
  "Lending invariant pack was not selected."
);
assert.ok(
  intelligence.invariants.some(
    item => item.invariant.id === "oracle-freshness-consistency"
  ),
  "Oracle invariant was not selected from the security signal."
);
assert.equal(intelligence.escalationPlans.length, 1);
assert.ok(
  intelligence.escalationPlans[0].steps.some(
    step =>
      step.stage === "PINNED_FORK_REPRODUCTION" &&
      step.required === true
  )
);
assert.equal(intelligence.attackPaths.length, 1);
assert.ok(intelligence.attackPaths[0].nodes.length >= 4);

const nextSnapshot = structuredClone(snapshot);
nextSnapshot.blockNumber = 123457;
nextSnapshot.blockHash =
  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
nextSnapshot.digest =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
nextSnapshot.contracts[0].implementationSlot =
  "0x4444444444444444444444444444444444444444";

const monitorDiff = diffPinnedSnapshots(snapshot, nextSnapshot);
assert.equal(monitorDiff.changed, true);
assert.ok(
  monitorDiff.changes.some(
    change =>
      change.kind === "IMPLEMENTATION_CHANGED" &&
      change.severity === "HIGH"
  )
);

const upgrade = compareProtocolUpgrade({
  previousSnapshot: snapshot,
  currentSnapshot: nextSnapshot
});
assert.equal(upgrade.changed, true);
assert.ok(
  upgrade.changes.some(change => change.kind === "IMPLEMENTATION")
);

const benchmarkCases = [
  {
    id: "case-access",
    corpus: "SMARTBUGS_CURATED",
    sourcePath: "access.sol",
    labels: [{ category: "access_control", lines: [10] }]
  },
  {
    id: "case-reentrancy",
    corpus: "SMARTBUGS_CURATED",
    sourcePath: "reentrancy.sol",
    labels: [{ category: "reentrancy", lines: [20] }]
  }
];

const metrics = evaluateBenchmark(benchmarkCases, [
  {
    caseId: "case-access",
    durationMs: 10,
    findings: [
      { category: "authorization", line: 10, severity: "HIGH" },
      { category: "oracle_risk", line: 40, severity: "LOW" }
    ]
  },
  {
    caseId: "case-reentrancy",
    durationMs: 20,
    findings: [
      { category: "reentrancy", line: 21, severity: "HIGH" }
    ]
  }
]);
assert.equal(metrics.truePositive, 2);
assert.equal(metrics.falseNegative, 0);
assert.equal(metrics.falsePositive, 1);
assert.ok(metrics.trueNegative > 0);
assert.ok(metrics.precision > 0 && metrics.precision < 1);
assert.equal(metrics.recall, 1);
assert.ok(metrics.falsePositiveRate > 0);
assert.equal(metrics.lineLocationAccuracy, 1);
assert.equal(
  BENCHMARK_CORPUS_COMMITS.SMARTBUGS_CURATED,
  "230e649123477eff332742a59a1c7cc6dc286cab"
);

const sourceInspection = {
  filesInspected: 1,
  sourceBytesInspected: 100,
  solidityVersionHints: ["^0.8.20"],
  findingCount: 0,
  totalFindingCount: 0,
  truncatedFindingCount: 0,
  findingLimit: 80,
  partial: false,
  sourceTruncated: false,
  truncatedSourceCharacters: 0,
  severityCounts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH_REVIEW: 0 },
  findings: [],
  advancedAnalysis: {
    engine: "native",
    analyzedAt: new Date().toISOString(),
    filesAnalyzed: 1,
    functionsAnalyzed: 1,
    graphs: [],
    dependencies: [],
    storage: [],
    calls: [],
    findings: [finding],
    limitations: []
  },
  protocolModel
};

const candidate = {
  id: "fixture-protocol",
  entityKind: "PROTOCOL",
  resolutionStatus: "SOURCE_ANALYZED",
  label: "Fixture Protocol",
  hostname: "fixture.example",
  chain: "ethereum",
  network: "mainnet",
  researchScore: 90,
  ethereumConfidence: 99,
  signalCount: 3,
  sourceDiversity: 2,
  kinds: ["public_audit_finding"],
  evidence: [],
  resolutionEvidence: [],
  ethereum: {
    chainId: 1,
    network: "ethereum-mainnet",
    contractReferencesObserved: 1,
    etherscanLookupsAttempted: 1,
    verifiedSourceContracts: 1,
    proxyContracts: 0,
    proxyImplementationsResolved: 0,
    sourceContractsInspected: 1,
    sourceFindingCount: 0,
    sourceHighReviewCount: 0,
    advancedFindingCount: 1,
    sourceInspections: [
      {
        contractRefId: "pool-ref",
        sourceRole: "DIRECT",
        contractName: "Pool",
        proxy: false,
        inspection: sourceInspection
      }
    ],
    pinnedStateSnapshot: snapshot,
    intelligence
  },
  classification: "HIGH_RESEARCH_PRIORITY"
};

const sarif = candidatesToSarif([candidate]);
assert.equal(sarif.version, "2.1.0");
assert.equal(sarif.runs[0].results.length, 1);
assert.equal(sarif.runs[0].results[0].ruleId, "oracle_risk");
assert.equal(
  sarif.runs[0].results[0].properties.evidenceStrength,
  "STRUCTURAL"
);

const renderer = await fs.readFile(
  path.join(root, "desktop", "renderer", "app.js"),
  "utf8"
);
const html = await fs.readFile(
  path.join(root, "desktop", "renderer", "index.html"),
  "utf8"
);
const css = await fs.readFile(
  path.join(root, "desktop", "renderer", "styles.css"),
  "utf8"
);
const packageJson = JSON.parse(
  await fs.readFile(path.join(root, "package.json"), "utf8")
);

for (const unsafe of [
  "innerHTML",
  "outerHTML",
  "insertAdjacentHTML",
  "eval(",
  "Function("
]) {
  assert.equal(
    renderer.includes(unsafe),
    false,
    "Unsafe renderer primitive found: " + unsafe
  );
}

for (const marker of [
  'data-candidate-tab="intelligence"',
  'id="candidate-graph-list"',
  'id="candidate-attestation-list"',
  'id="candidate-invariant-list"',
  'id="candidate-attack-paths"',
  'id="candidate-snapshot-list"',
  'id="candidate-watch"',
  'id="settings-replace-rpc"',
  'id="results-show-sarif"'
]) {
  assert.ok(html.includes(marker), "Protocol intelligence UI marker missing: " + marker);
}

for (const marker of [
  ".intelligence-layout",
  ".attack-path-flow",
  ".escalation-track",
  ".snapshot-grid"
]) {
  assert.ok(css.includes(marker), "Protocol intelligence CSS marker missing: " + marker);
}

assert.equal(
  packageJson.scripts?.["test:platform"],
  "npm run build && node scripts/protocol-intelligence-check.mjs"
);
assert.ok(
  String(packageJson.scripts?.check || "").includes(
    "protocol-intelligence-check.mjs"
  )
);

console.log(
  "Protocol intelligence checks passed: attestation semantics, pinned state, graph, invariants, escalation, monitoring, upgrade intelligence, benchmark metrics, SARIF and desktop contracts."
);
