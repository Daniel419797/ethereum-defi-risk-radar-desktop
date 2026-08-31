# Verification record

## Automated gates

- `npm.cmd run test:analysis`: passed. Exercises CFG, data-flow, taint, storage/state, calls, native findings, tool absence, trust gating, executable path rejection, all 12 DeFi categories, and 8 economic scenario packs.
- `npm.cmd run check`: passed. TypeScript build and application smoke checks.
- Electron CLI capability, native-project, trusted-deep unavailable-engine, and economic-scenario runs: passed locally.
- Codex Security standard scan `a4bd3e47-6268-4bd7-a467-e707d30f5887`: completed with zero open validated findings after remediation.

## Desktop UI

The Settings analysis-engine matrix was inspected in a running browser harness. Eight engine cards rendered. A 390 px viewport exposed an initial clipped sidebar; responsive navigation and single-column settings were repaired and rechecked with no overflowing content elements.

## Evidence boundary

This release is locally verified. Optional Slither, Mythril, Foundry, Anvil, and Echidna execution is available only when installed. Their absence is represented as typed `unavailable` state, not a failed native analysis. No deployment or production effectiveness claim is made.

## Final acceptance

- EDID evaluation `20260831T121525564Z-expanded-analysis-engine`: pass with distinct builder/evaluator identities and all four required checks passing.
- EDID task `expanded-analysis-engine`: complete; zero open repair packets.
- EDID project state: `locally_verified`.
- Post-evaluation Electron CLI smoke: native fixture analysis returned 3 CFGs, 4 dependencies, 3 storage surfaces, 2 cross-contract calls, and 7 normalized findings; the economic fixture completed 3 steps with all invariants passing.
