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

## Proof-grade analysis - 2026-08-31

- `npm run test:proof`: pass; closed CFG/dominator/reachability, mitigation scope, truncation, evidence invariants, external-engine semantics, protocol scenarios, and fail-closed external fork replay.
- `npm run test:analysis`: pass; 3 CFGs, 4 dependencies, 3 storage surfaces, 2 calls, 8 findings, 12 DeFi categories, and 8 scenario packs.
- `npm run check`: pass; build, desktop/CLI smoke, report redaction, truthful guarantee metadata, and detailed JSON/CSV finding rows.
- Browser inspection at 390 x 844: pass after responsive grid repair; no horizontal overflow and primary actions remained visible.
- Codex Security scan `106c2597-85e5-4ecf-9772-43e650be4961`: complete, focused partial repository coverage, zero open validated findings.
- EDID independent evaluation `20260831T184319592Z-proof-grade-analysis`: pass for tests, build, security, and browser/accessibility evidence.
- Evidence state: locally verified. No deployment or production behavior was tested.

## Desktop Analysis Lab - 2026-09-01

- `npm run test:desktop-analysis`: pass; all four desktop workflows, preload/IPC/UI contracts, trust gates, runtime engine validation, native analysis, and economic/protocol execution.
- `npm run test:proof`, `npm run test:analysis`, and `npm run check`: pass.
- Browser harness: project analysis completed and rendered evidence scope; at 390 x 844 every action remained visible with no horizontal overflow.
- Codex Security scan `3d147a79-6bce-472e-bb87-e9b48da25fd0`: complete with zero open validated findings across nine reviewed surfaces; coverage is partial because delegated workers and live optional toolchains were unavailable.
- EDID evaluation `20260901T083958200Z-desktop-analysis-lab`: pass; all five required tests, build, security, and browser/accessibility checks passed under distinct builder/evaluator identities.
- Evidence state: locally verified. External analyzers, live Anvil replay, deployment, and production behavior were not proven.
