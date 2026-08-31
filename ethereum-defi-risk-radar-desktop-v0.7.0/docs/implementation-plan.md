# Implementation plan

| Milestone | Outcome | Requirements | Verification | Status |
|---|---|---|---|---|
| M1 | Architecture, model, budgets, acceptance contract | All | EDID Validate | In progress |
| M2 | Native control/data/taint/storage/call results | FR-1–FR-3, FR-7–FR-8 | Golden fixtures/benchmark | Planned |
| M3 | Doctor and optional external adapters | FR-4–FR-6, FR-11, FR-13 | Fake-runner/capability tests | Planned |
| M4 | Category registry and economic simulator | FR-9–FR-10 | Conservation/solvency/category tests | Planned |
| M5 | Scanner, CLI, reports, settings, desktop workspace | FR-12–FR-13 | Build/smoke/report/browser | Planned |
| M6 | Independent evaluation, repair, release, handoff | All | EDID Evaluate/Complete | Planned |
| M7 | Proof-grade evidence, protocol graph, deterministic replay, and honest truncation | FR-14–FR-23, NFR-9 | Proof fixtures, adapter fixtures, replay tests, security/browser evidence | In progress |

## Dependencies and risks

| Item | Impact | Mitigation | Status |
|---|---|---|---|
| Approximate native parsing | False positives/negatives | Conservative labels; prefer Slither evidence | Accepted |
| Tool/schema version drift | Parsing failures | Version detection, schema guards, fixtures | Open |
| Project build hooks | Host compromise | Explicit trust warning; detection never builds | Open hard gate |
| Path explosion/nondeterminism | Long/inconclusive runs | Bounds, seeds, partial outcomes, cancellation | Accepted |
| RPC state/provider cost | Reproducibility/cost | Pin block; optional credentials; read/fork default | Accepted |
| Broad protocol taxonomy | Specific gaps | Shared primitives and versioned scenario packs | Accepted |
| Model witness misread as deployed exploit | Unsafe product claim | Mandatory evidence scope and scoped labels | Hard gate |
| Fork replay requires external RPC and installed Anvil | Optional capability unavailable | Typed unavailable state; deterministic fake-backend tests | Accepted |
