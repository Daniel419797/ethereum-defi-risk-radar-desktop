# Architecture

## Context, constraints, and non-goals

- Existing Electron/TypeScript desktop and CLI share a scanner and encrypted settings.
- Current verified-source inspection is transient and regex-based; reports redact addresses.
- The baseline must work offline. Python, Docker, analyzers, RPC, and paid services are optional.
- Inputs are verified Ethereum addresses and local Foundry/Hardhat projects.
- Rebuilding a compiler, SMT solver, full EVM, or mature fuzzer is a non-goal.
- Automated exploitability claims, private-key custody, and silent external transactions are
  excluded. Any future write-capable mode requires its own explicit trust boundary.

## Quality targets

Security, correctness/data integrity, and reliability are hard gates.

| Quality | Target | Verification |
|---|---|---|
| Security/privacy | Strict IPC; no shell strings; allowlisted tools; bounded processes; redacted RPC secrets; transient source | Tests, adapter, review |
| Correctness/integrity | Typed schema; stable IDs; provenance; confidence never exceeds evidence | Golden fixtures |
| Reliability/recovery | Partial results; timeout/cancel/kill; missing tools normal; scanner survives failures | Failure injection |
| Performance | Native 250 KB under 2 seconds; configurable 10–60 minute deep runs | Benchmark/limits |
| Scalability | Per-target/engine caps prevent unbounded paths, corpora, logs, or results | Budget tests |
| Delivery/collaboration | Preserve stack; cohesive modules; stable adapter contract | Build/review |
| Maintainability | Tool schemas stop at adapter boundary; dependency direction enforced | Typecheck/review |
| Testability/operability | Fake runner, deterministic fixtures, capability doctor, structured events | Tests/CLI |
| Accessibility/UX | Loading, unavailable, partial, failed, cancelled, complete states; keyboard controls | Browser evidence |
| Cost | Useful offline baseline; no required subscription | Offline test |

## Recommended design

Use a modular analysis subsystem inside the current single deployable:

1. `analysis/model` defines targets, plans, capabilities, graphs, traces, findings, evidence,
   simulation results, budgets, and lifecycle states.
2. `analysis/native` provides dependency-free token-aware CFG, data-flow, taint, storage, and
   cross-contract analysis. It is conservative triage, not a compiler substitute.
3. `analysis/adapters` detects and invokes Slither for compiler/IR analysis, Mythril for
   symbolic exploration, Forge/Anvil for fuzz/invariant/fork scenarios, and Echidna for
   coverage-guided stateful properties.
4. `analysis/orchestrator` validates targets, selects engines, enforces budgets, streams
   status, normalizes output, and preserves partial results.
5. `analysis/economic` models actors, assets, pools, positions, oracles, governance, bridges,
   and protocol accounting. Scenario packs compose price shocks, liquidity withdrawal, flash
   liquidity, liquidations, rounding, bad debt, fee extraction, governance capture, and
   cross-protocol contagion.
6. Scanner, main process, CLI, renderer, and reports consume the normalized model only.

### Trust boundaries and data flow

```text
renderer -> validated IPC -> main/CLI -> orchestrator
  -> native analyzer (in-process, transient source)
  -> process runner (allowlisted executable + argv, no shell)
     -> optional local tools or Docker
  -> optional read/fork RPC pinned to chain and block
  -> normalized/redacted results -> desktop and reports
```

The runner uses a controlled working directory, minimal environment, output limits, timeout,
and abort signal. Detection never runs project scripts. Compiling a local project is explicit
because build systems can execute repository-controlled code.

### Persistence and recovery

- Persist preferences, normalized summaries, seeds, and reproduction metadata; never persist
  raw source, RPC secrets, solver dumps, or unrestricted logs.
- Runs use queued/running/complete/partial/failed/timed_out/cancelled/unavailable states.
- Structured events contain engine, phase, elapsed time, limits, counts, and redacted codes.

## Repository structure and dependency direction

```text
src/analysis/
  model.ts capabilities.ts processRunner.ts orchestrator.ts
  native/{lexer,controlFlow,dataFlow,taint,storage,crossContract}.ts
  adapters/{slither,mythril,foundry,echidna}.ts
  economic/{model,simulator,categories,scenarios}.ts
tests/analysis/{fixtures,*.test.mjs}
```

Dependencies point inward to `model.ts`. Analysis modules never import Electron or renderer
code. Tool output is normalized at adapters. Adversarial executable fixtures stay in tests.

## Candidate comparison

Scores are 1–5; hard-gate failure rejects a candidate.

| Quality | Weight | Native only | External only | Hybrid selected | Evidence/assumption |
|---|---:|---:|---:|---:|---|
| Security/correctness/reliability | 5 | 2 reject | 3 | 4 | New compiler/solver is unsafe; tool-only fails when absent |
| Performance/scalability | 4 | 4 | 3 | 4 | Fast triage plus bounded deep engines |
| Delivery/collaboration | 4 | 2 | 4 | 4 | Stable normalization enables slices |
| Maintainability | 4 | 2 | 3 | 4 | Adapters isolate drift |
| Operability/cost | 3 | 4 | 2 | 4 | Offline baseline, no required service |

## Tradeoffs, reversibility, and verification

- Native findings are explainable review signals; Slither is preferred when available.
- External engines add installation, license, compiler, and schema drift, isolated by adapters.
- Deep analysis may be incomplete due to path explosion or weak invariants; bounds are reported
  and absence of evidence is never presented as a pass.
- Adapters are independently reversible. Reassess local-process isolation if untrusted projects
  become primary, scans run unattended, or shared/remote execution is introduced.
- Verify with golden source fixtures, fake-runner failure tests, deterministic economic
  conservation/solvency tests, build/smoke/redaction/security gates, and desktop browser checks.

## Desktop Analysis Lab integration

The desktop remains one sandboxed Electron deployable. A new Analysis Lab presentation module
calls narrowly scoped preload methods; the main process owns dialogs, selected-path authorization,
schema validation, execution trust, cancellation, and orchestration. Renderer code never receives
filesystem or process primitives. Normalized `AnalysisRunReport`, protocol-scenario results, and
external-replay findings are returned without adding a second backend or duplicating analysis logic.

The selected design is one screen with three workflow panels (project analysis, protocol simulation,
fork replay). Separate windows were rejected because they duplicate state and error handling; a local
HTTP API was rejected because it adds authentication and network attack surface. The design is
reversible: each IPC method and panel can be removed independently while CLI behavior remains intact.

Hard gates: only user-selected paths are accepted, deep execution requires an explicit trust checkbox,
replay requires explicit confirmation and never accepts a private key, payloads retain existing byte and
runtime bounds, and all evidence labels come from the shared analysis model. Reassess this boundary if
remote/shared execution, unattended scans, or product-owned Anvil processes are introduced.
