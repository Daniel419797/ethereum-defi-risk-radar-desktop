# Requirements

| ID | Requirement | Priority | Acceptance evidence |
|---|---|---|---|
| FR-1 | Build control-flow graphs with branches, loops, calls, returns, and unreachable signals | Must | Deterministic fixtures |
| FR-2 | Track definitions, uses, state reads/writes, and interprocedural dependencies | Must | Data-flow fixtures |
| FR-3 | Track untrusted sources to privileged, storage, call, transfer, delegatecall, and oracle sinks | Must | Positive and negative taint fixtures |
| FR-4 | Invoke an installed symbolic engine with bounded time/depth and normalized counterexamples | Must | Adapter fixtures |
| FR-5 | Invoke installed ABI-aware fuzzers and preserve seeds/corpus/failure metadata | Must | Adapter fixtures |
| FR-6 | Discover and run Foundry/Echidna invariants with sequences, seeds, coverage, and outcomes | Must | Invariant fixtures |
| FR-7 | Analyze storage layout, slots, packing, inheritance, proxy slots, delegatecall context, and collisions | Must | Storage/proxy fixtures |
| FR-8 | Build cross-contract call graphs covering callbacks, value flow, delegatecall, and reentrancy | Must | Multi-contract fixtures |
| FR-9 | Simulate actor balances, solvency, shocks, fees, and profit/loss assertions reproducibly | Must | Economic tests |
| FR-10 | Cover all documented DeFi categories through a shared, extensible registry | Must | Registry tests |
| FR-11 | Detect optional Slither, Mythril, Forge, Anvil, Echidna, Python, and Docker installations | Must | Capability tests |
| FR-12 | Expose engine status and normalized results in desktop, CLI, JSON, and CSV | Must | Smoke/report tests |
| FR-13 | Accept verified-address source and local Foundry/Hardhat project inputs | Must | Input/orchestration tests |

## Quality requirements

| ID | Attribute | Target | Acceptance evidence |
|---|---|---|---|
| NFR-1 | Security | No shell interpolation; allowlisted argv; no private-key requirement; sandboxed renderer | Security tests/review |
| NFR-2 | Correctness | Findings record engine, confidence, evidence class, locations, and limitations | Golden tests |
| NFR-3 | Reliability | Missing/crashed/timed-out engines return typed states without aborting discovery | Failure tests |
| NFR-4 | Performance | Native 250 KB scan under 2 seconds; deep engines cancellable and bounded | Benchmark/timeout tests |
| NFR-5 | Scalability | Cap bytes, findings, processes, runtime, output, paths, and simulation steps | Limit tests |
| NFR-6 | Accessibility | Keyboard-usable controls and textual status/error/recovery states | Browser evidence |
| NFR-7 | Operability | Doctor reports installation, version, availability, and remediation safely | CLI tests |
| NFR-8 | Reversibility | Each optional adapter can be disabled without changing discovery | Integration tests |

## Workflow and recovery

1. Validate a verified address or local project target.
2. Detect native and optional engine capabilities without building project code.
3. Always run native analysis for valid Solidity source.
4. Run explicitly selected optional engines with budgets and streamed status.
5. Normalize, deduplicate, rank, and export evidence.
6. Preserve missing-tool, compile, RPC, timeout, cancelled, partial, and failed states with
   remediation guidance.

