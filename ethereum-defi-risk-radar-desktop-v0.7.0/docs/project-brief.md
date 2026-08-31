# Project brief

## Problem and users

- Problem: v0.7 finds source keywords but cannot explain program paths, value propagation,
  multi-contract state, executable counterexamples, or DeFi economic risk.
- Users: smart-contract auditors, protocol engineers, security researchers, and risk teams
  reviewing systems they are authorized to assess.
- Job: provide evidence-ranked static and dynamic analysis without making heavyweight tools
  mandatory for ordinary desktop use.
- Success: native static analysis works without Python or Docker; installed external engines
  are detected and invoked with bounded resources; unavailable engines degrade clearly; every
  result identifies its engine, evidence, confidence, and limitations.

## Scope

### MVP

- Engine-neutral types for control/data/taint/storage/calls, symbolic execution, fuzzing,
  invariants, economic simulations, capabilities, budgets, and run states.
- Native deterministic source analysis for control/data/taint/storage/cross-contract signals.
- Optional adapters for Slither, Mythril, Foundry/Anvil, and Echidna when locally installed.
- Desktop, CLI, JSON, and CSV visibility for capabilities and normalized findings.

### Production

- Verified-address and uploaded Foundry/Hardhat inputs.
- Cancellable workers with time, output, process, and filesystem limits.
- Stateful scenarios for lending, AMMs, vaults, staking, bridges, governance, derivatives,
  stablecoins, yield aggregators, wrappers, and liquidation systems.
- Reproducible traces, seeds, block numbers, assumptions, and deduplication.

### Future

- Additional EVM networks, remote isolated workers, mutation/differential testing, automated
  invariant suggestions, and protocol-specific scenario packs.

## Non-goals, constraints, and assumptions

- Output is evidence for review, never a guarantee of safety or exploitability.
- External binaries, Python, Docker, RPC endpoints, and paid providers are optional.
- No private keys are required. Transaction broadcasting is a separate future boundary.
- All-category support uses shared primitives and an extensible registry; it does not imply
  that every protocol-specific invariant can be discovered automatically.

## Decisions

| Decision | Choice | Status |
|---|---|---|
| Inputs | Verified addresses and local projects | Accepted |
| Static engine | Native layer plus optional Slither | Accepted |
| Dynamic engines | Optional Foundry, Echidna, and Mythril | Accepted |
| RPC | Optional user-supplied endpoint | Accepted |
| Scope | Shared primitives for all DeFi categories | Accepted |
| External execution | Explicit bounded local worker | Accepted |

