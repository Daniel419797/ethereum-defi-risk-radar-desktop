# Decision log

Append decisions; never renumber or erase history. Supersede an old ADR with a new one.

## ADR-1 - Adopt Evidence-Driven Iterative Development

**Status.** Accepted

**Context.** The project needs consistent scope, delivery, verification, and handoff.

**Decision.** Use EDID with proportional full and lightweight loops.

**Consequences.** Completion claims require evidence; irrelevant ceremony is omitted.

## ADR-2 - Use hybrid native and optional external analysis

**Status.** Accepted

**Context.** Advanced analysis is required while Python, Docker, toolchains, and RPC remain
optional. Reimplementing a compiler, solver, EVM, and mature fuzzer fails hard quality gates.

**Decision.** Add a dependency-free native triage layer and engine-neutral result model.
Place locally installed Slither, Mythril, Foundry/Anvil, and Echidna behind bounded adapters.
Missing tools are expected capability states.

**Consequences.** Native findings remain conservative. Executable evidence depends on optional
tools, while tool drift stays isolated to adapters.

## ADR-3 - Compose all DeFi categories from shared economic primitives

**Status.** Accepted

**Context.** Separate simulators would duplicate actors, accounting, prices, liquidity,
governance, and invariants.

**Decision.** Define shared actors, assets, pools, positions, oracles, governance, bridge, and
balance-sheet primitives, then compose versioned category scenario packs.

**Consequences.** Broad coverage is extensible and testable; every protocol-specific model
must still declare assumptions and cannot claim universal exploit coverage.
## ADR-4: Evidence is earned by artifacts, not inferred from engine identity

**Status:** Accepted, 2026-08-31.

**Context.** The first expanded engine unconditionally labelled Mythril, Foundry, and Echidna
rows as `EXECUTED`, silently capped native rules, and could not distinguish a model witness
from deployed-code reproduction.

**Decision.** Route every finding through one evidence invariant. Static output remains
heuristic or structural. `EXECUTED` requires a parsed counterexample. `REPRODUCED` requires a
successful deterministic replay and an explicit `model` or `fork` scope; fork scope also
requires a pinned block. Caps produce truncation records. Protocol simulation derives its
initial state from an analyzed protocol graph and remains model-scoped unless a fork replay
confirms the same sequence.

**Alternatives.** Keeping engine-based labels was rejected for correctness. Treating every
external analyzer result as heuristic was safer but discarded real counterexample evidence.
Making fork infrastructure mandatory was rejected because optional tools and RPC access are
an explicit product constraint.

**Consequences.** Claims become mechanically conservative and replayable. The model and fork
backends remain replaceable; reassess when compiler-semantic IR or a sandboxed remote runner
becomes available.
