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

## ADR-5 - Present advanced workflows through one Analysis Lab

**Status.** Accepted, 2026-09-01.

**Context.** Local-project analysis, protocol simulation, and external Anvil replay existed as
backend/CLI workflows but had no desktop entry points, leaving the product boundary incomplete.

**Decision.** Add one responsive Analysis Lab screen and narrow IPC methods backed by the same
orchestrator used by the CLI. The main process owns user-selected paths, validation, trust and
confirmation gates, progress, cancellation, and normalized results.

**Alternatives.** Separate windows increase state duplication. A localhost API adds needless
authentication and networking risk. Reimplementing analysis in the renderer violates sandboxing.

**Consequences.** Every user-facing backend workflow becomes discoverable in the desktop without
forking domain logic. The screen is denser, so mobile layout and keyboard behavior are release gates.

## ADR-6 - Promote only contract-resolved protocols from web discovery

**Status.** Accepted, 2026-09-02.

**Context.** Passive discovery keyed candidates by search-result hostname and page title. Academic
papers, developer-tool lists, audit articles, and other documents could therefore appear in Results
without a deployed contract, verified source, or automatic source analysis. Etherscan enrichment was
only attempted when an address happened to be present in the original search snippet.

**Decision.** Treat public search results as leads rather than protocol entities. Infer only a
conservative protocol identity, reject document-only and generic-resource leads, perform a bounded
Etherscan-targeted resolution search, and promote a row to Results only when at least one Ethereum
Mainnet address returns verified source metadata. Proxy implementation resolution consumes the same
configured Etherscan lookup budget, and verified source is handed directly to the existing source
analyzer when source inspection is enabled. Without Etherscan verification, no document lead is
promoted to a protocol candidate.

**Alternatives.** Relabelling the current Results screen as a document-lead list was rejected because
it would preserve the broken product boundary. Trusting arbitrary addresses mentioned in articles was
rejected because reports may mention attacker, token, governance, or unrelated addresses. Requiring
live RPC probing was rejected because passive operation remains a product constraint.

**Consequences.** Results now represent contract-backed protocol research candidates instead of web
pages. Discovery becomes stricter and may return fewer rows, especially without Etherscan configured.
The resolver is deliberately bounded and heuristic; protocol aliases and multi-deployment grouping can
be improved later without weakening the verified-source promotion gate.

## ADR-7 - Keep Historical Audit Intelligence local, bounded, and subordinate to evidence

**Status.** Accepted, 2026-09-04.

**Context.** A third-party corpus provides 23,625 historical smart-contract audit findings and can
improve taxonomy, retrieval, remediation context, and analyzer evaluation. The corpus is raw and
semi-structured, contains many placeholder PoCs/recommendations, and its dataset card declares
`license: other` with unclear underlying audit-report redistribution/commercial-use rights. Historical
similarity also cannot prove that a current deployed contract is vulnerable or exploitable.

**Decision.** Implement three layers: (1) a deterministic local cleaning/evaluation pipeline that
normalizes and deduplicates the corpus while discarding PoC code; (2) Historical Audit Intelligence
that retrieves bounded analogues for existing source/structural findings; and (3) dependency-free local
statistical models using Naive Bayes classification plus TF-IDF similarity and deterministic holdout
evaluation. Generated corpora stay outside Git and installers. The default runtime path is under the
user's home directory and can be overridden with `RISK_RADAR_AUDIT_CORPUS`. Historical scores are
review-prioritization context only and never modify `HEURISTIC`, `STRUCTURAL`, `EXECUTED`, or
`REPRODUCED` evidence strength.

**Alternatives.** Bundling the full corpus was rejected because provenance rights are unresolved.
Sending findings to an external embedding/LLM service was rejected because the offline baseline and
privacy boundary are product requirements. Training an exploit-generation model was rejected because
it is unnecessary for defensive triage and would expand safety and distribution risk. Treating
historical similarity as a vulnerability verdict was rejected for correctness.

**Consequences.** Users who prepare the local corpus gain historical analogues, category prediction,
historical severity context, and common remediation patterns without weakening evidence semantics.
The application remains useful without the corpus. Reassess bundling or derived-model distribution
only after dataset provenance and commercial-use rights are explicitly resolved.
