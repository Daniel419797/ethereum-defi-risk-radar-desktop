# Ethereum DeFi Risk Radar

> Defensive Ethereum Mainnet protocol discovery, verified-source analysis, historical audit intelligence, deep local security analysis, economic simulation, and evidence-driven review in one desktop + CLI application.

**Ethereum DeFi Risk Radar** is a cross-platform defensive research tool for discovering Ethereum DeFi protocols from public evidence, resolving their real Mainnet contracts, retrieving verified Solidity source, analyzing that source for security-relevant patterns, and escalating suspicious findings through progressively stronger forms of evidence.

The project is intentionally conservative: it distinguishes **research signals**, **structural findings**, **executed counterexamples**, and **reproduced behavior** instead of treating every suspicious code pattern as a confirmed vulnerability.

The main application currently lives in:

```text
ethereum-defi-risk-radar-desktop-v0.7.0/
```

---

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [Core capabilities](#core-capabilities)
- [How Risk Radar works](#how-risk-radar-works)
- [Evidence model](#evidence-model)
- [Discovery and protocol resolution](#discovery-and-protocol-resolution)
- [Verified Solidity analysis](#verified-solidity-analysis)
- [Historical Audit Intelligence](#historical-audit-intelligence)
- [Deep analysis tools](#deep-analysis-tools)
- [Economic and protocol simulation](#economic-and-protocol-simulation)
- [Desktop application](#desktop-application)
- [CLI](#cli)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [API keys](#api-keys)
- [Processing the historical audit dataset](#processing-the-historical-audit-dataset)
- [Testing and quality gates](#testing-and-quality-gates)
- [Building installers](#building-installers)
- [Repository structure](#repository-structure)
- [Security boundaries](#security-boundaries)
- [What Risk Radar does not claim](#what-risk-radar-does-not-claim)
- [EDID development workflow](#edid-development-workflow)
- [Current development status](#current-development-status)

---

# Why this project exists

Smart-contract security research often requires several disconnected steps:

1. discover a protocol or security-relevant project;
2. determine whether the search result actually represents a real protocol rather than a paper, article, tool list, or audit document;
3. resolve the deployed Ethereum Mainnet contracts;
4. identify proxies and implementation contracts;
5. retrieve verified Solidity source;
6. run structural analysis;
7. compare suspicious behavior with prior audit findings;
8. use stronger tools such as static analyzers, symbolic execution, fuzzing, invariants, or controlled replay;
9. preserve the difference between suspicion and actual evidence.

Risk Radar brings those stages into one bounded workflow.

The product goal is not to produce sensational "vulnerable/not vulnerable" labels. The goal is to give a security researcher a progressively stronger body of evidence while keeping provenance, uncertainty, limits, and execution scope explicit.

---

# Core capabilities

| Capability | Purpose |
|---|---|
| **TinyFish discovery** | Searches public web sources for Ethereum DeFi protocol leads, audits, migrations, incidents, archived projects, governance concerns, and other review signals. |
| **Protocol-first resolution** | Prevents papers, GitHub resource lists, research articles, and generic documents from being promoted as protocol results. |
| **Etherscan V2 integration** | Resolves real Ethereum Mainnet contracts, verifies source availability, and follows proxy-to-implementation relationships within configured limits. |
| **Native Solidity analysis** | Performs dependency-free structural review of verified Solidity source. |
| **Source finding location** | Associates findings with source file and line where possible. |
| **Protocol modelling** | Builds protocol-level information from verified source and cross-contract relationships. |
| **Historical Audit Intelligence** | Compares current findings with a locally cleaned corpus of historical smart-contract audit findings. |
| **Local classification and retrieval** | Uses deterministic local statistical classification plus TF-IDF/cosine retrieval for historical analogues. |
| **Slither adapter** | Adds compiler-aware static analysis when Slither is installed. |
| **Mythril adapter** | Adds bounded symbolic EVM exploration and counterexample evidence when available. |
| **Foundry / Forge integration** | Runs trusted local Solidity tests and invariant workflows. |
| **Echidna integration** | Adds bounded stateful property-based fuzzing. |
| **Anvil replay** | Supports explicit, controlled local replay against pinned Ethereum state. |
| **Economic simulation** | Models protocol-level scenarios such as price shocks, flash liquidity, liquidation cascades, governance capture, bridge replay, rounding, and MEV ordering. |
| **Desktop UI** | Provides discovery, results, candidate review, source findings, activity, settings, and Analysis Lab workflows. |
| **Installed CLI** | Exposes the same research and analysis workflows from the terminal. |
| **Encrypted credentials** | Stores desktop API credentials through Electron `safeStorage` instead of plaintext application configuration. |

---

# How Risk Radar works

The normal automatic discovery path is:

```text
Public web
    │
    ▼
TinyFish search
    │
    ▼
Protocol-shaped lead
    │
    ├── reject papers / surveys / tool lists / generic resources
    │
    ▼
Ethereum Mainnet contract resolution
    │
    ▼
Etherscan verification
    │
    ├── real contract?
    ├── verified source?
    ├── proxy?
    └── implementation?
    │
    ▼
Verified Solidity source
    │
    ├───────────────┐
    ▼               ▼
Native analysis     Historical Audit Intelligence
    │               │
    └───────┬───────┘
            ▼
       Research finding
            │
   optional deeper analysis
            │
   ┌────────┼───────────┐
   ▼        ▼           ▼
Slither   Mythril    Foundry/Echidna
                       │
                       ▼
                     Anvil
                 controlled replay
```

A public document is therefore a **lead**, not automatically a protocol result.

A candidate reaches the protocol results workflow only after Risk Radar resolves a real Ethereum Mainnet deployment and validates verified source metadata through Etherscan.

---

# Evidence model

Risk Radar uses progressively stronger evidence levels.

```text
PUBLIC SIGNAL
    │
    │ Something is worth investigating.
    ▼
VERIFIED SOURCE
    │
    │ The actual deployed contract/source has been resolved.
    ▼
STRUCTURAL / HEURISTIC FINDING
    │
    │ Suspicious code or data-flow behavior was detected.
    ▼
EXECUTED COUNTEREXAMPLE
    │
    │ A bounded execution produced a concrete failing sequence.
    ▼
REPRODUCED BEHAVIOR
    │
    │ A deterministic replay reproduced the behavior in an
    │ explicitly stated model or pinned-fork scope.
    ▼
RESEARCHER CONCLUSION
```

The key rule is:

> **Engine identity does not determine evidence strength. Evidence is earned by the artifact produced.**

For example, a Mythril result is not automatically treated as executed evidence unless a usable counterexample was actually captured. Likewise, a low-level call found by static analysis is not automatically a vulnerability.

Important labels include:

- `HIGH_RESEARCH_PRIORITY` — stronger public research signal;
- `HIGH_REVIEW` — source/analysis item deserving human review;
- `EXECUTED` — an ordered counterexample or equivalent executed artifact exists;
- `REPRODUCED` — deterministic replay evidence exists;
- `CONFIRMED_AT_PINNED_BLOCK` — reserved for evidence meeting the project's strict pinned-fork confirmation requirements.

---

# Discovery and protocol resolution

## TinyFish

TinyFish is the public-web discovery layer.

It searches for signals such as:

- deprecated or decommissioned protocols;
- migrations;
- archived repositories;
- historical incidents;
- public audit findings;
- governance/admin-key concerns;
- upgradeability and proxy discussions;
- legacy project activity;
- security postmortems.

TinyFish does **not** determine that a protocol is vulnerable. It discovers leads and public evidence.

## Etherscan

Etherscan is the identity and verified-source bridge between public research and actual deployed Ethereum contracts.

Risk Radar uses Etherscan V2 to:

- validate Ethereum Mainnet contract addresses;
- determine whether source is verified;
- retrieve contract name and compiler metadata;
- identify proxies;
- resolve implementation addresses where available;
- provide verified Solidity to the source analyzer.

The application can launch without an Etherscan key, but **automatic public-web protocol promotion intentionally fails closed without Etherscan verification**. Documents are not promoted to protocol candidates simply because they mention Ethereum.

---

# Verified Solidity analysis

Risk Radar includes a built-in dependency-free Solidity analysis layer so the core product remains useful without requiring Python, Docker, Slither, Mythril, Foundry, or Echidna.

The verified-source review layer currently detects or models surfaces including:

- `tx.origin` authorization;
- `delegatecall` boundaries;
- self-destruct surfaces;
- low-level calls;
- value-bearing calls;
- inline assembly;
- privileged/admin access;
- upgradeability and proxy patterns;
- initializer patterns;
- reentrancy-guard indicators;
- unchecked arithmetic blocks;
- signature recovery;
- oracle/price dependencies;
- token-accounting compatibility;
- fee-on-transfer and non-standard token assumptions;
- permit/signature nonce behavior;
- cross-chain/bridge messaging;
- liquidation and solvency surfaces;
- MEV/slippage/deadline surfaces.

The deeper native analyzer also models or evaluates:

- control-flow graphs;
- external reachability;
- data dependencies;
- taint paths;
- storage/state writes;
- cross-contract calls;
- reentrancy ordering;
- authorization boundaries;
- oracle freshness/manipulation;
- arithmetic precision;
- gas/DoS conditions;
- signatures/replay;
- governance behavior;
- bridge messaging;
- token integration.

These are review signals and structural findings unless stronger execution evidence is produced.

---

# Historical Audit Intelligence

Historical Audit Intelligence adds context from real historical smart-contract audit findings.

The current implementation is designed around the **Zaevlad Smart Contract Audit Findings dataset**, which contains more than twenty-three thousand raw audit findings.

Because the source dataset has unclear third-party redistribution/commercial-use provenance, Risk Radar does **not bundle the dataset into the application**. The corpus is processed locally by the user.

## Three-stage design

### Stage 1 — dataset preparation

Risk Radar includes a local dataset preparation pipeline that:

- downloads only the approved dataset source or accepts a local CSV;
- bounds input size;
- parses CSV deterministically;
- removes malformed records;
- normalizes whitespace;
- removes researcher attribution from titles;
- normalizes severity;
- identifies placeholder PoC/recommendation values;
- deliberately excludes PoC/exploit content from the cleaned corpus;
- deduplicates findings using a stable hash;
- assigns a deterministic vulnerability taxonomy;
- recomputes a quality score;
- preserves the upstream weight only as source metadata;
- creates a deterministic 80/20 train/benchmark split;
- generates corpus metadata and evaluation output.

### Stage 2 — historical matching

For a current Risk Radar finding, the historical engine can return:

- predicted vulnerability category;
- model confidence;
- closest historical audit analogues;
- similarity values;
- historical severity distribution;
- common remediation patterns;
- historical review-priority context score.

A historical match is **supporting context, not proof that the current contract is vulnerable**.

### Stage 3 — local statistical intelligence

The project includes a dependency-free local statistical engine using:

- multinomial Naive Bayes for category classification;
- TF-IDF/cosine similarity for historical retrieval;
- deterministic benchmark evaluation;
- per-category precision/recall/F1 reporting;
- top-5 category retrieval hit-rate measurement.

This makes the intelligence layer measurable and reproducible without requiring an external LLM service.

## Audit taxonomy

The current historical taxonomy contains categories including:

```text
reentrancy
access_control
oracle_price
accounting_state
precision_rounding
token_integration
signature_replay
upgradeability
denial_of_service
mev_front_running
governance
bridge_cross_chain
liquidation
flash_liquidity
input_validation
gas_economic
business_logic
other
```

---

# Deep analysis tools

The core scanner does not require these tools, but Risk Radar detects and uses them when available through the Analysis Lab.

## Slither

Purpose: compiler-aware Solidity static analysis.

Useful for:

- control/data flow;
- dependency reasoning;
- detector output;
- storage interaction;
- taint-like relationships;
- contract relationships.

## Mythril

Purpose: bounded symbolic EVM execution.

Useful for exploring whether suspicious behavior can be reached under symbolic inputs and for producing counterexample sequences when available.

## Foundry / Forge

Purpose: trusted local Solidity testing and invariants.

Useful for:

- unit tests;
- fuzz tests;
- invariant testing;
- controlled reproduction projects.

Running repository-controlled build/test logic requires explicit project trust.

## Echidna

Purpose: stateful property-based smart-contract fuzzing.

Useful for searching sequences of transactions and inputs that violate explicitly defined security properties.

## Anvil

Purpose: controlled local Ethereum execution/replay.

Risk Radar's replay flow is deliberately constrained. Replay uses an explicitly approved loopback Anvil endpoint, validates expected chain/block information, and does not require or custody a Mainnet private key.

## Python and Docker

Python and Docker are detected as environment capabilities because optional security tools may depend on them, but neither is required by the core Risk Radar discovery or native-analysis workflow.

---

# Economic and protocol simulation

Risk Radar also contains a bounded economic-analysis layer for protocol-level reasoning.

The simulator models shared primitives such as:

- actors;
- assets;
- balances;
- pools;
- positions;
- prices/oracles;
- governance;
- bridges;
- protocol accounting.

Scenario packs cover classes such as:

- oracle/price shocks;
- flash-liquidity conditions;
- liquidity withdrawal/runs;
- liquidation cascades;
- rounding/donation inflation;
- governance capture;
- cross-domain replay;
- MEV/transaction ordering;
- bad debt and solvency stress;
- fee extraction;
- cross-protocol contagion.

Simulation results are model-scoped unless stronger replay evidence exists.

---

# Desktop application

The Electron desktop application is the recommended interface.

Main screens include:

- **First-launch setup** — TinyFish and Etherscan credentials plus scan configuration;
- **Dashboard** — scan controls, progress, connection state, metrics, and live activity;
- **Results** — verified protocol results with source-analysis state and review metrics;
- **Candidate workspace** — protocol overview, source findings, and public evidence;
- **Source Findings** — severity/category filters, file/line information, native analysis, and historical context when a local corpus is available;
- **Activity** — execution logs and recent scan summary;
- **Analysis Lab** — trusted local-project analysis, economic simulation, and explicit replay workflows;
- **Settings** — credentials, limits, reports, tool capabilities, and installed CLI management.

The renderer is sandboxed and does not receive direct filesystem/process primitives.

---

# CLI

The application includes both a development Node.js CLI and an installed end-user `risk-radar` CLI.

Common installed commands include:

```bash
risk-radar help
risk-radar status
risk-radar doctor
risk-radar capabilities
risk-radar scan --start=2016 --end=2026 --pages=1
risk-radar test-connections
risk-radar reports
risk-radar open-reports
risk-radar analyze-project /path/to/project
risk-radar economic-scenarios
risk-radar simulate-economic /path/to/scenario.json
risk-radar simulate-protocol /path/to/project /path/to/observations.json --seed=1
risk-radar replay-fork /path/to/replay-spec.json --confirm-fork
```

The installed CLI shares the desktop application's encrypted credentials and does not print stored API-key values.

See the detailed CLI documentation under:

```text
ethereum-defi-risk-radar-desktop-v0.7.0/docs/CLI.md
```

---

# Requirements

For source development:

- **Node.js >= 20.12**
- npm

Optional tools for deeper analysis:

- Slither
- Mythril
- Foundry / Forge / Anvil
- Echidna
- Python
- Docker

API/service access:

- **TinyFish API key** — required for automatic public-web discovery;
- **Etherscan API key** — required for automatic protocol resolution/promotion from public-web leads and verified-source analysis.

---

# Quick start

Clone the repository:

```bash
git clone https://github.com/Daniel419797/ethereum-defi-risk-radar-desktop.git
cd ethereum-defi-risk-radar-desktop
```

Enter the application directory:

```bash
cd ethereum-defi-risk-radar-desktop-v0.7.0
```

Install dependencies:

```bash
npm install
```

Build:

```bash
npm run build
```

Run the verification suite:

```bash
npm run check
```

Launch the desktop application:

```bash
npm run desktop
```

The first launch walks through credential and scan-limit configuration.

---

# API keys

## Desktop

Desktop credentials are stored with Electron `safeStorage` using OS-backed encryption.

The renderer is only told whether credentials exist; stored secret values are not returned to normal renderer UI code.

## Developer CLI

The source/developer CLI can also use environment variables during local development. See:

```text
ethereum-defi-risk-radar-desktop-v0.7.0/.env.example
```

Never commit real API keys.

---

# Processing the historical audit dataset

Historical Audit Intelligence is intentionally local-first because the third-party dataset's redistribution/commercial-use rights are not sufficiently clear for bundling.

Switch to a revision containing the audit-intelligence implementation, then from the application directory run:

```bash
npm install
npm run audit:prepare
```

The preparation command builds the project, downloads the approved public dataset, cleans it, builds the benchmark split, and writes the generated corpus to the user's Risk Radar data directory.

Default output:

### Windows

```text
C:\Users\<username>\.defi-risk-radar\audit-intelligence\
```

### macOS / Linux

```text
~/.defi-risk-radar/audit-intelligence/
```

Generated files:

```text
cleaned-audit-findings.jsonl
audit-benchmark.jsonl
audit-dataset-stats.json
audit-evaluation.json
```

The full local corpus is not committed to Git.

To process an already downloaded local CSV:

```bash
npm run audit:prepare -- --source="/path/to/bug_list.csv"
```

On Windows CMD:

```cmd
npm run audit:prepare -- --source="C:\Users\YOUR_USERNAME\Downloads\bug_list.csv"
```

A custom output directory can also be supplied:

```bash
npm run audit:prepare -- --source="/path/to/bug_list.csv" --output="/path/to/audit-intelligence"
```

If a custom output path is used, configure:

```text
RISK_RADAR_AUDIT_CORPUS=/path/to/cleaned-audit-findings.jsonl
```

Risk Radar otherwise automatically checks its default audit-intelligence directory.

## Dataset safety and provenance

The prepared corpus records:

```text
licenseStatus: UNVERIFIED_THIRD_PARTY
redistributionAllowed: false
```

The cleaner deliberately does not preserve exploit/PoC payloads in the prepared corpus. A boolean `hasPoc` indicator may be retained for research-quality context.

Do not redistribute or bundle the generated third-party corpus into commercial installers until the underlying rights are confirmed.

---

# Testing and quality gates

From the application directory:

```bash
npm run build
npm run check
```

Focused suites include:

```bash
npm run test:discovery
npm run test:protocol-ui
npm run test:analysis
npm run test:proof
npm run test:desktop-analysis
npm run test:audit-intelligence
```

The main `check` workflow includes TypeScript build and core regression/smoke checks.

The project treats the following as hard gates for substantive changes:

- security/privacy;
- correctness/data integrity;
- reliability/recovery.

Other explicit quality concerns include performance, scalability, maintainability, testability, operability, accessibility, cost, and reversibility.

---

# Building installers

## Windows

From the application directory:

```bash
npm run dist:win
```

Expected artifact:

```text
release/
  Ethereum-DeFi-Risk-Radar-Setup-0.7.0.exe
```

## macOS

Production universal build:

```bash
npm run dist:mac
```

Unsigned development-only build:

```bash
npm run dist:mac:unsigned
```

Architecture-specific builds:

```bash
npm run dist:mac:x64
npm run dist:mac:arm64
```

Production macOS distribution requires the appropriate Apple signing/notarization credentials and should pass the project's macOS verification scripts before release.

---

# Repository structure

High-level structure:

```text
ethereum-defi-risk-radar-desktop/
│
├── README.md                         # repository-level documentation
├── AGENTS.md                         # EDID project instructions
├── .edid/                            # executable EDID control plane
├── docs/                             # repository-level engineering records
│
└── ethereum-defi-risk-radar-desktop-v0.7.0/
    ├── README.md                     # application/release documentation
    ├── package.json
    ├── src/
    │   ├── scanner.ts                # public discovery + protocol resolution
    │   ├── etherscan.ts              # Etherscan verified-source integration
    │   ├── sourceAnalyzer.ts         # verified Solidity inspection
    │   ├── auditIntelligence/        # historical audit engine
    │   ├── analysis/
    │   │   ├── model.ts
    │   │   ├── native/               # dependency-free structural analysis
    │   │   ├── adapters/             # Slither/Mythril/Foundry/Echidna
    │   │   └── economic/             # protocol economic models/scenarios
    │   └── desktop/                  # Electron main-process integration
    │
    ├── desktop/
    │   ├── preload.cjs
    │   └── renderer/                 # desktop UI
    │
    ├── scripts/
    │   ├── prepare-audit-dataset.mjs
    │   ├── smoke-check.mjs
    │   ├── protocol-discovery-check.mjs
    │   ├── audit-intelligence-check.mjs
    │   └── other release/test scripts
    │
    ├── docs/
    │   ├── architecture.md
    │   ├── decisions.md
    │   ├── verification.md
    │   └── CLI.md
    │
    └── .github/workflows/
```

---

# Security boundaries

Risk Radar is designed as a defensive research product.

Important boundaries include:

- no automatic Mainnet transaction signing;
- no private-key custody;
- no silent transaction submission;
- no automatic active probing of discovered live contracts;
- no arbitrary shell command construction for analysis engines;
- external analyzers are invoked through bounded allowlisted adapters;
- project-controlled build/test execution requires explicit trust;
- raw verified Solidity is analyzed transiently rather than written into normal reports;
- full Ethereum addresses are redacted from safe report output where required by the reporting model;
- process execution is bounded by time/output limits;
- replay requires explicit confirmation and controlled scope;
- missing optional tools are normal capability states, not fatal errors;
- historical audit similarity never upgrades evidence strength by itself.

Electron desktop boundaries include:

- `nodeIntegration: false`;
- `contextIsolation: true`;
- renderer sandboxing;
- narrow `contextBridge` IPC;
- restrictive navigation handling;
- API-secret ownership in the main process;
- OS-backed credential encryption.

---

# What Risk Radar does not claim

Risk Radar does **not** claim that it:

- discovers every DeFi vulnerability;
- proves exploitability from regex or static patterns;
- guarantees a protocol is safe when no finding is returned;
- treats historical similarity as vulnerability confirmation;
- treats public incidents as proof that the current deployed version remains vulnerable;
- automatically performs offensive Mainnet exploitation;
- sends transactions on behalf of a researcher;
- replaces professional manual smart-contract auditing.

A finding such as:

```text
HIGH REVIEW
External interaction requires reentrancy ordering review
Vault.sol:184
```

means **review this path**, not **this contract is definitely exploitable**.

Historical intelligence such as:

```text
Historical analogue similarity: 91%
Historical review-priority context: 78 / 100
```

means **this resembles historical audit findings and deserves investigation**, not **78% chance of exploitation**.

---

# EDID development workflow

This repository uses **EDID — Evidence-Driven Implementation & Delivery**.

Development follows an evidence-oriented lifecycle:

```text
Discover
   ↓
Specify
   ↓
Plan
   ↓
Execute
   ↓
Evaluate
   ↓
Repair
   ↓
Release
   ↓
Learn
```

The repository's EDID control plane lives under `.edid/`, while architecture decisions and verification evidence are maintained under `docs/` and the application-level documentation directory.

Completion language is evidence-based: work should be described as planned, implemented, locally verified, deployed, or production-proven according to the strongest evidence actually available.

---

# Current development status

Current source includes the protocol-first discovery architecture and the Historical Audit Intelligence implementation on the active feature branch.

Historical Audit Intelligence includes:

- the dataset cleaner;
- deterministic taxonomy;
- local classification;
- TF-IDF historical retrieval;
- benchmark evaluation;
- verified-source integration;
- additional audit-derived review surfaces.

The third-party corpus itself is intentionally **not committed or bundled**. It must be prepared locally with:

```bash
npm run audit:prepare
```

Before treating a release as production-ready, use the repository's build/tests and external quality gates rather than assuming implementation alone implies release readiness.

---

## Project principle

> **Risk Radar should increase the strength of the evidence at every stage without overstating what the evidence proves.**

That principle governs discovery, source analysis, historical matching, external analyzers, simulations, replay, UI wording, and reports.
