# Finding-First Security Review

Ethereum DeFi Risk Radar separates **potential impact** from **strength of evidence**. A high-severity source pattern is not automatically a confirmed exploit, and a reproduced model violation is not automatically evidence about deployed mainnet bytecode.

## Evidence ladder

| Evidence | Meaning | What it may claim |
|---|---|---|
| `HEURISTIC` | Pattern-level source review signal | Manual review is warranted |
| `STRUCTURAL` | Control/data-flow, taint, call-graph, storage, or analyzer evidence | A concrete risky program structure was observed |
| `EXECUTED` | An analyzer captured an ordered counterexample | The bounded execution falsified the stated property |
| `REPRODUCED` + `model` | The violating sequence replayed deterministically in the Risk Radar model | The model reproduces the violation |
| `REPRODUCED` + `fork` | The violating sequence replayed against pinned fork state | Evidence about deployed bytecode/state at the pinned block |

`HEURISTIC` and `STRUCTURAL` rows are **review findings**, not vulnerability confirmations. `EXECUTED` requires a captured counterexample. A bare `REPRODUCED` label is not allowed; model/fork scope must remain visible.

## Severity

Severity is retained independently as:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

The desktop security-review workspace no longer collapses `CRITICAL` and `HIGH` into the legacy `HIGH_REVIEW` display bucket. Legacy pattern-review rows that used `HIGH_REVIEW` are normalized to `HIGH` and remain labeled as pattern-level/heuristic evidence.

## Candidate review workspace

The Source Findings tab is enhanced at runtime with a finding-first workspace that provides:

- overall assessment label;
- highest observed severity;
- strongest evidence grade;
- evidence ledger counts;
- critical/high counts;
- analysis completeness warnings;
- severity and evidence filters;
- grouping by inspected contract;
- source file/line/column where available;
- analyzer engine and confidence;
- external-entry reachability;
- remediation text;
- detected mitigations;
- witness/source-to-sink paths;
- limitations;
- counterexample metadata and bounded ordered sequences.

The original renderer remains intact underneath the enhancement. The security-review layer is loaded through `desktop/preload.cjs` using packaged `security-review.js` and `security-review.css` assets. The CSS is a same-origin asset so it remains compatible with the renderer's `style-src 'self'` Content Security Policy.

## Reports

Every completed scan continues to emit the original JSON and candidate-summary CSV and additionally emits:

### `*-findings.csv`

One row per emitted security finding, including:

- candidate/protocol identity;
- contract reference/name/compiler/proxy status;
- source layer;
- finding ID/category/engine;
- severity;
- confidence;
- evidence strength and model/fork scope;
- description and remediation;
- source location;
- external reachability;
- mitigations and correlated engines;
- limitations;
- witness path;
- counterexample sequence, observed violation, seed, and pinned block when present.

### `*-security-review.html`

A standalone human-readable report organized as:

```text
Protocol candidate
  ├─ assessment status
  ├─ severity/evidence summary
  ├─ analysis completeness
  └─ contract
       └─ individual finding
            ├─ location
            ├─ description
            ├─ remediation
            ├─ witness/mitigations
            ├─ counterexample evidence
            └─ limitations
```

## Privacy and report safety

Report generation retains the existing address-redaction boundary. Full EVM addresses are replaced with `[contract-address]` before JSON, CSV, detailed CSV, or HTML serialization. Raw verified Solidity source is not written to reports.

## Partial analysis

Finding caps, source byte limits, or analyzer truncation mark the candidate as partial. The UI and HTML report explicitly warn that **absence of a finding in a partial analysis must not be interpreted as a clean pass**.

## Regression gate

`npm run check` runs `scripts/security-review-check.mjs` after the normal build/smoke check. It verifies:

- renderer JS/CSS assets are wired by preload;
- CSP-compatible stylesheet loading is present;
- a fixture emits both structural and source-review findings;
- detailed CSV and HTML reports are generated;
- evidence-grade fields are present;
- summary assessment fields are present;
- report address redaction remains enforced.

The root `.github/workflows/security-review-ci.yml` is intended to run build/smoke, analysis-engine, and proof-grade checks on pull requests from the nested application directory.
