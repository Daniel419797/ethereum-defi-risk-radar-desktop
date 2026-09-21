# Finding-first security review

Risk Radar presents verified-source analysis as individual findings rather than a protocol-wide pass/fail verdict.

## Evidence model

Severity and evidence strength are independent dimensions.

Severity uses the native analyzer scale:

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

Evidence uses:

- `HEURISTIC` — source pattern or bounded review signal;
- `STRUCTURAL` — source-linked program analysis with an auditable structural basis;
- `EXECUTED` — an engine captured a concrete ordered counterexample;
- `REPRODUCED · model` — the counterexample replayed against the project's deterministic model;
- `REPRODUCED · fork` — the counterexample replayed against pinned fork state.

A CRITICAL heuristic or structural finding is not automatically a reproduced exploit. Only a finding with the explicit `CONFIRMED_AT_PINNED_BLOCK` verdict establishes exploitability against the recorded pinned fork block and configuration.

## Finding normalization

The desktop review layer preserves advanced-analysis severity instead of collapsing CRITICAL/HIGH into the legacy `HIGH_REVIEW` source-review bucket.

Legacy regex/source-review signals are normalized as HEURISTIC evidence. Signals that are only mitigation indicators are excluded from the vulnerability list, and legacy signals are suppressed when a nearby advanced finding already represents the same security surface.

Findings are deduplicated per contract, kind, location, title, evidence level and scope.

## Completeness

Analysis limits are first-class review information. The UI and reports surface:

- advanced-analysis truncation records;
- legacy/source-review finding caps;
- verified-source byte truncation;
- analyzer partial-run state.

No-finding output is phrased as “no findings emitted in the analyzed scope.” It is not presented as proof that a protocol is vulnerability-free.

## Historical Audit Intelligence

When a permitted local Historical Audit Intelligence corpus is configured, a finding can display:

- predicted audit category and model confidence;
- historical review-priority context;
- number of retrieved historical analogues.

Historical similarity remains supporting review context. It does not increase evidence strength and does not establish exploitability.

## Desktop review

The Security Findings workspace supports:

- native CRITICAL/HIGH/MEDIUM/LOW/INFO severity;
- separate evidence-strength filtering;
- category filtering;
- severity-first, evidence-first and source-location sorting;
- grouping by inspected contract;
- engine and confidence metadata;
- exploitability verdict;
- external reachability;
- remediation guidance;
- detected mitigations;
- witness paths;
- counterexample sequence/seed/pinned block when available;
- per-finding limitations;
- Historical Audit Intelligence context.

The renderer uses DOM APIs and text nodes for dynamic content; it does not use `innerHTML`, `insertAdjacentHTML`, `eval`, or `Function`.

## Report artifacts

Each scan can emit:

1. JSON — redacted protocol/candidate data plus normalized finding rows.
2. Detailed CSV — backwards-compatible row stream containing findings, truncations and protocol-model counts.
3. Summary CSV — one row per protocol with severity/evidence counts and completeness state.
4. Findings CSV — one row per normalized security finding.
5. Standalone HTML security review — human-readable grouped finding report.

All report artifacts retain the EVM-address redaction boundary. CSV values are formula-injection protected. Dynamic HTML report fields are escaped before rendering.

## Regression gates

`npm run check` includes `scripts/security-review-check.mjs`.

The security-review regression verifies:

- CRITICAL/HIGH are not collapsed into HIGH_REVIEW;
- evidence and severity filters exist independently;
- unsafe dynamic renderer APIs are absent;
- completeness warnings are present;
- all report artifacts are generated;
- raw EVM addresses remain redacted;
- HTML report content is escaped;
- CSV formula-injection protection remains active.

The repository-level `security-review-ci.yml` workflow also runs native analysis, proof-grade and desktop-analysis regressions on relevant pull requests.
