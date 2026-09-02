# Current EDID context

- Task: desktop-analysis-lab - End-to-end desktop analysis capability integration
- Mode: high_assurance
- Risk: critical
- Status: draft
- Dependencies: none
- Contract: .edid/contracts/desktop-analysis-lab.json

## Requirements

- FR-24: Maintain a source-backed capability matrix mapping every user-facing backend workflow to desktop, CLI, and verification evidence.
- FR-25: Provide an Analysis Lab desktop screen with local project selection, native/deep engine selection, explicit execution trust, budgets, progress, cancellation, and normalized results.
- FR-26: Provide protocol scenario simulation from a selected local project and observations JSON with seed, skipped reasons, model-scope findings, and result details.
- FR-27: Provide external Anvil replay from a selected replay JSON with explicit confirmation, capability checks, fail-closed evidence labels, and visible counterexample or no-violation result.
- FR-28: Use validated, least-privilege IPC contracts and user-selected filesystem paths; do not accept private keys or silently execute untrusted projects.
- FR-29: Expose loading, empty, partial, unavailable, cancelled, failed, and complete states with accessible responsive controls and recovery guidance.
- FR-30: Preserve passive discovery, settings, reports, candidate workspaces, and CLI behavior without regression.
- NFR-10: Keep analysis bounded, cancellable where supported, evidence-honest, renderer-sandboxed, and usable without optional external tools.

## Recent evidence

- No evidence recorded yet.

## Required reading

- AGENTS.md
- docs/methodology.md
- docs/architecture.md
- docs/decisions.md
- .edid/contracts/desktop-analysis-lab.json
- .edid/roles/builder.md
