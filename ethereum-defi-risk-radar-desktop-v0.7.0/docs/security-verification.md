# Security verification

- Completed scan: `a4bd3e47-6268-4bd7-a467-e707d30f5887`
- Mode: standard, source-backed review of product-owned source and configuration
- Open validated findings: 0
- Independent reviews: baseline code audit, architecture/threat-boundary review, focused process/traversal/IPC/economic review
- Remediated before completion: native-only PATH probing before trust, unbounded HTTP bodies/deadlines, pre-allocation traversal limits, and child-process-tree timeout handling
- Residual risk: explicitly trusted deep analysis runs project-controlled toolchains with the local user's authority. Process-tree termination is implemented; an OS-enforced Windows Job Object or container remains stronger containment.

The result is locally verified. It is not evidence of production deployment or hostile-environment proof.

## Proof-grade analysis follow-up

- Completed scan: `106c2597-85e5-4ecf-9772-43e650be4961`
- Mode: standard, focused post-remediation review of 12 proof-grade analysis artifacts
- Open validated findings: 0
- Coverage: partial repository coverage; six principal evidence-integrity trust surfaces reviewed
- Remediated before completion: unauthenticated fork confirmation, loose replay schemas and redirects, ambiguous revert semantics, analyzer success contradictions, source filename collisions, case-sensitive address redaction, and CSV formula-leading cells
- Residual risk: caller-selected loopback Anvil is not process-authenticated and therefore earns only `EXECUTED (model scope)`, never `CONFIRMED_AT_PINNED_BLOCK`.

Measured scan usage: 921,450 total tokens across one scan thread. The scan is locally completed; it is not production proof.

## Desktop Analysis Lab follow-up

- Completed scan: `3d147a79-6bce-472e-bb87-e9b48da25fd0`
- Mode: standard, focused review of nine Analysis Lab trust and execution surfaces
- Open validated findings: 0
- Coverage: partial; parent-performed source review plus executable integration, proof, analysis, build, smoke, and browser checks
- Hardened before completion: runtime analyzer allowlisting, native confirmation for project-controlled tools, finite non-negative initial economic state, abort propagation, and cleanup after replay cancellation
- Deferred evidence: independent delegated review and live Slither, Mythril, Foundry, Echidna, and Anvil execution were unavailable in this run

This result is locally verified and does not establish deployment, production behavior, or hostile-environment proof.
