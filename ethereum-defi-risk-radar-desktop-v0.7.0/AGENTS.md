# Project instructions

This project uses Evidence-Driven Iterative Development (EDID).

## Required workflow

- Work follows Discover, Specify, Plan, Execute, Evaluate, Repair, Release, and Learn.
- Narrow fixes use the smallest cohesive change and proportional verification.
- Read applicable project records under `docs/` before broad implementation.
- Keep `docs/decisions.md` append-only and record observed evidence in
  `docs/verification.md`.
- Proceed automatically on safe reversible decisions. Ask only for destructive, paid,
  credential-dependent, externally consequential, or expensive-to-reverse choices.

## Architecture and quality

Before major implementation, security, correctness/data integrity, and reliability must
pass as hard gates. Explicitly address performance, scalability, delivery speed,
collaboration, readability, maintainability, testability, operability, accessibility, cost,
and reversibility. Select the simplest sufficient architecture and document repository
structure, ownership, dependency direction, alternatives, tradeoffs, migration path,
reassessment triggers, and verification.

## Completion language

Report only the strongest evidenced state: planned, implemented, locally verified,
deployed, or production-proven. Name checks not run and unresolved external gates.
- Treat `.edid` as the executable control plane. Run `Status`, `Validate`, and the active
  task's `Context` before implementation; read the applicable `.edid/roles/` file.
- Complete tasks only after their acceptance contract passes. Standard and high-assurance
  work requires distinct builder and evaluator identities. Run `Handoff` before pausing.
- Configure security evidence for substantive projects, browser evidence for user-facing
  applications, and deployment plus observability evidence for deployable services. Leave
  adapters disabled only when not applicable or the external system is not yet selected.
