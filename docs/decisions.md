# Decision log

Append decisions; never renumber or erase history. Supersede an old ADR with a new one.

## ADR-1 - Adopt Evidence-Driven Iterative Development

**Status.** Accepted

**Context.** The project needs consistent scope, delivery, verification, and handoff.

**Decision.** Use EDID with proportional full and lightweight loops.

**Consequences.** Completion claims require evidence; irrelevant ceremony is omitted.

## ADR-2 - Publish desktop releases only from repository-level gated workflows

**Status.** Accepted, 2026-09-05

**Context.** Packaging workflows stored below the nested application directory were invisible to GitHub Actions because workflow discovery only occurs under the repository-level `.github/workflows/` directory. The macOS build also uploaded workflow artifacts but did not create an end-user GitHub Release, so a normal user could not install the application from the repository's Releases page.

**Decision.** Move release automation to repository-level workflows. Use one production desktop-release workflow that validates package/tag versions and `main` ancestry, runs repository/deep-analysis gates, builds and verifies a signed/notarized universal macOS package plus the Windows installer, and publishes GitHub Release assets only after both platform jobs pass. Keep unsigned macOS packaging in a separate manual-only workflow and never publish its output as a production release.

**Consequences.** Tagged releases fail closed when signing, notarization, Gatekeeper, architecture, CLI, installer, test, version, or release-asset checks fail. Apple distribution secrets remain an external prerequisite and are never committed. A release tag must match the application version and point to `main`.
