# Verification

## Acceptance matrix

| Requirement | Evidence | Environment | Result | Date |
|---|---|---|---|---|
| GitHub can discover the production desktop release workflow | `.github/workflows/desktop-release.yml` is repository-level | Repository inspection | Implemented | 2026-09-05 |
| GitHub can discover the unsigned macOS test workflow | `.github/workflows/macos-unsigned-test.yml` is repository-level | Repository inspection | Implemented | 2026-09-05 |
| Ignored nested packaging workflows are removed | Former app-local macOS/Windows workflow files deleted | Repository inspection | Implemented | 2026-09-05 |
| Tag and package version must agree | Release metadata job compares `v<package.version>` and package-lock version | Workflow review | Implemented, not executed | 2026-09-05 |
| Release tags must originate from `main` history | Release metadata job uses `git merge-base --is-ancestor` against `origin/main` | Workflow review | Implemented, not executed | 2026-09-05 |
| macOS release is signed, notarized, Gatekeeper accepted and universal | Production workflow invokes `dist:mac` then `verify:mac`; verification checks codesign, spctl, stapler and lipo | Workflow/script review | Implemented, credentials/run pending | 2026-09-05 |
| GitHub Release contains installable assets and checksums | Publish job downloads verified artifacts, creates/updates a Release and checks expected asset names | Workflow review | Implemented, tag run pending | 2026-09-05 |

## Automated gates

| Command / workflow | Observed result | Date |
|---|---|---|
| `Build and Publish Desktop Release` | Not run after implementation; Apple distribution secrets are required for the macOS production job | 2026-09-05 |
| `Build macOS Unsigned Test Package` | Not run after repository-level migration | 2026-09-05 |

## Runtime scenarios

| Scenario | Ground truth | Observed result | Result |
|---|---|---|---|
| End user downloads signed `.dmg` from GitHub Releases and launches normally | Requires a successful tagged production workflow with configured Apple credentials | No production Release exists yet | Pending external release run |

## Unresolved evidence

- Apple Developer signing/notarization secrets must be configured in repository Actions secrets before the production macOS workflow can pass.
- A tagged release has not yet exercised the new production workflow end-to-end.
- The unsigned manual macOS workflow has not yet been executed after migration.

## Current completion state

Implemented; production release verification is pending external credentials and a tagged workflow run.
