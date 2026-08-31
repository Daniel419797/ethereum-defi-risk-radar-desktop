# Changelog

## 0.7.0 — bundled desktop CLI

- Added the installed `risk-radar` terminal command to the Windows/macOS desktop distribution.
- Added a headless Electron CLI runtime so the terminal and GUI share the same `safeStorage`-encrypted TinyFish/Etherscan credentials and preferences.
- Added `scan`, `status`, `doctor`, `test-connections`, `reports`, `open-reports`, `config`, `install-cli`, `uninstall-cli`, `version` and `help` commands.
- Added non-echoing interactive API-key entry for CLI credential changes.
- Added Windows NSIS provisioning/removal of `risk-radar.cmd` in the user WindowsApps command directory.
- Added macOS user-level CLI installation at `~/.local/bin/risk-radar` with bounded shell-profile PATH integration.
- Added first-launch CLI installation control and Settings install/repair/removal UI.
- Added `cli/launch.cjs`, packaged outside ASAR, to bridge the packaged Electron runtime into headless CLI mode without requiring Node.js on the end-user machine.
- Added packaged CLI verification to Windows and macOS CI/release checks.
- Added `docs/CLI.md` with installation, commands, configuration and security behavior.
- Preserved all v0.6 macOS signing/notarization and v0.5 desktop research UI/security guardrails.

## 0.6.0 — macOS production distribution

- Added production macOS desktop distribution.
- Upgraded Electron from the unsupported 38.x line to supported Electron 43.x while retaining macOS 12 Monterey compatibility.
- Added a universal x86_64 + arm64 macOS target for Intel and Apple Silicon.
- Added DMG and ZIP outputs with architecture-specific artifact naming.
- Added a native `.icns` app icon and branded Retina-capable DMG background.
- Added Hardened Runtime and Electron JIT entitlements for production signing.
- Added electron-builder notarization configuration.
- Added production `build-macos.sh` with signing/notarization prerequisite checks.
- Added an explicit unsigned macOS test-build path that must not be distributed.
- Added `verify-macos.sh` for codesign, Gatekeeper, stapler and universal-binary verification.
- Added a signed/notarized macOS GitHub Actions workflow using Developer ID + App Store Connect API-key credentials.
- Added a manual unsigned-test macOS GitHub Actions workflow.
- Added macOS native application menus, standard edit/view/window roles, About panel and `⌘,` Settings shortcut.
- Added renderer app/platform metadata through restricted IPC and dynamic version display.
- Added macOS Keychain-specific secure-storage messaging.
- Added detailed macOS distribution documentation and secret-handling rules.
- Preserved the full v0.5 desktop UI, scanner logic, CLI and defensive guardrails.

## 0.5.0 — Desktop workspace redesign

- Rebuilt the renderer into a multi-screen desktop research workspace.
- Added two-step first-launch onboarding for API credentials and advanced scan settings.
- Added dashboard connection cards, scan controls, progress ring, metrics and live activity.
- Added dedicated Results workspace with search and sorting.
- Replaced the candidate popup with a full candidate review workspace.
- Added Overview, Source Findings and Public Evidence tabs.
- Added finding severity/category filters and sorting.
- Added dedicated Activity workspace and scan-summary export.
- Rebuilt Settings with API-key replacement/removal flows and report/source controls.
- Added Connection Test, Replace API Key and Remove Etherscan confirmation modals.
- Preserved Electron safeStorage credential encryption, renderer sandboxing and restrictive IPC.
- Preserved defensive scanner guardrails: no RPC probing, transactions or exploit generation.
- Added `npm run check` smoke validation.
