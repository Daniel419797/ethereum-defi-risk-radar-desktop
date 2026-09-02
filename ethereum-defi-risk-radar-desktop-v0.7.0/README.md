# Ethereum DeFi Risk Radar

A **defensive Ethereum Mainnet research application** for discovering legacy DeFi projects from public web evidence and optionally inspecting verified Solidity source from Etherscan.

Version `0.7.0` is a cross-platform desktop + CLI release with:

- an installable **Windows desktop app**;
- a production-ready **macOS universal app** for Intel and Apple Silicon;
- a bundled **`risk-radar` CLI** installed with the desktop app and sharing its OS-encrypted credentials;
- the original Node.js source/developer CLI for automation workflows;
- OS-backed encrypted API-key storage;
- signed/notarized macOS distribution configuration;
- Windows and macOS GitHub Actions packaging workflows with packaged-CLI verification.

The desktop app is the recommended interface.

---

## What it does

The application performs passive research only:

```text
Year range
   ↓
TinyFish Search API
   ↓
Ethereum relevance filtering
   ↓
Public risk-signal detection
   ↓
Optional Etherscan V2 enrichment
   ↓
Verified Solidity static inspection
   ↓
Research priority scoring
   ↓
Interactive desktop results + JSON/CSV reports
```

It looks for public evidence of deprecated/decommissioned protocols, dormant projects, archived repositories, migrations, public audit findings, historical incidents, admin/governance concerns, proxy/upgradeability surfaces and review signals in verified Solidity source.

Verified-source inspection now includes a built-in structural analysis layer for control-flow graphs, data dependencies, taint paths, storage/state writes, cross-contract calls, callback and reentrancy surfaces, proxy/upgrade boundaries, authorization, oracle freshness/manipulation, signature replay, precision, gas/DoS, MEV ordering, governance, bridge messaging, and non-standard token integration.

Optional locally installed engines extend this baseline:

- **Slither** for compiler-aware IR, CFG, dependency, taint, storage and detector evidence;
- **Mythril** for bounded EVM symbolic execution and counterexamples;
- **Foundry/Anvil** for ABI fuzzing, invariants, fork state and reproducible traces;
- **Echidna** for coverage-guided stateful property testing and minimized sequences.

Python, Docker and these analyzers are not required. Their availability is detected in Desktop Settings and through `risk-radar capabilities` / `risk-radar doctor`. Missing tools are reported as optional rather than scan failures.

The economic model includes all-category scenario packs for oracle/price shocks, atomic flash liquidity, liquidity runs, governance capture, cross-domain replay, rounding/donation inflation, liquidation cascades and MEV ordering across lending, AMMs/DEXs, vaults, staking, bridges, governance, derivatives, stablecoins, yield aggregators, wrappers and liquidation systems.

Heuristic and structural rows are **review signals**, not confirmed vulnerabilities.
`EXECUTED` requires a captured ordered counterexample. `REPRODUCED` requires deterministic
replay and always states `model scope` or `fork scope`; only a product-authenticated pinned-fork
replay could establish `CONFIRMED_AT_PINNED_BLOCK`. The current caller-selected loopback Anvil
command deliberately remains `EXECUTED (model scope)`. Finding caps are surfaced and mark
analysis partial. Reports explicitly deny exhaustive discovery and blanket exploitability.

---

# Desktop UI

The desktop renderer is a multi-screen research workspace:

- **First-launch API setup** — TinyFish required, Etherscan optional.
- **Advanced setup** — search limits, enrichment limits, source inspection, report location and optional terminal-command installation.
- **Dashboard** — connection state, scan controls, progress, metrics and live activity.
- **Results** — candidate search/sort, metrics and report access.
- **Candidate Overview** — research score, Ethereum confidence, signals and source metadata.
- **Source Findings** — severity/category filtering, source file/line and review descriptions.
- **Public Evidence** — trust heuristic, year, signal type, snippet and safe external-source opening.
- **Activity** — scanner log and recent-scan summary.
- **Analysis Lab** — local native/deep project analysis, protocol and generic economic simulation, explicit-confirmation Anvil replay, progress, cancellation and evidence-scoped results.
- **Settings** — API-key management, scan defaults, source limits, report output and CLI install/repair/removal.
- **Modals** — connection test, replace API key and Etherscan removal confirmation.

The UI intentionally does not claim unsupported capabilities such as TVL tracking, wallet balances, exploitability percentages, active RPC probing or transaction execution.

---

# Secure API-key storage

The desktop app does **not** persist API keys in plaintext `.env` files.

It uses Electron `safeStorage` in the main process:

```text
First launch
   ↓
User enters API key
   ↓
Electron safeStorage
   ↓
OS-backed encryption
   ↓
Encrypted application settings
```

On macOS, `safeStorage` is backed by the operating system's secure credential facilities/Keychain integration. On Windows it uses Windows OS-backed secure storage. The renderer is only told whether a key is configured; stored secret values are not returned to the UI.

If secure encryption is unavailable, the app refuses to persist newly entered credentials.

---

# Supported desktop platforms

| Platform | Distribution | Architecture | Status |
|---|---|---|---|
| Windows | NSIS `.exe` | x64 | Configured |
| macOS | `.dmg` + `.zip` | **Universal: Intel x86_64 + Apple Silicon arm64** | Configured |
| Linux | Source/Electron-compatible architecture | Not packaged in this release | Not a release target yet |

The project uses Electron `43.x` so the packaged macOS application targets **macOS 12 Monterey or newer**. The `minimumSystemVersion` in the bundle is explicitly set to `12.0`.

---

# Development

Requirements:

- Node.js `>=20.12`
- npm

Install dependencies:

```bash
npm install
```

Build TypeScript:

```bash
npm run build
```

Run smoke checks:

```bash
npm run check
```

Launch the desktop application:

```bash
npm run desktop
```

The first launch displays the two-step setup workflow.

---

# Windows distribution

On Windows:

```powershell
npm install
npm run dist:win
```

or:

```powershell
.\scripts\build-windows.ps1
```

Expected output:

```text
release/
  Ethereum-DeFi-Risk-Radar-Setup-0.7.0.exe
```

The GitHub Actions workflow is:

```text
.github/workflows/windows-installer.yml
```

---

# macOS distribution

## End-user build

The production target is a **single universal macOS application** that runs natively on:

- Intel Macs (`x86_64`)
- Apple Silicon Macs (`arm64`, including M1/M2/M3/M4-generation systems)

The release creates both:

```text
release/
  Ethereum-DeFi-Risk-Radar-0.7.0-universal.dmg
  Ethereum-DeFi-Risk-Radar-0.7.0-universal.zip
```

The DMG provides the normal macOS drag-to-Applications installation experience. The ZIP is also produced because it is useful as a signed distribution/update payload.

## Production signing and notarization

A public macOS build must be **Developer ID signed and Apple notarized** so Gatekeeper accepts it normally.

The project is configured with:

- Hardened Runtime;
- macOS entitlements for Electron JIT execution;
- a macOS `.icns` application icon;
- universal x64 + arm64 packaging;
- DMG + ZIP targets;
- electron-builder notarization;
- post-build verification of code signature, Gatekeeper acceptance, stapled notarization ticket and universal architecture.

The only items that cannot be committed into the project are your private Apple distribution credentials/certificates.

See the complete setup checklist:

```text
docs/MACOS_DISTRIBUTION.md
```

## Local production build on a Mac

After installing your Developer ID certificate and configuring notarization credentials:

```bash
./scripts/build-macos.sh
```

or manually:

```bash
npm install
npm run check
npm run dist:mac
npm run verify:mac
```

`verify:mac` checks:

```text
codesign        signature integrity
spctl           Gatekeeper acceptance
stapler         notarization ticket
lipo            x86_64 + arm64 universal binary
```

## Local unsigned test build

For development testing only:

```bash
./scripts/build-macos-unsigned.sh
```

or:

```bash
npm run dist:mac:unsigned
```

**Do not distribute unsigned builds to end users.** They do not provide normal Gatekeeper trust and intentionally disable production signing/notarization settings.

## Per-architecture builds

If smaller architecture-specific packages are ever needed:

```bash
npm run dist:mac:x64
npm run dist:mac:arm64
```

The standard release remains `universal` so users do not have to decide which Mac architecture they own.

---

# macOS GitHub Actions

Two workflows are included.

### Production signed/notarized build

```text
.github/workflows/macos-installer.yml
```

It:

1. requires Apple distribution secrets;
2. reconstructs the private App Store Connect API key only inside the ephemeral runner;
3. installs dependencies;
4. runs smoke checks;
5. builds a universal DMG + ZIP;
6. Developer ID signs and notarizes through electron-builder;
7. validates Gatekeeper, signing, stapling and universal architecture;
8. creates SHA-256 checksums;
9. uploads the release artifacts.

### Unsigned test build

```text
.github/workflows/macos-unsigned-test.yml
```

This is manual-only and clearly marked for test use. It does not need Apple credentials.

---

# macOS native behavior

The Electron main process now includes macOS-native integration:

- standard application menu;
- About panel with the real package version;
- native Edit menu roles (undo, cut, copy, paste, select all);
- native View/Window menu roles;
- `⌘,` Settings shortcut;
- normal macOS app lifecycle (`activate`, dock reopen and quit behavior);
- dynamic UI version from `app.getVersion()` rather than a hard-coded renderer version.

Windows continues to use the existing menu-free application window.

---

# Installed CLI

The Windows/macOS desktop distribution now includes a real terminal interface. End users do **not** need Node.js.

After installation:

```bash
risk-radar doctor
risk-radar help
risk-radar status
risk-radar capabilities
risk-radar analyze-project C:\path\to\project
risk-radar analyze-project C:\path\to\project --deep --trust-project --timeout=600
risk-radar economic-scenarios
risk-radar simulate-economic C:\path\to\scenario.json
risk-radar simulate-protocol C:\path\to\project C:\path\to\observations.json --seed=1
risk-radar replay-fork C:\path\to\replay-spec.json --confirm-fork
```

Run a scan with:

```bash
risk-radar scan --start=2016 --end=2026 --pages=1
```

The installed CLI uses the **same Electron `safeStorage` encrypted credentials and settings as the desktop UI**. A TinyFish key entered once in the GUI is therefore available to the CLI without being copied into `.env`, a shell profile, or a launcher script. Etherscan remains optional.

Windows installs `risk-radar.cmd` into the user WindowsApps command directory through the NSIS installer. macOS offers terminal-command installation during first launch and from Settings, using `~/.local/bin/risk-radar`.

Useful commands include:

```text
risk-radar scan
risk-radar status
risk-radar doctor
risk-radar test-connections
risk-radar config show
risk-radar config set tinyfish-key
risk-radar config set etherscan-key
risk-radar config remove etherscan-key
risk-radar reports
risk-radar open-reports
risk-radar install-cli
risk-radar uninstall-cli
```

API-key commands prompt interactively without echoing the key. `config show` never prints secret values.

Full documentation:

```text
docs/CLI.md
```

## Source/developer CLI

The original Node.js CLI remains available for repository automation/development and can still use `.env` variables:

```bash
cp .env.example .env
npm run build
npm run scan -- --start=2016 --end=2026
```

This is separate from the installed `risk-radar` command.

---

# Desktop security architecture

```text
┌───────────────────────────────────────────────────────────────┐
│ Electron renderer                                             │
│ Dashboard · setup · settings · results · candidate review     │
└───────────────────────────┬───────────────────────────────────┘
                            │ contextBridge / restricted IPC
                            ▼
┌───────────────────────────────────────────────────────────────┐
│ Electron main process                                         │
│ safeStorage · configuration · GUI + CLI scan orchestration     │
└──────────────┬──────────────────────────────────────┬─────────┘
               │                                      │
               ▼                                      ▼
      ┌──────────────────┐                   ┌──────────────────┐
      │ TinyFish Search  │                   │ Etherscan API V2 │
      │ public discovery │                   │ optional source  │
      └─────────┬────────┘                   └─────────┬────────┘
                └────────────────┬─────────────────────┘
                                 ▼
                     scanner + source analyzer
                                 ↓
                      JSON / CSV research reports
```

Desktop security boundaries include:

- `nodeIntegration: false`;
- `contextIsolation: true`;
- renderer sandbox enabled;
- narrow `contextBridge` API;
- restrictive Content Security Policy;
- blocked in-window external navigation;
- external evidence opens in the system browser;
- API secrets handled only in the main process;
- report redaction for full EVM addresses;
- raw verified Solidity analyzed in memory and not written to reports;
- macOS Hardened Runtime for production-signed builds.

---

# Defensive scope

The application does **not** silently:

- probe Ethereum RPC endpoints;
- call live contracts;
- sign or send transactions;
- execute local project build/test hooks without explicit `--trust-project` confirmation;
- require private keys, paid RPC access, Python, Docker, or external analyzers;
- claim a contract is currently exploitable solely from heuristic or structural evidence.

Native economic scenarios and installed dynamic engines may simulate adversarial sequences in bounded local/fork environments. Results retain their engine, bounds, assumptions, seeds/traces where available, confidence and evidence strength.

`HIGH_RESEARCH_PRIORITY` and `HIGH_REVIEW` are manual-review signals, not vulnerability confirmations.
