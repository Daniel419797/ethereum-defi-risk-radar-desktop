# `risk-radar` installed CLI

Ethereum DeFi Risk Radar `0.7.0` ships the desktop application and a terminal interface together.

The installed CLI is **not a second configuration silo**. It starts the same packaged Electron application in headless CLI mode and therefore uses the same:

- Electron `safeStorage` encrypted TinyFish API key;
- optional encrypted Etherscan API key;
- TinyFish endpoint;
- scan defaults;
- verified-source inspection limits;
- report output directory.

No API key is copied into a shell script, environment file, or command launcher.

## How the packaged CLI works

```text
risk-radar
    ↓
small user-level launcher
    ↓
packaged Electron binary in ELECTRON_RUN_AS_NODE mode
    ↓
cli/launch.cjs
    ↓
same packaged Electron binary --cli
    ↓
Electron main process + safeStorage
    ↓
shared encrypted desktop configuration
    ↓
scanner / TinyFish / optional Etherscan
```

The first process is only a launcher. The actual command is executed by the application's Electron main process so macOS Keychain/Windows secure-storage access remains available.

## Installation behavior

### Windows

The NSIS installer writes:

```text
%LOCALAPPDATA%\Microsoft\WindowsApps\risk-radar.cmd
```

That directory is normally already in the user PATH on Windows 10/11. The Settings screen can also install or repair the launcher.

Open a **new** PowerShell, Command Prompt, or Windows Terminal after installation and run:

```powershell
risk-radar doctor
risk-radar capabilities
risk-radar analyze-project C:\path\to\foundry-or-hardhat-project
risk-radar analyze-project C:\path\to\project --deep --trust-project --timeout=600
risk-radar economic-scenarios
risk-radar simulate-economic C:\path\to\scenario.json
risk-radar simulate-protocol C:\path\to\project C:\path\to\observations.json --seed=1
risk-radar replay-fork C:\path\to\replay-spec.json --confirm-fork
```

The NSIS uninstaller removes the launcher.

### macOS

The application bundle contains the CLI runtime. During first-launch setup, **Install `risk-radar` terminal command** is enabled by default.

When enabled, the app writes:

```text
~/.local/bin/risk-radar
```

and, when necessary, adds this bounded block to the active shell profile (`~/.zprofile`, `~/.bash_profile`, or `~/.profile`):

```sh
# >>> Ethereum DeFi Risk Radar CLI >>>
export PATH="$HOME/.local/bin:$PATH"
# <<< Ethereum DeFi Risk Radar CLI <<<
```

Open a new Terminal window after installation and run:

```bash
risk-radar doctor
```

The Settings screen can install/repair or remove the CLI. Removing it also removes the profile block created by the app.

Because macOS apps are commonly uninstalled by dragging the `.app` to Trash, remove the CLI from **Settings → Command Line** first if you also want the user-level launcher removed.

## Commands

```text
risk-radar help
risk-radar version
risk-radar status
risk-radar doctor
risk-radar test-connections
risk-radar reports
risk-radar open-reports
risk-radar install-cli
risk-radar uninstall-cli
```

### Scan

```bash
risk-radar scan --start=2016 --end=2026 --pages=1
```

Options:

```text
--start=<year>   Start year, 2016 or later
--end=<year>     End year, not later than the current year
--pages=<1..10>  TinyFish result pages per query
--quiet          Reduce per-query terminal progress output
```

The scan creates the same redacted JSON and CSV reports as the desktop interface.

### Show configuration

```bash
risk-radar config show
```

Secret values are never printed. The output only reports whether TinyFish/Etherscan credentials are configured.

### Update non-secret configuration

```bash
risk-radar config set pages 2
risk-radar config set min-signals 3
risk-radar config set etherscan-lookups 2
risk-radar config set inspect-source true
risk-radar config set max-source-bytes 2000000
risk-radar config set max-findings 80
risk-radar config set endpoint https://api.search.tinyfish.ai
risk-radar config set output-dir "/path/to/reports"
```

### Set API keys securely

Do **not** put API keys directly on the command line. The CLI prompts without echoing the value:

```bash
risk-radar config set tinyfish-key
risk-radar config set etherscan-key
```

The resulting value is passed to Electron `safeStorage` and saved in the same encrypted settings store used by the GUI.

Remove the optional Etherscan credential with:

```bash
risk-radar config remove etherscan-key
```

## `doctor`

```bash
risk-radar doctor
```

Checks:

- application version;
- current platform/architecture;
- secure-storage availability;
- TinyFish credential presence;
- optional Etherscan credential presence;
- report-directory writability;
- global CLI launcher installation.

## Source/developer CLI

The repository still contains the original Node.js developer CLI:

```bash
npm run build
npm run scan -- --start=2016 --end=2026
```

That source-mode CLI continues to support `.env`/environment-variable configuration for automation and development.

The **installed `risk-radar` command is different**: it deliberately shares the desktop application's OS-encrypted configuration and does not require the end user to install Node.js.

## Security notes

- The launcher contains no API keys.
- API keys are not exported into shell environment variables.
- `config show` never reveals secret values.
- API-key entry uses an interactive non-echoing prompt.
- The discovery scanner remains passive and does not submit transactions. Local-project analysis can run bounded native or explicitly trusted optional engines; economic and fork scenarios retain their assumptions and evidence level and never require a signing key.

`analyze-project` runs the built-in control-flow, data-flow, taint, storage/state and
cross-contract analysis without extra tools. `--deep` requests locally installed Slither,
Mythril, Foundry and Echidna adapters. It requires `--trust-project` because Solidity project
compiler and test hooks can execute repository-controlled code. Each engine is bounded by the
selected timeout and output limits; missing tools return an optional/unavailable state.

`simulate-protocol` builds a source-linked contract/call/category model, then runs applicable
scenario packs using explicit observed balances, liabilities, and prices. A failed invariant
is `REPRODUCED (model scope)`, never a claim about deployed bytecode.

`replay-fork` accepts only an unauthenticated `http://127.0.0.1` Anvil endpoint and requires
`chainId: 1`, a trusted canonical `blockHash`, a matching `blockNumber`, canonical transaction
fields, and an explicit invariant (`changed`, `zero`, or `transaction_reverted` with a
`transactionIndex`). It snapshots state, uses explicit block tags, validates receipts, and
restores the snapshot. Because this endpoint is caller-selected rather than a product-owned
process, successful replay is intentionally `EXECUTED (model scope)` and cannot earn
`CONFIRMED_AT_PINNED_BLOCK`. No private key is accepted or required.

Evidence is fail-closed: a passing Forge test or analyzer row without a counterexample remains
structural. Seeds, ordered calls, invariant IDs, block numbers, scopes, and truncation counts
are retained in JSON output. JSON includes a flat `findingRows` collection, while CSV emits
one detailed row per finding with evidence, scope, exploitability verdict, path, mitigation,
counterexample, seed, block, limitation, and truncation fields.
