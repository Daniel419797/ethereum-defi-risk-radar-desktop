# Installing Ethereum DeFi Risk Radar

This guide is for people who want to **use the desktop application**, not develop it.

## macOS

### Supported Macs

The production macOS package is built as a **universal application** for:

- Apple Silicon (`arm64`) Macs;
- Intel (`x86_64`) Macs;
- macOS 12 Monterey or newer.

A normal end user does **not** need Node.js, npm, Git, Python, Docker, Slither, Mythril, Foundry, Echidna, or Anvil to install the core desktop application.

### Install from GitHub Releases

1. Open this repository on GitHub.
2. Open **Releases**.
3. Open the latest release.
4. Download the file named like:

   ```text
   Ethereum-DeFi-Risk-Radar-0.7.0-universal.dmg
   ```

5. Optionally verify the download against `SHA256SUMS.txt` included in the same release.
6. Double-click the `.dmg`.
7. Drag **Ethereum DeFi Risk Radar** into **Applications**.
8. Eject the disk image.
9. Open **Applications** and launch **Ethereum DeFi Risk Radar**.

Production release builds are configured to be Developer ID signed, Apple notarized, Gatekeeper verified, and stapled before they are published. Do not distribute the unsigned test workflow output as an end-user release.

### First launch

Risk Radar asks for service credentials during initial setup.

- **TinyFish API key** — required for automatic public-web discovery.
- **Etherscan API key** — effectively required for automatic protocol promotion because document leads are not promoted until Risk Radar resolves an Ethereum Mainnet contract with verified source metadata.

Desktop credentials are stored through Electron `safeStorage`; the renderer is not given the stored secret values.

After setup:

1. choose the historical year range to research;
2. start a scan;
3. allow TinyFish to discover public leads;
4. allow Etherscan to resolve/verify Mainnet contracts and proxy implementations;
5. review protocols under **Results**;
6. open a protocol to inspect verified-source findings and public evidence;
7. use **Analysis Lab** when deeper local tooling is installed and explicitly trusted.

### Optional terminal command

The macOS application can install the bundled `risk-radar` command into `~/.local/bin` from first-launch setup or Settings.

Examples:

```bash
risk-radar doctor
risk-radar status
risk-radar capabilities
risk-radar scan --start=2016 --end=2026 --pages=1
```

The installed CLI shares the desktop application's encrypted credentials.

### Historical Audit Intelligence

The third-party historical audit corpus is intentionally **not bundled** into release packages because its redistribution/commercial-use provenance is not yet sufficiently clear.

Developers/researchers who have a permitted local copy can prepare it with the repository dataset pipeline. When a cleaned corpus exists at:

```text
~/.defi-risk-radar/audit-intelligence/cleaned-audit-findings.jsonl
```

Risk Radar loads it automatically and can attach historical audit analogues to current verified-source findings. Historical similarity remains supporting review context, not proof of current exploitability.

## Windows

Tagged desktop releases also build the NSIS installer:

```text
Ethereum-DeFi-Risk-Radar-Setup-0.7.0.exe
```

The installer is attached to the same GitHub Release after the Windows packaging and CLI verification gates pass.

## Source/developer installation

Only contributors or users who intentionally want to run from source need the development toolchain:

```bash
git clone https://github.com/Daniel419797/ethereum-defi-risk-radar-desktop.git
cd ethereum-defi-risk-radar-desktop/ethereum-defi-risk-radar-desktop-v0.7.0
npm ci
npm run check
npm run desktop
```

For normal users, prefer a signed GitHub Release rather than source installation.
