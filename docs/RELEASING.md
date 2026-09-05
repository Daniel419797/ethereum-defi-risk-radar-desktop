# Desktop Release Runbook

The repository-level workflow `.github/workflows/desktop-release.yml` is the production release pipeline for macOS and Windows.

## What the workflow guarantees before publishing

A tagged release is published only after all required jobs succeed.

### Release metadata gate

The workflow verifies that:

- `package.json` and `package-lock.json` contain the same application version;
- a tag such as `v0.7.0` exactly matches package version `0.7.0`;
- a release tag points to a commit reachable from `main`.

### macOS gate

The macOS job:

1. installs dependencies with `npm ci`;
2. runs the repository checks and deep-analysis regressions;
3. requires the configured Apple signing/notarization secrets;
4. builds a universal Intel + Apple Silicon application;
5. Developer ID signs the application;
6. submits it for Apple notarization through electron-builder;
7. verifies the code signature;
8. verifies Gatekeeper acceptance;
9. verifies the stapled notarization ticket;
10. verifies the bundled `risk-radar` CLI runtime and package version;
11. verifies that the application executable contains both `x86_64` and `arm64` architectures;
12. emits DMG/ZIP assets and SHA-256 checksums.

### Windows gate

The Windows job:

1. installs dependencies with `npm ci`;
2. runs repository and deep-analysis checks;
3. builds the NSIS installer;
4. silently installs it on the ephemeral runner;
5. verifies that `risk-radar.cmd` is installed;
6. verifies the installed CLI reports the expected package version;
7. emits the installer and a SHA-256 checksum.

### GitHub Release gate

Only after both platform jobs succeed does the publish job create/update the GitHub Release and attach:

```text
Ethereum-DeFi-Risk-Radar-<version>-universal.dmg
Ethereum-DeFi-Risk-Radar-<version>-universal.zip
Ethereum-DeFi-Risk-Radar-Setup-<version>.exe
SHA256SUMS.txt
SHA256SUMS-macos.txt
SHA256SUMS-windows.txt
```

The release job verifies that the expected DMG, ZIP, EXE and combined checksum are actually present on the published release.

## Apple credentials required in GitHub Actions

Production macOS distribution requires an Apple Developer Program account and a **Developer ID Application** certificate.

In GitHub:

```text
Repository
→ Settings
→ Secrets and variables
→ Actions
→ New repository secret
```

Configure all of the following:

| Secret | Purpose |
|---|---|
| `MAC_CSC_LINK` | Developer ID Application certificate payload/location accepted by electron-builder, normally a base64-encoded `.p12` in CI. |
| `MAC_CSC_KEY_PASSWORD` | Password used when exporting the `.p12`. |
| `APPLE_API_KEY_BASE64` | Base64 representation of the App Store Connect API `.p8` key. |
| `APPLE_API_KEY_ID` | App Store Connect API key ID. |
| `APPLE_API_ISSUER` | App Store Connect API issuer ID. |
| `APPLE_TEAM_ID` | Apple Developer Team ID. |

Never commit certificate files, `.p8` files, passwords, private keys, or secret values to the repository.

### Example: encode the certificate locally

On macOS, after exporting your Developer ID Application certificate as a password-protected `.p12`:

```bash
base64 -i DeveloperIDApplication.p12 | pbcopy
```

Store the copied value as `MAC_CSC_LINK`.

Encode the App Store Connect API key similarly:

```bash
base64 -i AuthKey_XXXXXXXXXX.p8 | pbcopy
```

Store the copied value as `APPLE_API_KEY_BASE64`.

## Publishing a release

### 1. Update the application version

From the application directory:

```bash
cd ethereum-defi-risk-radar-desktop-v0.7.0
npm version 0.7.1 --no-git-tag-version
```

This updates `package.json` and `package-lock.json` together.

Commit the version change and merge it into `main` only after the normal quality gates pass.

### 2. Create the matching tag

From an up-to-date `main` branch:

```bash
git checkout main
git pull --ff-only origin main
git tag v0.7.1
git push origin v0.7.1
```

The tag must exactly match the package version. A mismatched tag intentionally fails before packaging.

### 3. Observe the workflow

GitHub Actions automatically starts **Build and Publish Desktop Release**.

Do not create the public release manually while this workflow is running. The workflow owns release-asset publication so it can enforce the verification gates.

### 4. Validate the published release

After the workflow passes:

- open GitHub **Releases**;
- confirm the DMG, ZIP, EXE and checksum files are present;
- download the DMG on at least one clean Apple Silicon Mac;
- if available, test the same universal DMG on an Intel Mac;
- verify normal Gatekeeper launch without bypass instructions;
- run first-launch credential setup;
- run a connection test;
- verify the installed CLI if you enable it from Settings.

## Manual signed build without publishing a Release

The production workflow supports `workflow_dispatch`. A manual run builds and verifies signed packages and stores them as GitHub Actions artifacts, but the `publish-release` job runs only for a `v*` tag.

This is useful before publishing a real release.

## Unsigned macOS test package

Use the separate repository-level workflow:

```text
.github/workflows/macos-unsigned-test.yml
```

It is manual-only and does not require Apple distribution credentials.

Its output is for development/testing only. It must not be presented as the normal end-user download and should not be attached to a production GitHub Release.

## Failure policy

A failed signing, notarization, Gatekeeper, architecture, CLI, test, installer, version, or publishing check means the release is **not production-ready**. Fix the failure and rerun the workflow rather than bypassing the gate.
