# macOS Distribution Setup

This document covers the external Apple credentials and release steps required to distribute Ethereum DeFi Risk Radar to macOS users without Gatekeeper warnings.

## 1. Supported Macs

The release target is:

```text
macOS 12 Monterey+
Universal binary
  ├─ x86_64 — Intel Macs
  └─ arm64  — Apple Silicon Macs
```

The packaged app is built with Electron 43.x and `LSMinimumSystemVersion` is set to `12.0`.

## 2. Apple Developer Program

For normal public distribution outside the Mac App Store, enroll the organization/account in the Apple Developer Program.

You need a **Developer ID Application** certificate. A Mac App Store certificate is not the correct certificate for the DMG distribution path used by this project.

## 3. Export the Developer ID certificate

On a trusted Mac:

1. Install/create the Developer ID Application certificate in Keychain Access.
2. Export the certificate **with its private key** as a password-protected `.p12`.
3. Never commit the `.p12` or its password to Git.

For local builds, the certificate may remain in the user's Keychain and electron-builder can discover it.

For GitHub Actions, base64-encode the `.p12` and store it as the repository secret:

```text
MAC_CSC_LINK
```

Store its password as:

```text
MAC_CSC_KEY_PASSWORD
```

## 4. Create App Store Connect API credentials for notarization

App Store Connect API-key authentication is the recommended CI path.

Record:

```text
Key ID
Issuer ID
Team ID
```

Download the private `.p8` key once and keep it secret.

Base64-encode the `.p8` contents for GitHub Actions and configure:

```text
APPLE_API_KEY_BASE64
APPLE_API_KEY_ID
APPLE_API_ISSUER
APPLE_TEAM_ID
```

The GitHub workflow reconstructs the `.p8` only inside the ephemeral runner and deletes it when the runner is destroyed.

## 5. Required GitHub repository secrets

Production macOS CI expects all of these:

```text
MAC_CSC_LINK
MAC_CSC_KEY_PASSWORD
APPLE_API_KEY_BASE64
APPLE_API_KEY_ID
APPLE_API_ISSUER
APPLE_TEAM_ID
```

The workflow fails immediately if any are absent rather than silently uploading an unsigned release as though it were production-ready.

## 6. Build locally with API-key notarization

Example environment variables on the Mac:

```bash
export APPLE_API_KEY="/secure/path/AuthKey_KEYID.p8"
export APPLE_API_KEY_ID="KEYID"
export APPLE_API_ISSUER="issuer-uuid"
export APPLE_TEAM_ID="TEAMID1234"
```

If the Developer ID Application certificate is installed in the login Keychain:

```bash
./scripts/build-macos.sh
```

Alternatively, electron-builder can use a certificate supplied through `CSC_LINK` and `CSC_KEY_PASSWORD`.

## 7. Other notarization authentication supported by the build tool

The electron-builder notarization integration can also use Apple-ID credentials:

```text
APPLE_ID
APPLE_APP_SPECIFIC_PASSWORD
APPLE_TEAM_ID
```

or a stored notarytool keychain profile:

```text
APPLE_KEYCHAIN_PROFILE
APPLE_KEYCHAIN   (optional path)
```

The GitHub workflow uses the App Store Connect API-key method because it is better suited to CI.

## 8. Build outputs

Production:

```bash
npm run dist:mac
```

Outputs:

```text
release/Ethereum-DeFi-Risk-Radar-0.7.0-universal.dmg
release/Ethereum-DeFi-Risk-Radar-0.7.0-universal.zip
```

The DMG is the normal user-facing installer. Users open it and drag the application to `/Applications`.

## 9. Verify before distribution

Always run:

```bash
npm run verify:mac
```

This verifies:

```bash
codesign --verify --deep --strict
spctl --assess --type exec
xcrun stapler validate
lipo -info
```

A production release should pass all four.

The executable must report both architectures:

```text
x86_64
arm64
```

Gatekeeper should report an accepted notarized Developer ID application.

## 10. CI release flow

Push a release tag such as:

```bash
git tag v0.7.0
git push origin v0.7.0
```

The Windows and macOS packaging workflows both listen for `v*` tags.

The macOS workflow creates SHA-256 checksums and uploads the DMG, ZIP and checksum file as artifacts.

## 11. Unsigned builds

Use unsigned builds only for development:

```bash
npm run dist:mac:unsigned
```

or:

```bash
./scripts/build-macos-unsigned.sh
```

Do not publish these. They intentionally skip signing, Hardened Runtime signing options and notarization, so they do not represent a trusted end-user release.

## 12. Security rules

Never commit:

```text
*.p12
*.p8
*.cer
*.mobileprovision
```

The repository `.gitignore` blocks these patterns as an additional guardrail, but secret-management discipline is still required.
