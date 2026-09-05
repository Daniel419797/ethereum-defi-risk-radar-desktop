# Desktop release implementation notes

This change set follows the merged Historical Audit Intelligence work and fixes desktop distribution from the repository root.

Implemented:

- repository-level production desktop release workflow;
- repository-level unsigned macOS test workflow;
- removal of ignored nested packaging workflows;
- macOS universal signed/notarized build verification;
- dynamic package-version verification for the bundled CLI;
- tag/package-lock/package version consistency checks;
- release-tag ancestry check against `main`;
- Windows installer build and installed-CLI verification;
- platform and combined SHA-256 checksums;
- automatic GitHub Release creation/update for `v*` tags;
- release-asset presence verification;
- end-user installation guide;
- maintainer release runbook;
- EDID decision and verification records.

Not externally completed by this code change:

- Apple Developer signing credentials cannot be created or committed by the application code;
- a production GitHub Release is intentionally not created until the required Apple Actions secrets are configured and a matching `v*` tag is pushed from `main`;
- the unsigned manual workflow output is test-only and must never be presented as a production release.
