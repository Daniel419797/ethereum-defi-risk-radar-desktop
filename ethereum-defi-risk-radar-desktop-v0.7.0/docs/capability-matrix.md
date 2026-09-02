# User-facing capability matrix

This matrix inventories product workflows rather than internal parsing helpers. `Desktop` means
the workflow has a visible control, preload contract, main-process handler, validation, and result state.

| Backend capability | CLI | Desktop | Desktop surface |
|---|---|---|---|
| Application/version status | Yes | Yes | Settings/about data |
| Secure configuration read/update | Yes | Yes | Onboarding and Settings |
| TinyFish/Etherscan connection test | Doctor | Yes | Dashboard and Settings |
| Passive historical discovery scan | Yes | Yes | Dashboard |
| Scan progress, activity, result recovery | Yes | Yes | Dashboard, Activity, Results |
| Verified-source native analysis | Via scan | Yes | Candidate findings |
| JSON/CSV research reports | Yes | Yes | Results |
| Summary export | Yes | Yes | Activity |
| Optional engine capability detection | Doctor | Yes | Settings and Analysis Lab |
| CLI installation/removal | N/A | Yes | Settings |
| Local-project native analysis | Yes | Yes | Analysis Lab |
| Trusted Slither/Mythril/Foundry/Echidna analysis | Yes | Yes | Analysis Lab, explicit trust gate |
| Generic economic scenario simulation | Yes | Yes | Analysis Lab |
| Protocol-derived attack simulation | Yes | Yes | Analysis Lab |
| External loopback Anvil replay | Yes | Yes | Analysis Lab, explicit confirmation |
| Analysis cancellation | Process interruption | Yes | Analysis Lab |

Internal library exports such as CFG construction, evidence ranking, adapter normalization, and
bounded process execution are implementation components consumed by the workflows above; they are
not separate end-user operations and do not receive standalone screens.

## Desktop trust boundaries

- The renderer cannot read arbitrary files or launch processes.
- Project and JSON paths must be selected in a native dialog and are authorized in memory.
- External project engines require explicit trust; native analysis does not.
- Replay requires explicit confirmation, accepts no private key, and is limited to the strict
  loopback specification enforced by the replay service.
- Missing optional tools are visible capability states, not application failures.
