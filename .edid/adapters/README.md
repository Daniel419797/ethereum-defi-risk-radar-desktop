# EDID evidence adapters

These adapters connect acceptance contracts to project-specific verification tools. They
verify; they never deploy, mutate provider configuration, or store credentials.

## Enable an adapter

Edit the corresponding JSON file, set `enabled` to `true`, and replace its example checks
with the project's real commands or HTTPS endpoints. Then add an adapter check to a task
contract and run the normal harness `Evaluate` command.

Supported check types:

- `command`: bounded, allowlisted process inside the project root.
- `https`: GET request restricted to HTTPS and `permissions.allowed_http_hosts`.
- `file`: required evidence or operational document inside the project root.

Environment placeholders use `${ENV:NAME}`. List credential-bearing variables under
`redact_environment`; their values are removed from captured output. Never put a secret in
adapter JSON, command arguments, contracts, or source control.

Command checks inherit the process environment, so tools should read credentials directly
from it. The runner blocks `${ENV:NAME}` expansion into command arguments for variables in
`redact_environment`, preventing credentials from appearing in operating-system process
lists. HTTPS authorization headers may use redacted environment placeholders.

Exit codes follow a stable protocol: `0` passed, `1` failed, and `20` blocked because a
capability, credential, permission, or configuration is unavailable. Every run writes a
JSON report and redacted logs under `.edid/adapter-evidence/`.

Pass `-CheckId <id>` through a contract's adapter `arguments` to execute one configured
check. This lets deployment health, migrations, monitoring, and rollback produce distinct
release evidence kinds without rerunning unrelated checks. HTTPS checks may include
`json_assertions` with `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, or `contains` operators for
metric thresholds and provider responses.

Example contract checks:

```json
[
  { "id": "deploy-health", "type": "adapter", "adapter": "deployment", "arguments": ["-CheckId", "deployed-health"], "required": true, "evidence_kind": "deployment_health" },
  { "id": "migration", "type": "adapter", "adapter": "deployment", "arguments": ["-CheckId", "migration-evidence"], "required": true, "evidence_kind": "migration" },
  { "id": "monitoring", "type": "adapter", "adapter": "observability", "arguments": ["-CheckId", "post-deploy-health-window"], "required": true, "evidence_kind": "monitoring" }
]
```

## Responsibilities

- `browser.json`: Playwright, Cypress, or another user-journey/accessibility runner.
- `deployment.json`: read-only revision, migration, health, and rollback verification.
- `observability.json`: post-deployment logs, metrics, traces, alerts, and health windows.
- `security.json`: dependency, secret, static, authorization, container, or DAST gates.

Keep deployment execution separate from deployment verification. External changes remain
subject to the project's approval policy; the adapter only gathers evidence afterward.
