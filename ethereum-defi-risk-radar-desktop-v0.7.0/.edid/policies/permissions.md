# Permissions and blast radius

Default permissions:

- read within the project and explicitly referenced documentation;
- write only within the active task's allowed paths;
- execute allowlisted local build, test, lint, analysis, and read-only diagnostic commands;
- no secrets in prompts, logs, evidence, contracts, or durable handoffs;
- no destructive filesystem, database, Git, deployment, payment, messaging, or remote
  mutation without explicit authority;
- no paid service or credential use without explicit authority;
- network evaluation disabled until hosts and adapters are explicitly allowlisted.

Every task records allowed and denied paths. Evaluations run bounded commands with time and
output limits. A harness permission is an upper boundary, not proof that an action is safe;
the acting agent must still inspect the concrete target and preserve unrelated work.
