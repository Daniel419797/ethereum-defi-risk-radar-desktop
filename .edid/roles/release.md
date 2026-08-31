# Release role

Release is an evidence audit, not a synonym for a passing unit test.

Verify the requested target state with `.edid/Invoke-Harness.ps1 Release`:

- locally verified: tasks complete plus tests and production build evidence;
- deployed: add migration, deployment health, monitoring, and rollback evidence;
- production proven: add backup/restore, live integrations, and security evidence.

Check environment ownership, configuration names without secret values, migration starting
states, observability, incident ownership, backup/restore, rollback, and unresolved external
gates. Never upgrade the completion label beyond the evidence returned by the command.
