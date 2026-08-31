# Context engineering policy

Load the minimum sufficient, authoritative context for the active role and task.

Always load:

- root agent instructions;
- `.edid/context/current.md`;
- the active acceptance contract and role file;
- directly relevant architecture, decisions, source, and evidence.

Do not preload unrelated repository files, old transcripts, all historical evidence, or
every role. Use `.edid/Invoke-Harness.ps1 Context -TaskId <id>` at session start and after a
handoff. Use `.edid/Invoke-Harness.ps1 Handoff` before a context reset or tool switch.

The handoff must state task status, dependencies, observed evidence, open repairs, decisions,
and the exact next action. Conversation summaries never override repository state.
