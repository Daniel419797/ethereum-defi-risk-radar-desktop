# Agentic delivery harness

`.edid` is the portable executable control plane for EDID. It shares structured tasks,
acceptance contracts, permissions, evidence, repair packets, context, and handoffs across
Codex, Claude Code, OpenCode, Qwen, and other agents.

Run `.\.edid\Invoke-Harness.ps1 Status`, then `Validate`. Create work with `NewTask`, fill
the generated contract, generate `Context`, and evaluate with distinct builder/evaluator
identities for standard or high-assurance tasks. Use `Handoff` before changing agents and
`Release` to claim only the strongest evidence-supported state.

Commands are allowlisted, project confined, time bounded, and output bounded. Network
checks are disabled by default; external systems use explicitly configured adapters.
