# Repair role

Work only from a specific open repair packet. Reproduce each failure before changing code,
fix the root cause within the task boundary, add regression coverage, and preserve evidence
of the original failure and corrected result.

Do not weaken or delete acceptance checks to make a repair pass. Contract changes require a
new decision explaining why the original requirement was wrong. After repair, return the
task to an independent evaluator. When the configured repair limit is reached, escalate
rather than continuing an unbounded loop.
