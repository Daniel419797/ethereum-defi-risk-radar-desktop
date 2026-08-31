# Adaptive harness complexity

Use the smallest harness that reliably covers the task.

| Mode | Selection | Required structure |
|---|---|---|
| Lightweight | Narrow scope and low risk | One bounded builder, executable checks, concise handoff |
| Standard | Feature/product work or medium risk | Planner/spec, builder, distinct evaluator, repair loop |
| High assurance | Release scope or high/critical risk | Planner, bounded builder, distinct evaluator, security/operations evidence, explicit release audit |

Escalate mode when work touches authentication, authorization, money, secrets, personal or
clinical data, destructive migrations, public APIs, infrastructure, production deployment,
or a repeated evaluation failure. Never downgrade merely to avoid a failing gate.

Parallel execution is allowed only for tasks that are dependency-independent, have disjoint
allowed paths, do not mutate shared state, and can be evaluated separately. Default to
sequential execution when uncertain. Multi-agent cost must be justified by independence,
risk reduction, or wall-clock benefit.
