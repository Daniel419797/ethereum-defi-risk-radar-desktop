# Evidence policy

Evidence is an observed result tied to a requirement, environment, source, timestamp, and
artifact. Claims, plans, code presence, and unchecked boxes are not evidence.

The harness captures command output, file assertions, allowlisted HTTPS checks, and configured
browser/deployment/observability/security adapter results. Required blocked or unrun checks do
not pass. Evidence output is bounded and should be reviewed for accidental sensitive data
before commit or sharing.

The builder may record focused checks. Standard and high-assurance completion also requires
an evaluator identity different from the builder. Deployment and production evidence remain
separate from local evidence. Failed evaluation produces a structured repair packet and must
not be overwritten by a later success.
