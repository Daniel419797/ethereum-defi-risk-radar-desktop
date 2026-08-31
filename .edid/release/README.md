# External release evidence

Provider-specific verification may write non-secret structured evidence here. Evidence must
identify the environment, deployed revision, observation time, check source, and result.
Never store tokens, cookies, private URLs, or provider credentials.

The default deployment adapter expects `migration-evidence.json` only after migrations have
been directly verified. Do not create placeholder evidence merely to satisfy a release gate.
