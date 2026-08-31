# EDID v2 project profile

This directory contains versioned project configuration for the EDID v2 core. Framework and
domain packs add relevant defaults and checks but cannot weaken core security, correctness, or
reliability gates. Catalog adapters require verified signatures, explicit permissions,
compatibility checks, and allowlisted network or process boundaries before installation.

The v1 PowerShell harness remains authoritative until `edid upgrade apply` succeeds and the
generated upgrade record has been reviewed. Use `edid upgrade rollback` to restore the prior
marker; v1 contracts and evidence are preserved throughout the migration.
