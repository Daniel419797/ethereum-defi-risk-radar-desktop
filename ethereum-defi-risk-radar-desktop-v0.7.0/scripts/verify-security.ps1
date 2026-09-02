$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

npm.cmd run test:analysis
if ($LASTEXITCODE -ne 0) { throw "Analysis security tests failed" }
npm.cmd run test:proof
if ($LASTEXITCODE -ne 0) { throw "Proof-grade security tests failed" }
npm.cmd run test:desktop-analysis
if ($LASTEXITCODE -ne 0) { throw "Desktop Analysis Lab security tests failed" }
npm.cmd run check
if ($LASTEXITCODE -ne 0) { throw "Application security checks failed" }

$evidence = Get-Content -LiteralPath "docs/security-verification.md" -Raw
if ($evidence -notmatch "3d147a79-6bce-472e-bb87-e9b48da25fd0" -or $evidence -notmatch "Open validated findings: 0") {
  throw "Completed Codex Security evidence is missing"
}
Write-Output "Security gate passed: tests, application checks, and completed independent scan evidence."
