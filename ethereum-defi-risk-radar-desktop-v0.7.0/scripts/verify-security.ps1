$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

npm.cmd run test:analysis
if ($LASTEXITCODE -ne 0) { throw "Analysis security tests failed" }
npm.cmd run check
if ($LASTEXITCODE -ne 0) { throw "Application security checks failed" }

$evidence = Get-Content -LiteralPath "docs/security-verification.md" -Raw
if ($evidence -notmatch "a4bd3e47-6268-4bd7-a467-e707d30f5887" -or $evidence -notmatch "Open validated findings: 0") {
  throw "Completed Codex Security evidence is missing"
}
Write-Output "Security gate passed: tests, application checks, and completed independent scan evidence."
