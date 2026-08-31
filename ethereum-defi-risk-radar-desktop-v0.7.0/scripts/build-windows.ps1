$ErrorActionPreference = "Stop"

Write-Host "Ethereum DeFi Risk Radar - Windows installer build" -ForegroundColor Green

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is required. Install Node.js 20.12 or newer first."
}

$nodeVersion = node --version
Write-Host "Node: $nodeVersion"

npm install --no-audit --no-fund
npm run check
npm run dist:win

Write-Host "" 
Write-Host "Installer created under .\release\" -ForegroundColor Green
Get-ChildItem .\release\Ethereum-DeFi-Risk-Radar-Setup-*.exe | Select-Object FullName, Length
