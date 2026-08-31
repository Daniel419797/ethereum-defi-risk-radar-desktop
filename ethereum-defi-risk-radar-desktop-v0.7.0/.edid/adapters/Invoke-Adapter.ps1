[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("browser", "deployment", "observability", "security")]
    [string]$Name,

    [string]$ProjectPath = (Get-Location).Path,

    [string[]]$CheckId = @()
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = [System.IO.Path]::GetFullPath($ProjectPath)
$edid = Join-Path $root ".edid"
$configPath = Join-Path $edid "adapters\$Name.json"
$harnessPath = Join-Path $edid "harness.json"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$runDirectory = Join-Path $edid "adapter-evidence\$timestamp-$Name"
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-PropertyValue {
    param($Object, [string]$PropertyName, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$PropertyName]
    if ($property) { return $property.Value }
    $Default
}

function Write-JsonFile {
    param([string]$Path, $Value)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    [System.IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 30) + [Environment]::NewLine), $utf8)
}

function Resolve-ProjectPath {
    param([string]$RelativePath, [switch]$AllowMissing)
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $root $RelativePath))
    $prefix = $root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ne $root -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes the project root: $RelativePath"
    }
    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $candidate)) {
        throw "Project path is missing: $RelativePath"
    }
    $candidate
}

function Expand-EnvironmentTokens {
    param([AllowEmptyString()][string]$Value)
    [regex]::Replace($Value, '\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}', {
        param($match)
        $environmentValue = [Environment]::GetEnvironmentVariable($match.Groups[1].Value)
        if ($null -eq $environmentValue) { return "" }
        $environmentValue
    })
}

function Protect-Output {
    param([AllowEmptyString()][string]$Text, [string[]]$EnvironmentNames)
    $safe = $Text
    foreach ($environmentName in $EnvironmentNames) {
        $value = [Environment]::GetEnvironmentVariable($environmentName)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $safe = $safe.Replace($value, "[REDACTED:$environmentName]")
        }
    }
    $safe
}

function Convert-ProcessArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-BoundedCommand {
    param($Check, $Harness, [string[]]$RedactNames)

    $executable = [string](Get-PropertyValue $Check "executable")
    $rawArguments = @(Get-PropertyValue $Check "arguments" @() | ForEach-Object { [string]$_ })
    foreach ($redactName in $RedactNames) {
        if (@($rawArguments | Where-Object { $_ -match [regex]::Escape("`${ENV:$redactName}") }).Count -gt 0) {
            return [pscustomobject]@{ result="blocked"; summary="Secret-bearing environment values cannot be placed in process arguments: $redactName"; output="" }
        }
    }
    $arguments = @($rawArguments | ForEach-Object { Expand-EnvironmentTokens $_ })
    $allowed = @(@($Harness.permissions.allowed_executables) | Where-Object {
        $_ -eq $executable -or $_ -eq [System.IO.Path]::GetFileName($executable)
    })
    if ($allowed.Count -eq 0) { return [pscustomobject]@{ result="blocked"; summary="Executable is not allowlisted: $executable"; output="" } }

    $rendered = "$executable $($arguments -join ' ')"
    foreach ($pattern in @($Harness.permissions.denied_argument_patterns)) {
        if ($rendered.IndexOf([string]$pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [pscustomobject]@{ result="blocked"; summary="Command matches denied pattern: $pattern"; output="" }
        }
    }

    $command = Get-Command $executable -ErrorAction SilentlyContinue
    if (-not $command) { return [pscustomobject]@{ result="blocked"; summary="Executable not found: $executable"; output="" } }
    $workingRelative = [string](Get-PropertyValue $Check "working_directory" ".")
    try { $working = Resolve-ProjectPath $workingRelative } catch {
        return [pscustomobject]@{ result="blocked"; summary=$_.Exception.Message; output="" }
    }

    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $command.Source
    $renderedArguments = @($arguments | ForEach-Object { Convert-ProcessArgument $_ })
    $start.Arguments = $renderedArguments -join " "
    $start.WorkingDirectory = $working
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { return [pscustomobject]@{ result="blocked"; summary="Process did not start"; output="" } }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $checkTimeout = [int](Get-PropertyValue $Check "timeout_seconds" $Harness.command_timeout_seconds)
        $finished = $process.WaitForExit($checkTimeout * 1000)
        if (-not $finished) {
            try { $process.Kill() } catch { }
            $process.WaitForExit()
        }
        $output = Protect-Output (($stdout.Result + [Environment]::NewLine + $stderr.Result).Trim()) $RedactNames
        $maximum = [int]$Harness.max_evidence_output_chars
        if ($output.Length -gt $maximum) { $output = $output.Substring(0, $maximum) + "`n[output truncated]" }
        if (-not $finished) { return [pscustomobject]@{ result="fail"; summary="Command timed out after $checkTimeout seconds"; output=$output } }
        $expected = [int](Get-PropertyValue $Check "expected_exit_code" 0)
        $result = if ($process.ExitCode -eq $expected) { "pass" } else { "fail" }
        [pscustomobject]@{ result=$result; summary="Exit code $($process.ExitCode); expected $expected"; output=$output }
    } finally { $process.Dispose() }
}

function Invoke-HttpsCheck {
    param($Check, $Harness, [string[]]$RedactNames)

    if (-not [bool]$Harness.permissions.allow_network_evaluation) {
        return [pscustomobject]@{ result="blocked"; summary="Network evaluation is disabled"; output="" }
    }
    $url = Expand-EnvironmentTokens ([string](Get-PropertyValue $Check "url"))
    try { $uri = [uri]$url } catch { return [pscustomobject]@{ result="blocked"; summary="Invalid URL"; output="" } }
    if ($uri.Scheme -ne "https") { return [pscustomobject]@{ result="blocked"; summary="Only HTTPS adapter URLs are allowed"; output="" } }
    if ($uri.Host -notin @($Harness.permissions.allowed_http_hosts)) {
        return [pscustomobject]@{ result="blocked"; summary="HTTP host is not allowlisted: $($uri.Host)"; output="" }
    }

    $headers = @{}
    $headerObject = Get-PropertyValue $Check "headers"
    if ($headerObject) {
        foreach ($property in $headerObject.PSObject.Properties) {
            $headers[$property.Name] = Expand-EnvironmentTokens ([string]$property.Value)
        }
    }
    try {
        $response = Invoke-WebRequest -Uri $uri.AbsoluteUri -Headers $headers -Method Get -UseBasicParsing -TimeoutSec ([int]$Harness.command_timeout_seconds)
        $expected = [int](Get-PropertyValue $Check "expected_status" 200)
        $body = Protect-Output ([string]$response.Content) $RedactNames
        $result = if ([int]$response.StatusCode -eq $expected) { "pass" } else { "fail" }
        $requiredText = [string](Get-PropertyValue $Check "body_contains" "")
        if ($result -eq "pass" -and $requiredText -and $body.IndexOf($requiredText, [StringComparison]::Ordinal) -lt 0) { $result = "fail" }
        $assertionMessages = New-Object System.Collections.Generic.List[string]
        foreach ($assertion in @(Get-PropertyValue $Check "json_assertions" @())) {
            try { $json = $body | ConvertFrom-Json } catch {
                $result = "fail"
                $assertionMessages.Add("response is not valid JSON")
                break
            }
            $actual = $json
            $path = [string](Get-PropertyValue $assertion "path")
            foreach ($segment in $path.Split('.')) {
                $property = $actual.PSObject.Properties[$segment]
                if (-not $property) { $actual = $null; break }
                $actual = $property.Value
            }
            $expectedValue = Get-PropertyValue $assertion "value"
            $operator = [string](Get-PropertyValue $assertion "operator" "eq")
            $assertionPassed = switch ($operator) {
                "eq" { $actual -eq $expectedValue }
                "ne" { $actual -ne $expectedValue }
                "lt" { [double]$actual -lt [double]$expectedValue }
                "lte" { [double]$actual -le [double]$expectedValue }
                "gt" { [double]$actual -gt [double]$expectedValue }
                "gte" { [double]$actual -ge [double]$expectedValue }
                "contains" { ([string]$actual).IndexOf([string]$expectedValue, [StringComparison]::Ordinal) -ge 0 }
                default { $false }
            }
            if (-not $assertionPassed) { $result = "fail" }
            $assertionMessages.Add("$path $operator $expectedValue`: $assertionPassed")
        }
        $summary = "HTTP $($response.StatusCode); expected $expected"
        if ($assertionMessages.Count -gt 0) { $summary += "; " + ($assertionMessages -join "; ") }
        [pscustomobject]@{ result=$result; summary=$summary; output=$body }
    } catch { [pscustomobject]@{ result="fail"; summary=$_.Exception.Message; output="" } }
}

function Invoke-FileCheck {
    param($Check)
    try { $path = Resolve-ProjectPath ([string](Get-PropertyValue $Check "path")) } catch {
        return [pscustomobject]@{ result="fail"; summary=$_.Exception.Message; output="" }
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return [pscustomobject]@{ result="fail"; summary="Required file is missing"; output="" } }
    [pscustomobject]@{ result="pass"; summary="Required file exists"; output="" }
}

if (-not (Test-Path -LiteralPath $configPath -PathType Leaf) -or -not (Test-Path -LiteralPath $harnessPath -PathType Leaf)) {
    Write-Error "Adapter or harness configuration is missing"
    exit 20
}

$config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
$harness = Get-Content -Raw -LiteralPath $harnessPath | ConvertFrom-Json
if (-not [bool](Get-PropertyValue $config "enabled" $false)) {
    [pscustomobject]@{ adapter=$Name; result="blocked"; summary="Adapter is installed but not enabled" } | ConvertTo-Json -Compress
    exit 20
}
$checks = @(Get-PropertyValue $config "checks" @())
if ($checks.Count -eq 0) {
    [pscustomobject]@{ adapter=$Name; result="blocked"; summary="Adapter has no configured checks" } | ConvertTo-Json -Compress
    exit 20
}
if ($CheckId.Count -gt 0) {
    $checks = @($checks | Where-Object { [string](Get-PropertyValue $_ "id") -in $CheckId })
    if ($checks.Count -eq 0) {
        [pscustomobject]@{ adapter=$Name; result="blocked"; summary="Requested adapter check was not found"; requested=$CheckId } | ConvertTo-Json -Compress
        exit 20
    }
}

$requiredEnvironment = @(Get-PropertyValue $config "required_environment" @() | ForEach-Object { [string]$_ })
$missingEnvironment = @($requiredEnvironment | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
if ($missingEnvironment.Count -gt 0) {
    [pscustomobject]@{ adapter=$Name; result="blocked"; summary="Missing required environment variables"; missing=$missingEnvironment } | ConvertTo-Json -Compress
    exit 20
}
$redactNames = @($requiredEnvironment) + @(Get-PropertyValue $config "redact_environment" @())
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$results = New-Object System.Collections.Generic.List[object]
foreach ($check in $checks) {
    $type = [string](Get-PropertyValue $check "type")
    $outcome = switch ($type) {
        "command" { Invoke-BoundedCommand $check $harness $redactNames }
        "https" { Invoke-HttpsCheck $check $harness $redactNames }
        "file" { Invoke-FileCheck $check }
        default { [pscustomobject]@{ result="blocked"; summary="Unsupported adapter check type: $type"; output="" } }
    }
    $logRelative = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$outcome.output)) {
        $logPath = Join-Path $runDirectory ("$([string](Get-PropertyValue $check 'id' 'check')).log")
        [System.IO.File]::WriteAllText($logPath, [string]$outcome.output + [Environment]::NewLine, $utf8)
        $logRelative = $logPath.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
    }
    $results.Add([pscustomobject]@{
        id = [string](Get-PropertyValue $check "id" "check")
        type = $type
        required = [bool](Get-PropertyValue $check "required" $true)
        result = [string]$outcome.result
        summary = [string]$outcome.summary
        artifact_path = $logRelative
    })
}
$requiredFailures = @($results | Where-Object { $_.required -and $_.result -ne "pass" })
$overall = if ($requiredFailures.Count -eq 0) { "pass" } elseif (@($requiredFailures | Where-Object result -eq "fail").Count -gt 0) { "fail" } else { "blocked" }
$report = [pscustomobject]@{ adapter=$Name; result=$overall; run_id="$timestamp-$Name"; results=$results.ToArray(); evaluated_at=(Get-Date).ToUniversalTime().ToString("o") }
Write-JsonFile (Join-Path $runDirectory "results.json") $report
$report | ConvertTo-Json -Depth 20 -Compress
if ($overall -eq "pass") { exit 0 }
if ($overall -eq "blocked") { exit 20 }
exit 1
