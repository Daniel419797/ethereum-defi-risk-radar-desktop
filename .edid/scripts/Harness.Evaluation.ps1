Set-StrictMode -Version Latest

function ConvertTo-EdidProcessArgument {
    param([AllowEmptyString()][string]$Value)

    if ($Value -notmatch '[\s"]') { return $Value }
    '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-EdidBoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$MaximumOutputCharacters
    )

    $command = Get-Command $Executable -ErrorAction SilentlyContinue
    if (-not $command) {
        return [pscustomobject]@{ ExitCode = $null; TimedOut = $false; Output = "Executable not found: $Executable"; Started = $false }
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $command.Source
    $renderedArguments = foreach ($argument in $Arguments) {
        ConvertTo-EdidProcessArgument ([string]$argument)
    }
    $startInfo.Arguments = $renderedArguments -join ' '
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            return [pscustomobject]@{ ExitCode = $null; TimedOut = $false; Output = "Process did not start"; Started = $false }
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            try { $process.Kill() } catch { }
            $process.WaitForExit()
        }

        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $combined = ($stdout + [Environment]::NewLine + $stderr).Trim()
        if ($combined.Length -gt $MaximumOutputCharacters) {
            $combined = $combined.Substring(0, $MaximumOutputCharacters) + [Environment]::NewLine + "[output truncated]"
        }

        [pscustomobject]@{
            ExitCode = if ($finished) { $process.ExitCode } else { $null }
            TimedOut = -not $finished
            Output = $combined
            Started = $true
        }
    } finally {
        $process.Dispose()
    }
}

function Test-EdidCommandPermission {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @()
    )

    $allowed = @(@($Config.permissions.allowed_executables) | Where-Object {
        $_ -eq $Executable -or $_ -eq ([System.IO.Path]::GetFileName($Executable))
    })
    if ($allowed.Count -eq 0) {
        return [pscustomobject]@{ Allowed = $false; Reason = "Executable is not allowlisted: $Executable" }
    }

    $rendered = ($Executable + " " + ($Arguments -join " "))
    foreach ($pattern in @($Config.permissions.denied_argument_patterns)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$pattern) -and
            $rendered.IndexOf([string]$pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [pscustomobject]@{ Allowed = $false; Reason = "Command matches denied pattern: $pattern" }
        }
    }

    [pscustomobject]@{ Allowed = $true; Reason = $null }
}

function Invoke-EdidCommandCheck {
    param($Check, $Config, $Paths)

    $arguments = @(Get-EdidPropertyValue $Check "arguments" @() | ForEach-Object { [string]$_ })
    $permission = Test-EdidCommandPermission -Config $Config -Executable ([string]$Check.executable) -Arguments $arguments
    if (-not $permission.Allowed) {
        return [pscustomobject]@{ Result = "blocked"; Summary = $permission.Reason; Output = ""; ExitCode = $null }
    }

    $workingRelativeValue = Get-EdidPropertyValue $Check "working_directory"
    $workingRelative = if ($workingRelativeValue) { [string]$workingRelativeValue } else { "." }
    $workingDirectory = Resolve-EdidProjectPath -Paths $Paths -RelativePath $workingRelative
    if (-not (Test-Path -LiteralPath $workingDirectory -PathType Container)) {
        return [pscustomobject]@{ Result = "blocked"; Summary = "Working directory is not a directory: $workingRelative"; Output = ""; ExitCode = $null }
    }

    $run = Invoke-EdidBoundedProcess `
        -Executable ([string]$Check.executable) `
        -Arguments $arguments `
        -WorkingDirectory $workingDirectory `
        -TimeoutSeconds ([int]$Config.command_timeout_seconds) `
        -MaximumOutputCharacters ([int]$Config.max_evidence_output_chars)

    if (-not $run.Started) {
        return [pscustomobject]@{ Result = "blocked"; Summary = $run.Output; Output = $run.Output; ExitCode = $null }
    }
    if ($run.TimedOut) {
        return [pscustomobject]@{ Result = "fail"; Summary = "Command timed out"; Output = $run.Output; ExitCode = $null }
    }

    $expected = [int](Get-EdidPropertyValue $Check "expected_exit_code" 0)
    $result = if ($run.ExitCode -eq $expected) { "pass" } else { "fail" }
    [pscustomobject]@{
        Result = $result
        Summary = "Exit code $($run.ExitCode); expected $expected"
        Output = $run.Output
        ExitCode = $run.ExitCode
    }
}

function Invoke-EdidFileCheck {
    param($Check, $Paths)

    try {
        $path = Resolve-EdidProjectPath -Paths $Paths -RelativePath ([string]$Check.path)
    } catch {
        return [pscustomobject]@{ Result = "fail"; Summary = $_.Exception.Message; Output = "" }
    }

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ Result = "fail"; Summary = "File is missing: $($Check.path)"; Output = "" }
    }
    $contains = Get-EdidPropertyValue $Check "contains"
    if ($contains) {
        $matched = Select-String -LiteralPath $path -SimpleMatch ([string]$contains) -Quiet
        if (-not $matched) {
            return [pscustomobject]@{ Result = "fail"; Summary = "File does not contain required text"; Output = "" }
        }
    }
    [pscustomobject]@{ Result = "pass"; Summary = "File check passed: $($Check.path)"; Output = "" }
}

function Invoke-EdidHttpCheck {
    param($Check, $Config)

    if (-not [bool]$Config.permissions.allow_network_evaluation) {
        return [pscustomobject]@{ Result = "blocked"; Summary = "Network evaluation is disabled"; Output = "" }
    }

    try { $uri = [uri]([string]$Check.url) } catch {
        return [pscustomobject]@{ Result = "blocked"; Summary = "Invalid URL"; Output = "" }
    }
    if ($uri.Scheme -ne "https") {
        return [pscustomobject]@{ Result = "blocked"; Summary = "Only HTTPS evaluation URLs are allowed"; Output = "" }
    }
    if ($uri.Host -notin @($Config.permissions.allowed_http_hosts)) {
        return [pscustomobject]@{ Result = "blocked"; Summary = "HTTP host is not allowlisted: $($uri.Host)"; Output = "" }
    }

    try {
        $response = Invoke-WebRequest -Uri $uri.AbsoluteUri -Method Get -UseBasicParsing -TimeoutSec ([int]$Config.command_timeout_seconds)
        $expected = if ($Check.expected_status) { [int]$Check.expected_status } else { 200 }
        $result = if ([int]$response.StatusCode -eq $expected) { "pass" } else { "fail" }
        [pscustomobject]@{ Result = $result; Summary = "HTTP $($response.StatusCode); expected $expected"; Output = "" }
    } catch {
        [pscustomobject]@{ Result = "fail"; Summary = $_.Exception.Message; Output = "" }
    }
}

function Invoke-EdidAdapterCheck {
    param($Check, $Config, $Paths)

    $adapterProperty = $Config.adapters.PSObject.Properties[[string]$Check.adapter]
    if (-not $adapterProperty -or $null -eq $adapterProperty.Value) {
        return [pscustomobject]@{ Result = "blocked"; Summary = "Adapter is not configured: $($Check.adapter)"; Output = "" }
    }
    $adapter = $adapterProperty.Value
    $arguments = @(Get-EdidPropertyValue $adapter "arguments" @()) + @(Get-EdidPropertyValue $Check "arguments" @())
    $proxy = [pscustomobject]@{
        executable = $adapter.executable
        arguments = $arguments
        working_directory = Get-EdidPropertyValue $adapter "working_directory" "."
        expected_exit_code = Get-EdidPropertyValue $adapter "expected_exit_code" 0
    }
    $outcome = Invoke-EdidCommandCheck -Check $proxy -Config $Config -Paths $Paths
    $blockedExitCodes = @(Get-EdidPropertyValue $adapter "blocked_exit_codes" @() | ForEach-Object { [int]$_ })
    if ($null -ne $outcome.ExitCode -and $outcome.ExitCode -in $blockedExitCodes) {
        return [pscustomobject]@{
            Result = "blocked"
            Summary = "Adapter reported blocked (exit code $($outcome.ExitCode))"
            Output = $outcome.Output
            ExitCode = $outcome.ExitCode
        }
    }
    $outcome
}

function Invoke-EdidEvaluation {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Task,
        [Parameter(Mandatory = $true)]$Contract,
        [string]$BuilderId,
        [string]$EvaluatorId
    )

    if ([bool]$Task.independent_evaluation_required) {
        if ([string]::IsNullOrWhiteSpace($BuilderId) -or [string]::IsNullOrWhiteSpace($EvaluatorId)) {
            throw "Task $($Task.id) requires builder and evaluator identities"
        }
        if ($BuilderId -eq $EvaluatorId) {
            throw "Independent evaluation requires different builder and evaluator identities"
        }
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
    $runId = "$timestamp-$($Task.id)"
    $runDirectory = Join-Path $Paths.Evidence $runId
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($check in @($Contract.checks)) {
        $outcome = switch ([string]$check.type) {
            "command" { Invoke-EdidCommandCheck -Check $check -Config $Config -Paths $Paths }
            "file" { Invoke-EdidFileCheck -Check $check -Paths $Paths }
            "http" { Invoke-EdidHttpCheck -Check $check -Config $Config }
            "adapter" { Invoke-EdidAdapterCheck -Check $check -Config $Config -Paths $Paths }
            "manual" { [pscustomobject]@{ Result = "not_run"; Summary = "Manual evaluation required: $($check.instructions)"; Output = "" } }
        }

        $artifactRelative = $null
        if (-not [string]::IsNullOrWhiteSpace([string]$outcome.Output)) {
            $artifact = Join-Path $runDirectory ("$($check.id).log")
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($artifact, [string]$outcome.Output + [Environment]::NewLine, $utf8)
            $artifactRelative = $artifact.Substring($Paths.Root.Length).TrimStart('\', '/') -replace '\\', '/'
        }

        $result = [pscustomobject]@{
            check_id = [string]$check.id
            type = [string]$check.type
            required = [bool]$check.required
            evidence_kind = [string]$check.evidence_kind
            result = [string]$outcome.Result
            summary = [string]$outcome.Summary
            artifact_path = $artifactRelative
        }
        $results.Add($result)
        Add-EdidEvidenceRecord -State $State -TaskId $Task.id -Kind $result.evidence_kind -Source "harness:$runId/$($result.check_id)" -Result $result.result -Summary $result.summary -ArtifactPath $artifactRelative | Out-Null
    }

    $requiredFailures = @($results | Where-Object { $_.required -and $_.result -ne "pass" })
    $verdict = if ($requiredFailures.Count -eq 0) { "pass" } else { "fail" }
    $run = [pscustomobject]@{
        id = $runId
        task_id = $Task.id
        builder_id = $BuilderId
        evaluator_id = $EvaluatorId
        independent = -not [string]::IsNullOrWhiteSpace($EvaluatorId) -and $BuilderId -ne $EvaluatorId
        verdict = $verdict
        results = $results.ToArray()
        evaluated_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    Write-EdidJsonAtomic -Path (Join-Path $runDirectory "results.json") -Value $run
    $State.evaluation_runs = @($State.evaluation_runs) + $run

    if ($verdict -eq "pass") {
        $Task.status = "evaluated"
    } else {
        $attempt = @($State.repair_packets | Where-Object { $_.task_id -eq $Task.id }).Count + 1
        $repair = [pscustomobject]@{
            id = "$($Task.id)-repair-$attempt"
            task_id = $Task.id
            evaluation_run_id = $runId
            attempt = $attempt
            status = "open"
            failures = $requiredFailures
            created_at = (Get-Date).ToUniversalTime().ToString("o")
        }
        Write-EdidJsonAtomic -Path (Join-Path $Paths.Repairs "$($repair.id).json") -Value $repair
        $State.repair_packets = @($State.repair_packets) + $repair
        $Task.status = if ($attempt -ge [int]$Config.repair_limit) { "escalation_required" } else { "repair_required" }
    }
    $State.updated_at = (Get-Date).ToUniversalTime().ToString("o")
    $run
}
