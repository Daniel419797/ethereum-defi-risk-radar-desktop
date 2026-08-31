[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("Status", "Validate", "NewTask", "Evaluate", "Complete", "Evidence", "Context", "Handoff", "Release")]
    [string]$Command = "Status",

    [string]$ProjectPath = (Get-Location).Path,
    [string]$TaskId,
    [string]$Title,
    [ValidateSet("auto", "lightweight", "standard", "high_assurance")][string]$Mode = "auto",
    [ValidateSet("narrow", "feature", "product", "release")][string]$Scope = "feature",
    [ValidateSet("low", "medium", "high", "critical")][string]$Risk = "medium",
    [string[]]$DependsOn = @(),
    [string]$BuilderId,
    [string]$EvaluatorId,
    [ValidateSet("tests", "build", "browser", "deployment_health", "migration", "monitoring", "rollback", "backup_restore", "live_integrations", "security", "performance", "accessibility", "other")][string]$Kind = "other",
    [string]$Source,
    [ValidateSet("pass", "fail", "blocked", "not_run")][string]$Result = "not_run",
    [string]$Summary,
    [string]$ArtifactPath,
    [ValidateSet("locally_verified", "deployed", "production_proven")][string]$TargetState = "locally_verified"
)

$ErrorActionPreference = "Stop"
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDirectory "scripts\Harness.Core.ps1")
. (Join-Path $scriptDirectory "scripts\Harness.Evaluation.ps1")

$paths = Get-EdidPaths -ProjectPath $ProjectPath
$config = Read-EdidJson -Path $paths.Config
$state = Read-EdidJson -Path $paths.State

function Save-HarnessState {
    $state.updated_at = (Get-Date).ToUniversalTime().ToString("o")
    Write-EdidJsonAtomic -Path $paths.State -Value $state
}

function Require-TaskId {
    if ([string]::IsNullOrWhiteSpace($TaskId)) { throw "-TaskId is required for $Command" }
}

function Get-RelativeProjectPath {
    param([string]$AbsolutePath)
    $AbsolutePath.Substring($paths.Root.Length).TrimStart('\', '/') -replace '\\', '/'
}

switch ($Command) {
    "Status" {
        [pscustomobject]@{
            ProjectPath = $paths.Root
            ProjectState = $state.project_state
            Phase = $state.phase
            ActiveTaskId = $state.active_task_id
            Tasks = @($state.tasks | Select-Object id, title, mode, risk, status)
            EvidenceCount = @($state.evidence).Count
            OpenRepairs = @($state.repair_packets | Where-Object { $_.status -eq "open" }).Count
            LastHandoffAt = $state.last_handoff_at
        }
    }

    "Validate" {
        $errors = New-Object System.Collections.Generic.List[string]
        foreach ($requiredFile in @(
            "AGENTS.md",
            "docs/methodology.md",
            "docs/architecture.md",
            "docs/decisions.md",
            "docs/verification.md",
            ".edid/harness.json",
            ".edid/state.json",
            ".edid/adapters/Invoke-Adapter.ps1"
        )) {
            if (-not (Test-Path -LiteralPath (Join-Path $paths.Root $requiredFile) -PathType Leaf)) {
                $errors.Add("missing required file: $requiredFile")
            }
        }

        foreach ($adapterName in @("browser", "deployment", "observability", "security")) {
            $adapterPath = Join-Path $paths.Root ".edid\adapters\$adapterName.json"
            if (-not (Test-Path -LiteralPath $adapterPath -PathType Leaf)) {
                $errors.Add("missing adapter configuration: $adapterName")
                continue
            }
            $adapterConfig = Read-EdidJson -Path $adapterPath
            $adapterResult = Test-EdidAdapterConfig -AdapterConfig $adapterConfig -ExpectedName $adapterName
            foreach ($adapterError in @($adapterResult.Errors)) {
                $errors.Add("adapter $adapterName`: $adapterError")
            }
            if (-not $config.adapters.PSObject.Properties[$adapterName]) {
                $errors.Add("harness adapter wiring is missing: $adapterName")
            }
        }

        $taskIds = @{}
        foreach ($task in @($state.tasks)) {
            if ($task.id -notmatch '^[a-z0-9][a-z0-9._-]*$') {
                $errors.Add("invalid task id: $($task.id)")
                continue
            }
            if ($taskIds.ContainsKey([string]$task.id)) {
                $errors.Add("duplicate task id: $($task.id)")
            } else {
                $taskIds[[string]$task.id] = $true
            }
            foreach ($dependency in @($task.depends_on)) {
                if (-not (@($state.tasks | ForEach-Object { $_.id }) -contains $dependency)) {
                    $errors.Add("task $($task.id) has unknown dependency: $dependency")
                }
            }

            $contractPath = Join-Path $paths.Root ([string]$task.contract_path)
            if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
                $errors.Add("task $($task.id) contract is missing: $($task.contract_path)")
            } else {
                $contract = Read-EdidJson -Path $contractPath
                $contractResult = Test-EdidContract -Contract $contract -ExpectedTaskId $task.id
                foreach ($contractError in @($contractResult.Errors)) {
                    $errors.Add("task $($task.id): $contractError")
                }
            }
        }

        if ($errors.Count -gt 0) {
            [pscustomobject]@{ Valid = $false; Errors = $errors.ToArray() }
            exit 1
        }
        [pscustomobject]@{ Valid = $true; TaskCount = @($state.tasks).Count; Errors = @() }
    }

    "NewTask" {
        Require-TaskId
        if ($TaskId -notmatch '^[a-z0-9][a-z0-9._-]*$') { throw "Invalid task id: $TaskId" }
        if ([string]::IsNullOrWhiteSpace($Title)) { throw "-Title is required for NewTask" }
        if (@($state.tasks | ForEach-Object { $_.id }) -contains $TaskId) { throw "Task already exists: $TaskId" }
        foreach ($dependency in $DependsOn) {
            if (-not (@($state.tasks | ForEach-Object { $_.id }) -contains $dependency)) { throw "Unknown dependency: $dependency" }
        }

        $selectedMode = if ($Mode -eq "auto") { Get-EdidAdaptiveMode -Scope $Scope -Risk $Risk } else { $Mode }
        $contractRelative = ".edid/contracts/$TaskId.json"
        $contractAbsolute = Join-Path $paths.Root ($contractRelative -replace '/', '\')
        $contract = [pscustomobject]@{
            version = 1
            task_id = $TaskId
            title = $Title
            requirements = @()
            checks = @()
            quality_gates = [pscustomobject]@{
                security = "required"
                correctness = "required"
                reliability = "required"
                performance = "not_applicable"
                accessibility = "not_applicable"
                operability = "not_applicable"
            }
        }
        Write-EdidJsonAtomic -Path $contractAbsolute -Value $contract

        $task = [pscustomobject]@{
            id = $TaskId
            title = $Title
            scope = $Scope
            risk = $Risk
            mode = $selectedMode
            status = "draft"
            depends_on = @($DependsOn)
            contract_path = $contractRelative
            independent_evaluation_required = $selectedMode -in @("standard", "high_assurance")
            allowed_paths = @()
            denied_paths = @(".env", ".git", "secrets", "credentials")
            created_at = (Get-Date).ToUniversalTime().ToString("o")
            updated_at = (Get-Date).ToUniversalTime().ToString("o")
        }
        $state.tasks = @($state.tasks) + $task
        $state.active_task_id = $TaskId
        $state.phase = "specify"
        Save-HarnessState
        [pscustomobject]@{ Task = $task; ContractPath = $contractAbsolute; Next = "Fill requirements and checks, then run Validate" }
    }

    "Evaluate" {
        Require-TaskId
        $task = Get-EdidTask -State $state -TaskId $TaskId
        foreach ($dependency in @($task.depends_on)) {
            $dependencyTask = Get-EdidTask -State $state -TaskId $dependency
            if ($dependencyTask.status -ne "complete") { throw "Dependency is not complete: $dependency" }
        }
        $contractPath = Join-Path $paths.Root ([string]$task.contract_path -replace '/', '\')
        $contract = Read-EdidJson -Path $contractPath
        $contractResult = Test-EdidContract -Contract $contract -ExpectedTaskId $TaskId
        if (-not $contractResult.Valid) { throw ("Invalid contract: " + ($contractResult.Errors -join "; ")) }

        $task.status = "evaluating"
        $state.phase = "evaluate"
        Save-HarnessState
        $run = Invoke-EdidEvaluation -Paths $paths -Config $config -State $state -Task $task -Contract $contract -BuilderId $BuilderId -EvaluatorId $EvaluatorId
        Save-HarnessState
        $run
        if ($run.verdict -ne "pass") { exit 1 }
    }

    "Complete" {
        Require-TaskId
        $task = Get-EdidTask -State $state -TaskId $TaskId
        $latest = @($state.evaluation_runs | Where-Object { $_.task_id -eq $TaskId } | Select-Object -Last 1)
        if ($latest.Count -eq 0 -or $latest[0].verdict -ne "pass") {
            throw "Task cannot complete without a passing evaluation: $TaskId"
        }
        if ([bool]$task.independent_evaluation_required -and -not [bool]$latest[0].independent) {
            throw "Task requires independent evaluator evidence: $TaskId"
        }
        $task.status = "complete"
        $task.updated_at = (Get-Date).ToUniversalTime().ToString("o")
        $openRepair = @($state.repair_packets | Where-Object { $_.task_id -eq $TaskId -and $_.status -eq "open" })
        foreach ($repair in $openRepair) { $repair.status = "resolved" }
        if (@($state.tasks | Where-Object { $_.status -ne "complete" }).Count -eq 0) {
            $state.phase = "release"
        }
        Save-HarnessState
        [pscustomobject]@{ TaskId = $TaskId; Status = "complete" }
    }

    "Evidence" {
        Require-TaskId
        Get-EdidTask -State $state -TaskId $TaskId | Out-Null
        if ([string]::IsNullOrWhiteSpace($Source)) { throw "-Source is required for Evidence" }
        if ([string]::IsNullOrWhiteSpace($Summary)) { throw "-Summary is required for Evidence" }
        $normalizedArtifact = $null
        if (-not [string]::IsNullOrWhiteSpace($ArtifactPath)) {
            $artifactAbsolute = Resolve-EdidProjectPath -Paths $paths -RelativePath $ArtifactPath
            $normalizedArtifact = Get-RelativeProjectPath -AbsolutePath $artifactAbsolute
        }
        $record = Add-EdidEvidenceRecord -State $state -TaskId $TaskId -Kind $Kind -Source $Source -Result $Result -Summary $Summary -ArtifactPath $normalizedArtifact
        Save-HarnessState
        $record
    }

    "Context" {
        Require-TaskId
        $task = Get-EdidTask -State $state -TaskId $TaskId
        $contract = Read-EdidJson -Path (Join-Path $paths.Root ([string]$task.contract_path -replace '/', '\'))
        New-Item -ItemType Directory -Path $paths.Context -Force | Out-Null
        $contextPath = Join-Path $paths.Context "current.md"
        $dependencies = if (@($task.depends_on).Count) { @($task.depends_on) -join ", " } else { "none" }
        $evidenceLines = @($state.evidence | Where-Object { $_.task_id -eq $TaskId } | Select-Object -Last 10 | ForEach-Object {
            "- [$($_.result)] $($_.kind): $($_.summary)"
        })
        if ($evidenceLines.Count -eq 0) { $evidenceLines = @("- No evidence recorded yet.") }
        $content = @(
            "# Current EDID context",
            "",
            "- Task: $($task.id) - $($task.title)",
            "- Mode: $($task.mode)",
            "- Risk: $($task.risk)",
            "- Status: $($task.status)",
            "- Dependencies: $dependencies",
            "- Contract: $($task.contract_path)",
            "",
            "## Requirements",
            ""
        ) + @($contract.requirements | ForEach-Object {
            $requirementId = Get-EdidPropertyValue $_ "id"
            $requirementText = Get-EdidPropertyValue $_ "text"
            if ($requirementId -and $requirementText) { "- $requirementId`: $requirementText" } else { "- $_" }
        }) + @(
            "",
            "## Recent evidence",
            ""
        ) + $evidenceLines + @(
            "",
            "## Required reading",
            "",
            "- AGENTS.md",
            "- docs/methodology.md",
            "- docs/architecture.md",
            "- docs/decisions.md",
            "- $($task.contract_path)",
            "- .edid/roles/$($(if ($task.status -in @('evaluating','evaluated')) { 'evaluator' } elseif ($task.status -eq 'repair_required') { 'repair' } else { 'builder' })).md"
        )
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($contextPath, $content, $utf8)
        [pscustomobject]@{ ContextPath = $contextPath; TaskId = $TaskId }
    }

    "Handoff" {
        New-Item -ItemType Directory -Path $paths.Handoffs -Force | Out-Null
        $handoffPath = Join-Path $paths.Handoffs "current.md"
        $taskLines = @($state.tasks | ForEach-Object {
            "- $($_.id): $($_.status) ($($_.mode), risk $($_.risk)) - $($_.title)"
        })
        if ($taskLines.Count -eq 0) { $taskLines = @("- No tasks recorded.") }
        $repairLines = @($state.repair_packets | Where-Object { $_.status -eq "open" } | ForEach-Object {
            "- $($_.id): evaluation $($_.evaluation_run_id), attempt $($_.attempt)"
        })
        if ($repairLines.Count -eq 0) { $repairLines = @("- No open repair packets.") }
        $lines = @(
            "# EDID session handoff",
            "",
            "- Project state: $($state.project_state)",
            "- Phase: $($state.phase)",
            "- Active task: $($state.active_task_id)",
            "- Generated: $((Get-Date).ToUniversalTime().ToString('o'))",
            "",
            "## Tasks",
            ""
        ) + $taskLines + @("", "## Open repairs", "") + $repairLines + @(
            "",
            "## Resume protocol",
            "",
            "1. Read AGENTS.md and docs/methodology.md.",
            "2. Run `.\.edid\Invoke-Harness.ps1 Validate`.",
            "3. Run `.\.edid\Invoke-Harness.ps1 Context -TaskId <active-task>`.",
            "4. Read the generated context pack and relevant role file before acting."
        )
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($handoffPath, $lines, $utf8)
        $state.last_handoff_at = (Get-Date).ToUniversalTime().ToString("o")
        Save-HarnessState
        [pscustomobject]@{ HandoffPath = $handoffPath; ActiveTaskId = $state.active_task_id }
    }

    "Release" {
        $incomplete = @($state.tasks | Where-Object { $_.status -ne "complete" })
        $requiredKinds = @($config.release.$TargetState)
        $passingKinds = @($state.evidence | Where-Object { $_.result -eq "pass" } | Select-Object -ExpandProperty kind -Unique)
        $missingKinds = @($requiredKinds | Where-Object { $_ -notin $passingKinds })
        $releaseResult = [pscustomobject]@{
            TargetState = $TargetState
            Passed = $incomplete.Count -eq 0 -and $missingKinds.Count -eq 0
            IncompleteTasks = @($incomplete | Select-Object -ExpandProperty id)
            RequiredEvidenceKinds = $requiredKinds
            MissingEvidenceKinds = $missingKinds
            CheckedAt = (Get-Date).ToUniversalTime().ToString("o")
        }
        if ($releaseResult.Passed) {
            $state.project_state = $TargetState
            $state.phase = if ($TargetState -eq "production_proven") { "learn" } else { "release" }
            Save-HarnessState
        }
        $releaseResult
        if (-not $releaseResult.Passed) { exit 1 }
    }
}
