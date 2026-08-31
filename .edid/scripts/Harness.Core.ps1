Set-StrictMode -Version Latest

function Get-EdidPaths {
    param([Parameter(Mandatory = $true)][string]$ProjectPath)

    $root = [System.IO.Path]::GetFullPath($ProjectPath)
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "Project path does not exist: $root"
    }

    [pscustomobject]@{
        Root = $root
        Harness = Join-Path $root ".edid"
        Config = Join-Path $root ".edid\harness.json"
        State = Join-Path $root ".edid\state.json"
        Contracts = Join-Path $root ".edid\contracts"
        Evidence = Join-Path $root ".edid\evidence"
        Evaluations = Join-Path $root ".edid\evaluations"
        Repairs = Join-Path $root ".edid\repairs"
        Context = Join-Path $root ".edid\context"
        Handoffs = Join-Path $root ".edid\handoffs"
    }
}

function Read-EdidJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required EDID file is missing: $Path"
    }

    try {
        Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    } catch {
        throw "Invalid JSON in $Path`: $($_.Exception.Message)"
    }
}

function Get-EdidPropertyValue {
    param($Object, [Parameter(Mandatory = $true)][string]$Name, $Default = $null)

    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $Default
}

function Write-EdidJsonAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = Join-Path $parent (([System.IO.Path]::GetFileName($Path)) + ".tmp-" + [guid]::NewGuid().ToString("N"))
    $json = $Value | ConvertTo-Json -Depth 30
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Resolve-EdidProjectPath {
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [switch]$AllowMissing
    )

    $candidate = [System.IO.Path]::GetFullPath((Join-Path $Paths.Root $RelativePath))
    $rootPrefix = $Paths.Root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ne $Paths.Root -and
        -not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes the project root: $RelativePath"
    }

    if (-not $AllowMissing -and -not (Test-Path -LiteralPath $candidate)) {
        throw "Project path is missing: $RelativePath"
    }

    $candidate
}

function Get-EdidTask {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskId
    )

    $task = @($State.tasks) | Where-Object { $_.id -eq $TaskId } | Select-Object -First 1
    if (-not $task) {
        throw "Unknown task: $TaskId"
    }
    $task
}

function Get-EdidAdaptiveMode {
    param(
        [ValidateSet("narrow", "feature", "product", "release")][string]$Scope,
        [ValidateSet("low", "medium", "high", "critical")][string]$Risk
    )

    if ($Scope -eq "narrow" -and $Risk -eq "low") { return "lightweight" }
    if ($Scope -eq "release" -or $Risk -in @("high", "critical")) { return "high_assurance" }
    "standard"
}

function Test-EdidContract {
    param(
        [Parameter(Mandatory = $true)]$Contract,
        [Parameter(Mandatory = $true)][string]$ExpectedTaskId
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $contractVersion = [int](Get-EdidPropertyValue $Contract "version" 0)
    if ($contractVersion -notin @(1, 2)) { $errors.Add("contract version must be 1 or 2") }
    if ((Get-EdidPropertyValue $Contract "task_id") -ne $ExpectedTaskId) { $errors.Add("contract task_id must match $ExpectedTaskId") }
    if ([string]::IsNullOrWhiteSpace([string](Get-EdidPropertyValue $Contract "title"))) { $errors.Add("contract title is required") }
    $requirements = @(Get-EdidPropertyValue $Contract "requirements" @())
    if ($requirements.Count -lt 1) { $errors.Add("at least one requirement is required") }
    if (@(Get-EdidPropertyValue $Contract "checks" @()).Count -lt 1) { $errors.Add("at least one acceptance check is required") }

    $requirementIds = @{}
    if ($contractVersion -eq 2) {
        foreach ($requirement in $requirements) {
            $requirementId = [string](Get-EdidPropertyValue $requirement "id")
            $requirementText = [string](Get-EdidPropertyValue $requirement "text")
            if ($requirementId -notmatch '^[A-Z][A-Z0-9]*-[0-9][A-Z0-9.-]*$') {
                $errors.Add("invalid requirement id: $requirementId")
            } elseif ($requirementIds.ContainsKey($requirementId)) {
                $errors.Add("duplicate requirement id: $requirementId")
            } else {
                $requirementIds[$requirementId] = $true
            }
            if ([string]::IsNullOrWhiteSpace($requirementText)) {
                $errors.Add("requirement $requirementId requires text")
            }
        }
    }

    $checkIds = @{}
    $coveredRequirements = @{}
    foreach ($check in @(Get-EdidPropertyValue $Contract "checks" @())) {
        if ([string]::IsNullOrWhiteSpace([string]$check.id)) {
            $errors.Add("each check requires an id")
        } elseif ($checkIds.ContainsKey([string]$check.id)) {
            $errors.Add("duplicate check id: $($check.id)")
        } else {
            $checkIds[[string]$check.id] = $true
        }

        if ($check.type -notin @("command", "file", "http", "adapter", "manual")) {
            $errors.Add("unsupported check type for $($check.id): $($check.type)")
        }
        if ([string]::IsNullOrWhiteSpace([string]$check.evidence_kind)) {
            $errors.Add("check $($check.id) requires evidence_kind")
        }
        if ($contractVersion -eq 2) {
            $checkRequirementIds = @(Get-EdidPropertyValue $check "requirement_ids" @())
            if ($checkRequirementIds.Count -lt 1) {
                $errors.Add("check $($check.id) must cover at least one requirement")
            }
            foreach ($requirementId in $checkRequirementIds) {
                $normalizedRequirementId = [string]$requirementId
                if (-not $requirementIds.ContainsKey($normalizedRequirementId)) {
                    $errors.Add("check $($check.id) references unknown requirement: $normalizedRequirementId")
                } else {
                    $coveredRequirements[$normalizedRequirementId] = $true
                }
            }
        }
        if ($check.type -eq "command" -and [string]::IsNullOrWhiteSpace([string]$check.executable)) {
            $errors.Add("command check $($check.id) requires executable")
        }
        if ($check.type -eq "file" -and [string]::IsNullOrWhiteSpace([string]$check.path)) {
            $errors.Add("file check $($check.id) requires path")
        }
        if ($check.type -eq "http" -and [string]::IsNullOrWhiteSpace([string]$check.url)) {
            $errors.Add("http check $($check.id) requires url")
        }
        if ($check.type -eq "adapter" -and $check.adapter -notin @("browser", "deployment", "observability", "security")) {
            $errors.Add("adapter check $($check.id) has an unsupported adapter")
        }
    }

    if ($contractVersion -eq 2) {
        foreach ($requirementId in $requirementIds.Keys) {
            if (-not $coveredRequirements.ContainsKey($requirementId)) {
                $errors.Add("requirement has no acceptance check: $requirementId")
            }
        }
    }

    $qualityGates = Get-EdidPropertyValue $Contract "quality_gates"
    foreach ($hardGate in @("security", "correctness", "reliability")) {
        $property = if ($qualityGates) { $qualityGates.PSObject.Properties[$hardGate] } else { $null }
        if (-not $property -or $property.Value -notin @("required", "not_applicable")) {
            $errors.Add("quality_gates.$hardGate must be required or not_applicable")
        }
    }
    if ($contractVersion -eq 2) {
        $qualityGateChecks = Get-EdidPropertyValue $Contract "quality_gate_checks"
        foreach ($qualityGateProperty in @($qualityGates.PSObject.Properties)) {
            if ($qualityGateProperty.Value -ne "required") { continue }
            $mapping = if ($qualityGateChecks) { $qualityGateChecks.PSObject.Properties[$qualityGateProperty.Name] } else { $null }
            $mappedCheckIds = @(if ($mapping) { $mapping.Value } else { @() })
            if ($mappedCheckIds.Count -lt 1) {
                $errors.Add("required quality gate has no acceptance check: $($qualityGateProperty.Name)")
                continue
            }
            foreach ($mappedCheckId in $mappedCheckIds) {
                if (-not $checkIds.ContainsKey([string]$mappedCheckId)) {
                    $errors.Add("quality gate $($qualityGateProperty.Name) references unknown check: $mappedCheckId")
                }
            }
        }
    }

    [pscustomobject]@{ Valid = $errors.Count -eq 0; Errors = $errors.ToArray() }
}

function Test-EdidAdapterConfig {
    param(
        [Parameter(Mandatory = $true)]$AdapterConfig,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    $errors = New-Object System.Collections.Generic.List[string]
    if ((Get-EdidPropertyValue $AdapterConfig "version") -ne 1) { $errors.Add("version must be 1") }
    if ((Get-EdidPropertyValue $AdapterConfig "adapter") -ne $ExpectedName) { $errors.Add("adapter must be $ExpectedName") }
    if ($null -eq (Get-EdidPropertyValue $AdapterConfig "enabled")) { $errors.Add("enabled must be present") }
    $ids = @{}
    foreach ($check in @(Get-EdidPropertyValue $AdapterConfig "checks" @())) {
        $id = [string](Get-EdidPropertyValue $check "id")
        $type = [string](Get-EdidPropertyValue $check "type")
        if ($id -notmatch '^[a-z0-9][a-z0-9._-]*$') { $errors.Add("invalid check id: $id") }
        elseif ($ids.ContainsKey($id)) { $errors.Add("duplicate check id: $id") }
        else { $ids[$id] = $true }
        if ($type -notin @("command", "https", "file")) { $errors.Add("unsupported check type for $id`: $type") }
        if ($type -eq "command" -and [string]::IsNullOrWhiteSpace([string](Get-EdidPropertyValue $check "executable"))) { $errors.Add("command check $id requires executable") }
        if ($type -eq "https" -and [string]::IsNullOrWhiteSpace([string](Get-EdidPropertyValue $check "url"))) { $errors.Add("https check $id requires url") }
        if ($type -eq "file" -and [string]::IsNullOrWhiteSpace([string](Get-EdidPropertyValue $check "path"))) { $errors.Add("file check $id requires path") }
    }
    [pscustomobject]@{ Valid=$errors.Count -eq 0; Errors=$errors.ToArray() }
}

function Add-EdidEvidenceRecord {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][ValidateSet("pass", "fail", "blocked", "not_run")][string]$Result,
        [Parameter(Mandatory = $true)][string]$Summary,
        [string]$ArtifactPath
    )

    $record = [pscustomobject]@{
        id = [guid]::NewGuid().ToString("N")
        task_id = $TaskId
        kind = $Kind
        source = $Source
        result = $Result
        summary = $Summary
        artifact_path = $ArtifactPath
        recorded_at = (Get-Date).ToUniversalTime().ToString("o")
    }
    $State.evidence = @($State.evidence) + $record
    $record
}
