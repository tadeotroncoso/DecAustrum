[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Assert-NativeCommandSucceeded {
    param(
        [Parameter(Mandatory)]
        [int]$ExitCode,

        [Parameter(Mandatory)]
        [string]$Operation
    )

    if ($ExitCode -ne 0) {
        throw "$Operation failed with exit code $ExitCode."
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot ".."
)).Path
$virtualPython = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$detectSecretsHook = Join-Path (
    Split-Path -Parent $virtualPython
) "detect-secrets-hook.exe"
$secretsBaseline = Join-Path $repositoryRoot ".secrets.baseline"
$baselineValidator = Join-Path (
    $repositoryRoot
) "scripts\validate_secrets_baseline.py"

foreach ($requiredPath in @(
    $virtualPython,
    $detectSecretsHook,
    $secretsBaseline,
    $baselineValidator
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Security gate prerequisite is missing: $requiredPath"
    }
}

Push-Location $repositoryRoot

try {
    & $virtualPython $baselineValidator $secretsBaseline
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Secret baseline review"

    & $virtualPython -m pip_audit `
        --requirement "requirements\dev.lock" `
        --require-hashes `
        --disable-pip `
        --progress-spinner off
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Dependency vulnerability audit"

    $previousErrorActionPreference = $ErrorActionPreference
    $banditOutput = @()
    $banditExitCode = 1

    try {
        $ErrorActionPreference = "Continue"
        $banditOutput = @(
            & $virtualPython -m bandit `
                --recursive `
                app `
                "sdk\python\src" `
                scripts `
                --quiet 2>&1
        )
        $banditExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($banditExitCode -ne 0) {
        $banditOutput | ForEach-Object { Write-Host $_ }
        throw (
            "Python static security analysis failed with exit code " +
            "$banditExitCode."
        )
    }

    $publishableFiles = @(
        & git ls-files --cached --others --exclude-standard
    )
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Tracked file discovery"

    if ($publishableFiles.Count -eq 0) {
        throw "Secret scan requires at least one tracked file."
    }

    & $detectSecretsHook `
        --baseline $secretsBaseline `
        --no-verify `
        --exclude-files `
            '^\.(bandit-baseline\.json|secrets\.baseline)$' `
        @publishableFiles
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Secret scan"
} finally {
    Pop-Location
}

Write-Host "DecAustrum security gate passed."
