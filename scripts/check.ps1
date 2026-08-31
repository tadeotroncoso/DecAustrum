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

if (-not (Test-Path -LiteralPath $virtualPython)) {
    throw "Run scripts\bootstrap.ps1 before the project checks."
}

& (Join-Path $repositoryRoot "scripts\security-check.ps1")

$artifactDirectory = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("decaustrum-build-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $artifactDirectory | Out-Null
$sdkBuildSource = Join-Path $artifactDirectory "sdk-python"
$wheelDirectory = Join-Path $artifactDirectory "wheel"
New-Item -ItemType Directory -Path $sdkBuildSource | Out-Null
New-Item -ItemType Directory -Path $wheelDirectory | Out-Null
Copy-Item -LiteralPath (
    Join-Path $repositoryRoot "sdk\python\pyproject.toml"
) -Destination $sdkBuildSource
Copy-Item -LiteralPath (
    Join-Path $repositoryRoot "sdk\python\README.md"
) -Destination $sdkBuildSource
Copy-Item -LiteralPath (
    Join-Path $repositoryRoot "sdk\python\LICENSE"
) -Destination $sdkBuildSource
Copy-Item -LiteralPath (
    Join-Path $repositoryRoot "sdk\python\THIRD_PARTY_NOTICES.md"
) -Destination $sdkBuildSource
Copy-Item -LiteralPath (
    Join-Path $repositoryRoot "sdk\python\src"
) -Destination $sdkBuildSource -Recurse

try {
    & $virtualPython -m pip check
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Dependency consistency check"
    & $virtualPython -m ruff check `
        app `
        "sdk\python\src" `
        scripts `
        tests
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Python lint check"
    & $virtualPython -m mypy
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Static type check"
    & $virtualPython -m pytest `
        -q `
        -p no:cacheprovider `
        --cov=app `
        --cov=decaustrum `
        --cov-branch `
        --cov-report=term-missing
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Test and coverage suite"
    & $virtualPython -m pip wheel `
        --no-deps `
        --no-build-isolation `
        --wheel-dir $wheelDirectory `
        $sdkBuildSource
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "SDK wheel build"
} finally {
    $resolvedArtifacts = (Resolve-Path -LiteralPath $artifactDirectory).Path
    $temporaryPrefix = [System.IO.Path]::GetTempPath().TrimEnd("\") + "\"

    if (-not $resolvedArtifacts.StartsWith(
        $temporaryPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing to remove non-temporary path: $resolvedArtifacts"
    }

    Remove-Item -LiteralPath $resolvedArtifacts -Recurse -Force
}

Write-Host "DecAustrum quality, tests, and package builds passed."
