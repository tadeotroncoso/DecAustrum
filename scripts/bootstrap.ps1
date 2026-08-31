[CmdletBinding()]
param(
    [switch]$RuntimeOnly
)

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
$pythonCommand = Get-Command python -ErrorAction Stop
$pythonMinor = & $pythonCommand.Source -c (
    "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
)
Assert-NativeCommandSucceeded `
    -ExitCode $LASTEXITCODE `
    -Operation "Python version check"

if ($pythonMinor -ne "3.12") {
    throw "DecAustrum requires Python 3.12; found $pythonMinor."
}

$virtualEnvironment = Join-Path $repositoryRoot ".venv"
$virtualPython = Join-Path $virtualEnvironment "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $virtualPython)) {
    & $pythonCommand.Source -m venv $virtualEnvironment
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Virtual environment creation"
}

& $virtualPython -m pip install --upgrade "pip==26.2.1"
Assert-NativeCommandSucceeded `
    -ExitCode $LASTEXITCODE `
    -Operation "pip installation"

$lockFile = if ($RuntimeOnly) {
    Join-Path $repositoryRoot "requirements\runtime.lock"
} else {
    Join-Path $repositoryRoot "requirements\dev.lock"
}

& $virtualPython -m pip install --no-deps --requirement $lockFile
Assert-NativeCommandSucceeded `
    -ExitCode $LASTEXITCODE `
    -Operation "Locked dependency installation"
& $virtualPython -m pip check
Assert-NativeCommandSucceeded `
    -ExitCode $LASTEXITCODE `
    -Operation "Dependency consistency check"

if (-not $RuntimeOnly) {
    & $virtualPython -m pip install `
        --no-deps `
        --no-build-isolation `
        --editable $repositoryRoot
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "Backend editable installation"
    & $virtualPython -m pip install `
        --no-deps `
        --no-build-isolation `
        --editable (Join-Path $repositoryRoot "sdk\python")
    Assert-NativeCommandSucceeded `
        -ExitCode $LASTEXITCODE `
        -Operation "SDK editable installation"
}

Write-Host "DecAustrum environment is ready at $virtualEnvironment"
