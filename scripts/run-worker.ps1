[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot ".."
)).Path
$virtualPython = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$environmentFile = Join-Path $repositoryRoot ".env"

if (-not (Test-Path -LiteralPath $virtualPython)) {
    throw "Run scripts\bootstrap.ps1 before starting DecAustrum."
}

if (-not (Test-Path -LiteralPath $environmentFile)) {
    throw "Copy .env.example to .env and configure local secrets first."
}

Push-Location $repositoryRoot

try {
    & $virtualPython -m dotenv `
        --file $environmentFile `
        run -- `
        $virtualPython -m app.webhook_worker

    if ($LASTEXITCODE -ne 0) {
        throw "DecAustrum webhook worker exited with code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}
