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

& $virtualPython -m uvicorn app.main:app `
    --app-dir $repositoryRoot `
    --env-file $environmentFile `
    --host 127.0.0.1 `
    --port 8000 `
    --no-access-log

if ($LASTEXITCODE -ne 0) {
    throw "DecAustrum API exited with code $LASTEXITCODE."
}
