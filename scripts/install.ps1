<#
.SYNOPSIS
    Install the Trident CLI and its scanner tools on Windows.

.PARAMETER Venv
    Path to the virtual environment to create or reuse.
    Defaults to the per-user Trident data directory.

.PARAMETER SkipWarmup
    Install and verify tools without downloading vulnerability databases.

.EXAMPLE
    ./scripts/install.ps1
    ./scripts/install.ps1 -Venv C:/dev/trident-venv -SkipWarmup
#>

param(
    [string]$Venv = "$env:LOCALAPPDATA/Trident/venv",
    [switch]$SkipWarmup
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Backend = Join-Path $Root "backend"

function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "    ERROR: $msg" -ForegroundColor Red; exit 1 }

Step "Creating virtual environment at $Venv"
python -m venv $Venv
if ($LASTEXITCODE -ne 0) { Fail "python -m venv failed" }

$Python = Join-Path $Venv "Scripts/python.exe"
$Trident = Join-Path $Venv "Scripts/trident.exe"

Step "Installing the Trident CLI"
& $Python -m pip install $Backend --quiet
if ($LASTEXITCODE -ne 0) { Fail "pip install failed" }

Step "Installing and verifying scanner tools"
$ToolArgs = @("install-tools", "--verify")
if (-not $SkipWarmup) { $ToolArgs += "--warmup" }
& $Trident @ToolArgs
if ($LASTEXITCODE -ne 0) { Fail "install-tools failed" }

Write-Host ""
Write-Host "Trident CLI is installed and ready." -ForegroundColor Green
Write-Host "  CLI:  $Trident" -ForegroundColor White
Write-Host "  Scan: $Trident scan <path>" -ForegroundColor White
