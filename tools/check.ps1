#requires -version 5.1
<#
.SYNOPSIS
    DirectDesk workspace gate: fmt-check, clippy (deny warnings), and the
    full test suite. Prints one PASS/FAIL summary line per check plus an
    overall result, and exits non-zero if anything failed.

.DESCRIPTION
    Run this before considering any change to the workspace done:

        powershell -NoProfile -File tools\check.ps1

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

# Resolve the repo root as the parent of this script's directory, so this
# works regardless of the caller's current directory.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

# Prepend cargo to PATH for this session (rustup normally does this
# permanently, but a fresh/CI shell may not have it yet).
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

Push-Location $RepoRoot
try {
    $results = New-Object System.Collections.ArrayList
    $overallPass = $true

    function Run-Check {
        param(
            [string]$Name,
            [string[]]$ArgList
        )

        Write-Host ""
        Write-Host "==> $Name" -ForegroundColor Cyan
        Write-Host ("    cargo " + ($ArgList -join " "))

        & cargo @ArgList
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Host "    PASS: $Name" -ForegroundColor Green
            [void]$results.Add([PSCustomObject]@{ Name = $Name; Pass = $true })
        } else {
            Write-Host "    FAIL: $Name (exit code $exitCode)" -ForegroundColor Red
            [void]$results.Add([PSCustomObject]@{ Name = $Name; Pass = $false })
        }

        return $exitCode -eq 0
    }

    $fmtOk = Run-Check -Name "cargo fmt --check" -ArgList @("fmt", "--check")
    if (-not $fmtOk) { $overallPass = $false }

    $clippyOk = Run-Check -Name "cargo clippy --workspace -D warnings" -ArgList @("clippy", "--workspace", "--", "-D", "warnings")
    if (-not $clippyOk) { $overallPass = $false }

    $testOk = Run-Check -Name "cargo test --workspace" -ArgList @("test", "--workspace")
    if (-not $testOk) { $overallPass = $false }

    Write-Host ""
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "DirectDesk check.ps1 summary" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan

    foreach ($r in $results) {
        if ($r.Pass) {
            Write-Host ("  PASS  " + $r.Name) -ForegroundColor Green
        } else {
            Write-Host ("  FAIL  " + $r.Name) -ForegroundColor Red
        }
    }

    Write-Host ""
    if ($overallPass) {
        Write-Host "OVERALL: PASS" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "OVERALL: FAIL" -ForegroundColor Red
        exit 1
    }
}
finally {
    Pop-Location
}
