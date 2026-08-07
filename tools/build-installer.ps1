#requires -version 5.1
<#
.SYNOPSIS
    Builds DirectDesk in release mode, then compiles the Inno Setup
    installer (installer/directdesk.iss) with ISCC.exe if it can be found.

.DESCRIPTION
        powershell -NoProfile -File tools\build-installer.ps1

    If Inno Setup 6's ISCC.exe cannot be found in any of the standard
    locations, this script builds the release binaries anyway and then
    prints a clear, non-fatal message explaining how to install Inno Setup
    and re-run, rather than failing with a confusing "command not found".

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$IssPath = Join-Path $RepoRoot "installer\directdesk.iss"

$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

Push-Location $RepoRoot
try {
    # Deliberately three per-crate builds rather than one `--workspace`.
    #
    # Cargo unifies features across every member built in a single invocation.
    # `directdesk-tests` depends on `directdesk-shared` with `features =
    # ["netsim"]`, so a `--workspace` build compiles `shared` ONCE with the
    # simulator switched on and links that rlib into all three shipped exes --
    # silently undoing the parking that `shared/Cargo.toml` exists to do.
    # Naming the three product crates keeps the tests crate out of the resolve,
    # so the shipped binaries get the small `shared`. Same three exes either way.
    Write-Host "==> cargo build --release (host, client, service)" -ForegroundColor Cyan
    & cargo build --release -p directdesk-host -p directdesk-client -p directdesk-service
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: release build failed (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }
    Write-Host "    release build OK" -ForegroundColor Green

    $expectedExes = @(
        "target\release\DirectDeskHost.exe",
        "target\release\DirectDeskClient.exe",
        "target\release\DirectDeskService.exe"
    )
    $missing = New-Object System.Collections.ArrayList
    foreach ($exe in $expectedExes) {
        $full = Join-Path $RepoRoot $exe
        if (-not (Test-Path $full)) {
            [void]$missing.Add($exe)
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host "FAIL: expected release binaries missing after build:" -ForegroundColor Red
        foreach ($m in $missing) { Write-Host "    $m" -ForegroundColor Red }
        exit 1
    }

    if (-not (Test-Path $IssPath)) {
        Write-Host "FAIL: installer script not found at $IssPath" -ForegroundColor Red
        exit 1
    }

    # Search standard Inno Setup 6 install locations plus the winget location.
    $candidates = @(
        "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\JRSoftware.InnoSetup_Microsoft.Winget.Source_8wekyb3d8bbwe\ISCC.exe"
    )

    # winget installs land under a version-suffixed folder that varies; glob for it too.
    $wingetGlobRoot = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"
    if (Test-Path $wingetGlobRoot) {
        $wingetMatches = Get-ChildItem -Path $wingetGlobRoot -Filter "ISCC.exe" -Recurse -ErrorAction SilentlyContinue
        foreach ($m in $wingetMatches) {
            $candidates += $m.FullName
        }
    }

    # Also honor ISCC already being on PATH.
    $onPath = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($onPath) {
        $candidates = @($onPath.Source) + $candidates
    }

    $isccPath = $null
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            $isccPath = $c
            break
        }
    }

    if (-not $isccPath) {
        Write-Host ""
        Write-Host "Inno Setup 6 (ISCC.exe) was not found." -ForegroundColor Yellow
        Write-Host "Release binaries were built successfully, but the installer was NOT compiled." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To build the installer, install Inno Setup 6 with one of:" -ForegroundColor Yellow
        Write-Host "    winget install JRSoftware.InnoSetup" -ForegroundColor Yellow
        Write-Host "    (or download from https://jrsoftware.org/isdl.php)" -ForegroundColor Yellow
        Write-Host "then re-run this script." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "==> Found ISCC.exe at $isccPath" -ForegroundColor Cyan
    Write-Host "==> Compiling installer\directdesk.iss" -ForegroundColor Cyan
    & $isccPath $IssPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: ISCC.exe failed (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }

    Write-Host ""
    Write-Host "PASS: installer built. Check installer\Output\ for the result." -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
