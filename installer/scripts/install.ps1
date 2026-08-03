#requires -version 5.1
<#
.SYNOPSIS
    Thin manual equivalent of installer\directdesk.iss, for machines where
    running the Inno Setup installer isn't convenient (e.g. a dev box you
    just built release binaries on). Not a replacement for the real
    installer for end users - it does not register an uninstall entry in
    "Apps & features"; use installer\Output\DirectDeskSetup-*.exe for that.

.DESCRIPTION
        powershell -NoProfile -File installer\scripts\install.ps1 [-InstallDir <path>] [-Autostart]

    Copies the three release exes to $InstallDir (default
    C:\Program Files\DirectDesk), and - only if -Autostart is passed -
    installs+starts the DirectDesk service and adds the visible
    "DirectDesk Host" HKCU Run entry. Requires Administrator for the copy
    into Program Files and for the service install step.

    SYNC-POINT: this script assumes DirectDeskService.exe accepts
    "install" / "start" verbs, and that DirectDeskHost.exe accepts a
    "--minimized" flag, exactly like installer\directdesk.iss does. See
    that file's header comment - these do not exist yet in the M0
    scaffold and must be kept in sync with whatever the host/service CLI
    parsing actually implements.

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

param(
    [string]$InstallDir = "$env:ProgramFiles\DirectDesk",
    [switch]$Autostart
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$ReleaseDir = Join-Path $RepoRoot "target\release"

$exes = @("DirectDeskHost.exe", "DirectDeskClient.exe", "DirectDeskService.exe")

Write-Host "==> DirectDesk manual install" -ForegroundColor Cyan
Write-Host "    Source:      $ReleaseDir"
Write-Host "    Destination: $InstallDir"

$missing = New-Object System.Collections.ArrayList
foreach ($exe in $exes) {
    $src = Join-Path $ReleaseDir $exe
    if (-not (Test-Path $src)) {
        [void]$missing.Add($src)
    }
}
if ($missing.Count -gt 0) {
    Write-Host "FAIL: missing release binaries. Run 'cargo build --workspace --release' first:" -ForegroundColor Red
    foreach ($m in $missing) { Write-Host "    $m" -ForegroundColor Red }
    exit 1
}

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

foreach ($exe in $exes) {
    $src = Join-Path $ReleaseDir $exe
    $dst = Join-Path $InstallDir $exe
    Copy-Item -Path $src -Destination $dst -Force
    Write-Host "    copied $exe"
}

Write-Host "PASS: binaries installed to $InstallDir" -ForegroundColor Green

if ($Autostart) {
    Write-Host ""
    Write-Host "==> Configuring autostart (service + HKCU Run entry)" -ForegroundColor Cyan

    $serviceExe = Join-Path $InstallDir "DirectDeskService.exe"
    $hostExe = Join-Path $InstallDir "DirectDeskHost.exe"

    Write-Host "    $serviceExe install"
    & $serviceExe install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: service install failed (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }

    Write-Host "    $serviceExe start"
    & $serviceExe start
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAIL: service start failed (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }

    $runValue = '"' + $hostExe + '" --minimized'
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "DirectDesk Host" -Value $runValue -PropertyType String -Force | Out-Null

    Write-Host "PASS: autostart configured (service installed+started, HKCU Run entry 'DirectDesk Host' set)" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Autostart not requested (-Autostart not passed) - no service or startup entry was created." -ForegroundColor Yellow
    Write-Host "This installer never enables autostart or firewall changes silently." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Note: unlike installer\directdesk.iss, this script does not register" -ForegroundColor Cyan
Write-Host "an entry in Windows 'Apps & features' or create Start Menu shortcuts." -ForegroundColor Cyan
exit 0
