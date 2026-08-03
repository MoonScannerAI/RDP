#requires -version 5.1
<#
.SYNOPSIS
    Thin manual equivalent of the uninstall steps performed by the Inno
    Setup installer's [UninstallRun]/[Registry] sections (see
    installer\directdesk.iss), for machines installed via
    installer\scripts\install.ps1 rather than the real installer.

.DESCRIPTION
        powershell -NoProfile -File installer\scripts\uninstall.ps1 [-InstallDir <path>] [-DeleteProgramData]

    Stops+uninstalls the DirectDesk service (if present), removes the HKCU
    "DirectDesk Host" Run entry (if present), removes the DirectDesk
    firewall rule group (if present), and deletes the three exes from
    $InstallDir. Prompts before deleting %ProgramData%\DirectDesk unless
    -DeleteProgramData or -KeepProgramData is passed explicitly (matching
    the installer's uninstall-time prompt - never a silent default either
    way).

    SYNC-POINT: this script assumes DirectDeskService.exe accepts
    "stop" / "uninstall" verbs, same as installer\directdesk.iss. See that
    file's header comment.

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

param(
    [string]$InstallDir = "$env:ProgramFiles\DirectDesk",
    [switch]$DeleteProgramData,
    [switch]$KeepProgramData
)

Write-Host "==> DirectDesk manual uninstall" -ForegroundColor Cyan

$serviceExe = Join-Path $InstallDir "DirectDeskService.exe"

if (Test-Path $serviceExe) {
    Write-Host "    $serviceExe stop"
    & $serviceExe stop
    # Non-fatal if it was already stopped/not installed.

    Write-Host "    $serviceExe uninstall"
    & $serviceExe uninstall
    # Non-fatal if it was never installed.
} else {
    Write-Host "    (DirectDeskService.exe not found at $serviceExe - skipping service stop/uninstall)" -ForegroundColor Yellow
}

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$existing = Get-ItemProperty -Path $runKeyPath -Name "DirectDesk Host" -ErrorAction SilentlyContinue
if ($existing) {
    Remove-ItemProperty -Path $runKeyPath -Name "DirectDesk Host" -ErrorAction SilentlyContinue
    Write-Host "    removed HKCU Run entry 'DirectDesk Host'"
} else {
    Write-Host "    (no HKCU Run entry 'DirectDesk Host' found - nothing to remove)"
}

$fwRules = Get-NetFirewallRule -DisplayGroup "DirectDesk" -ErrorAction SilentlyContinue
if ($fwRules) {
    $fwRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "    removed DirectDesk firewall rule group"
} else {
    Write-Host "    (no DirectDesk firewall rules found - nothing to remove)"
}

if (Test-Path $InstallDir) {
    $exes = @("DirectDeskHost.exe", "DirectDeskClient.exe", "DirectDeskService.exe")
    foreach ($exe in $exes) {
        $p = Join-Path $InstallDir $exe
        if (Test-Path $p) {
            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
            Write-Host "    removed $exe"
        }
    }
    # Only remove the directory itself if it's now empty - don't blow away
    # anything unexpected a user might have placed alongside the exes.
    $remaining = Get-ChildItem -Path $InstallDir -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item -Path $InstallDir -Force -ErrorAction SilentlyContinue
        Write-Host "    removed empty directory $InstallDir"
    }
}

Write-Host "PASS: DirectDesk binaries and autostart configuration removed" -ForegroundColor Green

$programDataDir = "$env:ProgramData\DirectDesk"
if (Test-Path $programDataDir) {
    $doDelete = $false

    if ($DeleteProgramData) {
        $doDelete = $true
    } elseif ($KeepProgramData) {
        $doDelete = $false
    } else {
        Write-Host ""
        $answer = Read-Host "Delete DirectDesk's stored data in $programDataDir ? [y/N]"
        if ($answer -eq "y" -or $answer -eq "Y") {
            $doDelete = $true
        }
    }

    if ($doDelete) {
        Remove-Item -Path $programDataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "    removed $programDataDir" -ForegroundColor Green
    } else {
        Write-Host "    kept $programDataDir" -ForegroundColor Yellow
    }
} else {
    Write-Host "    (no $programDataDir found - nothing to prompt about)"
}

exit 0
