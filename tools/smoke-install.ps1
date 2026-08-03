#requires -version 5.1
<#
.SYNOPSIS
    Installer smoke test placeholder for M7.

.DESCRIPTION
    This script is a placeholder. There is no installer output to test yet
    until tools\build-installer.ps1 has produced installer\Output\*.exe AND
    the service/host CLI verbs it depends on (see the SYNC-POINT comment in
    installer\directdesk.iss) actually exist. Running this script today
    just reports that it is not yet implemented and exits 0 (not a failure
    - there's nothing to test yet, so "skipped" is the correct, honest
    result, same as tools\smoke-loopback.ps1's M1 placeholder behavior).

    PLANNED STEPS (M7), to be implemented for real once the installer and
    service CLI exist:

      1. Locate installer\Output\*.exe (the compiled Inno Setup installer
         produced by tools\build-installer.ps1). Fail clearly if absent
         with instructions to run that script first.

      2. Run the installer silently for an unattended smoke test:
             installer\Output\DirectDeskSetup-<version>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
         (Inno Setup's standard silent-install switches - no code signing
         means no additional SmartScreen bypass is scriptable here; a CI
         runner would need SmartScreen/Defender exclusions configured
         separately, which is out of scope for this script.)

      3. Verify the three executables landed in {autopf}\DirectDesk:
             Test-Path "$env:ProgramFiles\DirectDesk\DirectDeskHost.exe"
             Test-Path "$env:ProgramFiles\DirectDesk\DirectDeskClient.exe"
             Test-Path "$env:ProgramFiles\DirectDesk\DirectDeskService.exe"

      4. Verify Start Menu shortcuts exist for host and client.

      5. If the installer was run with the "start automatically with
         Windows" task selected, verify:
           - The DirectDesk service is installed and running:
                 Get-Service DirectDeskService
           - The HKCU Run key entry "DirectDesk Host" exists and points at
             DirectDeskHost.exe --minimized (SYNC-POINT: confirm this flag
             name against whatever the host CLI actually implements).
           - The firewall rule group "DirectDesk" exists:
                 Get-NetFirewallRule -DisplayGroup "DirectDesk"

      6. Run the uninstaller (from Programs and Features / the generated
         unins000.exe) silently:
             & "$env:ProgramFiles\DirectDesk\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

      7. Verify full reversal:
           - Service uninstalled: Get-Service DirectDeskService should
             error/not-found.
           - HKCU Run entry removed.
           - Firewall rule group removed.
           - Install directory removed (modulo any files the uninstall
             page's %ProgramData%\DirectDesk prompt intentionally left
             behind if the tester chose to keep them - this script should
             test both the "keep" and "delete" paths of that prompt across
             two separate runs if it's to be a real regression test).

      8. Report PASS/FAIL per step, overall PASS/FAIL, matching the
         PASS/FAIL summary convention used by tools\check.ps1.

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$OutputDir = Join-Path $RepoRoot "installer\Output"

Write-Host "==> DirectDesk installer smoke test (M7 placeholder)" -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) {
    Write-Host "SKIP (TODO M7): $OutputDir does not exist yet. Run tools\build-installer.ps1 first." -ForegroundColor Yellow
    Write-Host "SKIPPED: this script is not yet implemented - see the PLANNED STEPS comment block at the top of this file." -ForegroundColor Yellow
    exit 0
}

Write-Host "SKIP (TODO M7): installer output found, but this smoke test is not yet implemented." -ForegroundColor Yellow
Write-Host "See the PLANNED STEPS comment block at the top of this file for what it will do." -ForegroundColor Yellow
exit 0
