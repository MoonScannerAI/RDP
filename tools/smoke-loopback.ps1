#requires -version 5.1
<#
.SYNOPSIS
    Loopback smoke test placeholder for M1 (host/client core).

.DESCRIPTION
    This script is a placeholder. The real loopback smoke test arrives with
    M1, once DirectDeskHost.exe and DirectDeskClient.exe actually implement
    capture/encode/stream/decode/display. As of M0, both exes are scaffolds
    (see host/src/main.rs, client/src/main.rs) and do not accept any CLI
    flags at all.

    Once M1 lands, this script is meant to:
      1. Build (or locate) release binaries for host and client.
      2. Start "DirectDeskHost.exe --selftest" - a self-contained check that
         exercises capture -> encode without needing a network peer, and
         exits 0 on success / non-zero on failure.
      3. Start "DirectDeskClient.exe --loopback-demo" - connects the client
         to a host running on localhost (loopback), exercises the full
         connect -> decode -> display path, and exits 0 on success.
      4. Check both exit codes and report PASS/FAIL accordingly.

    SYNC-POINT: "--selftest" (host) and "--loopback-demo" (client) are the
    flag names this script expects. Whoever implements the host/client CLI
    in M1 should either match these exact flag names or update this script
    to match whatever flags are actually implemented.

    Written for PowerShell 5.1 compatibility: no && / || chaining, no
    ternary operator, no null-conditional operator.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

$HostExe = Join-Path $RepoRoot "target\release\DirectDeskHost.exe"
$ClientExe = Join-Path $RepoRoot "target\release\DirectDeskClient.exe"

Write-Host "==> DirectDesk loopback smoke test" -ForegroundColor Cyan

$skipped = $false

if (-not (Test-Path $HostExe)) {
    Write-Host "SKIP (TODO M1): $HostExe not found. Run tools\build-installer.ps1 or 'cargo build --release' first once host --selftest exists." -ForegroundColor Yellow
    $skipped = $true
}

if (-not (Test-Path $ClientExe)) {
    Write-Host "SKIP (TODO M1): $ClientExe not found. Run tools\build-installer.ps1 or 'cargo build --release' first once client --loopback-demo exists." -ForegroundColor Yellow
    $skipped = $true
}

if ($skipped) {
    Write-Host ""
    Write-Host "SKIPPED: loopback smoke test not runnable yet (M1 not landed)." -ForegroundColor Yellow
    Write-Host "This is expected on the M0 tree and is not a failure." -ForegroundColor Yellow
    exit 0
}

Write-Host "==> $HostExe --selftest"
& $HostExe --selftest
$hostExit = $LASTEXITCODE

if ($hostExit -ne 0) {
    Write-Host "FAIL: host --selftest exited $hostExit" -ForegroundColor Red
    exit 1
}
Write-Host "    PASS: host --selftest" -ForegroundColor Green

Write-Host "==> $ClientExe --loopback-demo"
& $ClientExe --loopback-demo
$clientExit = $LASTEXITCODE

if ($clientExit -ne 0) {
    Write-Host "FAIL: client --loopback-demo exited $clientExit" -ForegroundColor Red
    exit 1
}
Write-Host "    PASS: client --loopback-demo" -ForegroundColor Green

Write-Host ""
Write-Host "OVERALL: PASS" -ForegroundColor Green
exit 0
