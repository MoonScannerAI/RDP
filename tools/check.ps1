#requires -version 5.1
<#
.SYNOPSIS
    DirectDesk workspace gate: fmt-check, clippy (deny warnings), and the
    full test suite. Prints one PASS/FAIL summary line per check plus an
    overall result, and exits non-zero if anything failed.

.DESCRIPTION
    Run this before considering any change to the workspace done:

        powershell -NoProfile -File tools\check.ps1

    When ANDROID_NDK_HOME and cargo-ndk are available, an Android stage also
    clippy-checks directdesk-android for arm64-v8a and x86_64; otherwise it
    prints a yellow SKIP that does not count towards OVERALL.

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

        # `| Out-Host` is load-bearing, not decoration. A bare `& cargo @ArgList`
        # writes cargo's stdout into THIS FUNCTION's pipeline output, so the
        # `return` below appends the boolean to a few hundred lines of build
        # chatter. The caller's `$ok = Run-Check ...` then holds an array, every
        # non-empty array is truthy, `-not $ok` is always false, and the script
        # reported OVERALL: PASS with a failing test suite and exit 0. Out-Host
        # writes straight to the console and contributes nothing to the pipeline.
        & cargo @ArgList | Out-Host
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

    # `--all-features` is not optional here. Several sizeable modules in
    # `shared` (transport::tcp, transport::race, nettest, netsim) are parked
    # behind default-off cargo features because no binary selects them. Without
    # this flag clippy simply would not see ~7100 lines of the workspace, and
    # parked code that nothing lints is code that rots. Do NOT also add
    # `--all-targets`: that would newly subject every test file in the workspace
    # to `-D warnings`, which is a large unrelated change in scope.
    $clippyOk = Run-Check -Name "cargo clippy --workspace --all-features -D warnings" -ArgList @("clippy", "--workspace", "--all-features", "--", "-D", "warnings")
    if (-not $clippyOk) { $overallPass = $false }

    $testOk = Run-Check -Name "cargo test --workspace" -ArgList @("test", "--workspace")
    if (-not $testOk) { $overallPass = $false }

    # Android cross-check: clippy the NativeActivity crate (and, through it,
    # client + shared as compiled for Android) for both shipped ABIs. On
    # Windows `directdesk-android` is an empty library, so the clippy run
    # above never sees its code; only this stage does.
    #
    # Counted exactly like the checks above when the toolchain is present. A
    # machine without the NDK gets a visible yellow SKIP that is NOT a PASS
    # and does not change OVERALL — the remaining checks decide it.
    #
    # `--lib` and never `--all-targets`: the client's dev-dependency on the
    # host crate (Windows capture/encode) does not build for Android.
    $androidName = "cargo ndk clippy -p directdesk-android (arm64-v8a, x86_64) -D warnings"
    $androidSkip = $null
    if ([string]::IsNullOrEmpty($env:ANDROID_NDK_HOME)) {
        $userNdk = [Environment]::GetEnvironmentVariable("ANDROID_NDK_HOME", "User")
        if (-not [string]::IsNullOrEmpty($userNdk)) { $env:ANDROID_NDK_HOME = $userNdk }
    }
    if ([string]::IsNullOrEmpty($env:ANDROID_NDK_HOME)) {
        $androidSkip = "ANDROID_NDK_HOME not set"
    } else {
        & cargo ndk --version 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { $androidSkip = "cargo-ndk not installed" }
    }
    if ($null -eq $androidSkip) {
        $androidOk = Run-Check -Name $androidName -ArgList @(
            "ndk", "-t", "arm64-v8a", "-t", "x86_64", "-P", "26",
            "clippy", "-p", "directdesk-android", "--lib", "--", "-D", "warnings")
        if (-not $androidOk) { $overallPass = $false }
    } else {
        Write-Host ""
        Write-Host "SKIP: android cross-check ($androidSkip)" -ForegroundColor Yellow
        [void]$results.Add([PSCustomObject]@{ Name = "android cross-check ($androidSkip)"; Pass = $false; Skip = $true })
    }

    Write-Host ""
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "DirectDesk check.ps1 summary" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan

    foreach ($r in $results) {
        # A SKIP is neither PASS nor FAIL: shown, never counted.
        if ($r.PSObject.Properties["Skip"] -and $r.Skip) {
            Write-Host ("  SKIP  " + $r.Name) -ForegroundColor Yellow
        } elseif ($r.Pass) {
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
