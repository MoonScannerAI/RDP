#requires -version 5.1
<#
.SYNOPSIS
    Build the DirectDesk Android APK without Gradle.

.DESCRIPTION
    cargo ndk (release profile, minSdk 26) -> aapt2 link (manifest only) ->
    aapt add lib/<abi>/libdirectdesk_android.so -> zipalign -> apksigner sign
    -> apksigner verify.

    Output: target\android\DirectDesk-debug.apk or DirectDesk-release.apk
    (under CARGO_TARGET_DIR when that is set). The Rust code is always built
    with the release profile; "debug" / "release" only names the signing key.

    Debug builds are signed with %USERPROFILE%\.android\directdesk-debug.keystore,
    created on first use (alias androiddebugkey, the well-known Android debug
    password "android").

    Release builds need your own keystore. Passwords are never taken on the
    command line: put the password in an environment variable and pass the
    variable's NAME, e.g.

        $s = Read-Host -AsSecureString 'keystore password'
        $env:DD_KS_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
        .\tools\build-android.ps1 -Release -Keystore C:\keys\dd.jks `
            -KeystoreAlias directdesk -KeystorePassEnv DD_KS_PASS
        Remove-Item env:DD_KS_PASS

    Requirements: rustup + cargo-ndk, JAVA_HOME (JDK 17), ANDROID_HOME with
    platforms;android-34 and build-tools (34.0.0 preferred), ANDROID_NDK_HOME.
    Missing JAVA_HOME / ANDROID_HOME / ANDROID_NDK_HOME are read from the
    user environment.

    Exits non-zero on any failure.

.PARAMETER Abi
    arm64-v8a, x86_64 (emulator), or all (default: one APK with both).
#>
[CmdletBinding()]
param(
    [ValidateSet('arm64-v8a', 'x86_64', 'all')]
    [string]$Abi = 'all',
    [switch]$Release,
    [string]$Keystore,
    [string]$KeystoreAlias,
    # NAME of the environment variable holding the keystore password.
    [string]$KeystorePassEnv,
    # NAME of the environment variable holding the key password; defaults to
    # KeystorePassEnv (PKCS12 keystores use one password for both).
    [string]$KeyPassEnv
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

$LibName = 'libdirectdesk_android.so'
$MinSdk = 26
$CompileSdk = 34
$PreferredBuildTools = '34.0.0'
$AbiTriples = [ordered]@{
    'arm64-v8a' = 'aarch64-linux-android'
    'x86_64'    = 'x86_64-linux-android'
}

function Fail([string]$Message) {
    throw $Message
}

# Run a native tool, echo its stdout to the console (never into this
# script's pipeline), and fail on a non-zero exit code.
function Invoke-Tool {
    param([string]$What, [string]$Exe, [string[]]$ArgList)
    Write-Host ("    > " + (Split-Path -Leaf $Exe) + " " + ($ArgList -join ' ')) -ForegroundColor DarkGray
    & $Exe @ArgList | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Fail "$What failed (exit code $LASTEXITCODE)"
    }
}

function Step([string]$Text) {
    Write-Host ""
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Use-UserEnv([string]$Name) {
    $cur = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrEmpty($cur)) {
        $user = [Environment]::GetEnvironmentVariable($Name, 'User')
        if (-not [string]::IsNullOrEmpty($user)) {
            [Environment]::SetEnvironmentVariable($Name, $user, 'Process')
        }
    }
    $val = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrEmpty($val) -or -not (Test-Path $val)) {
        Fail "$Name is not set (process or user environment) or does not exist: '$val'"
    }
    return $val
}

Push-Location $RepoRoot
try {
    # ---------------------------------------------------------------- setup
    $env:PATH = "$env:USERPROFILE\.cargo\bin;C:\Program Files\Git\bin;$env:PATH"
    $JavaHome = Use-UserEnv 'JAVA_HOME'
    $AndroidHome = Use-UserEnv 'ANDROID_HOME'
    $null = Use-UserEnv 'ANDROID_NDK_HOME'

    if ($Abi -eq 'all') { $Abis = @($AbiTriples.Keys) } else { $Abis = @($Abi) }
    if ($Release) { $Flavor = 'release' } else { $Flavor = 'debug' }

    $AndroidJar = Join-Path $AndroidHome "platforms\android-$CompileSdk\android.jar"
    if (-not (Test-Path $AndroidJar)) { Fail "missing $AndroidJar (sdkmanager `"platforms;android-$CompileSdk`")" }

    $BuildToolsRoot = Join-Path $AndroidHome 'build-tools'
    $BuildTools = Join-Path $BuildToolsRoot $PreferredBuildTools
    if (-not (Test-Path $BuildTools)) {
        $latest = Get-ChildItem $BuildToolsRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { [version]($_.Name -replace '-.*$', '') } -ErrorAction SilentlyContinue |
            Select-Object -Last 1
        if ($null -eq $latest) { Fail "no Android build-tools under $BuildToolsRoot" }
        $BuildTools = $latest.FullName
        Write-Host "build-tools $PreferredBuildTools not found; using $BuildTools" -ForegroundColor Yellow
    }
    $Aapt2 = Join-Path $BuildTools 'aapt2.exe'
    $Aapt = Join-Path $BuildTools 'aapt.exe'
    $Zipalign = Join-Path $BuildTools 'zipalign.exe'
    $Apksigner = Join-Path $BuildTools 'apksigner.bat'
    $Keytool = Join-Path $JavaHome 'bin\keytool.exe'
    foreach ($t in @($Aapt2, $Aapt, $Zipalign, $Apksigner, $Keytool)) {
        if (-not (Test-Path $t)) { Fail "missing tool: $t" }
    }

    $Manifest = Join-Path $RepoRoot 'android\apk\AndroidManifest.xml'
    if (-not (Test-Path $Manifest)) { Fail "missing $Manifest" }

    if ([string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) {
        $TargetDir = Join-Path $RepoRoot 'target'
    } else {
        $TargetDir = $env:CARGO_TARGET_DIR
    }
    $OutDir = Join-Path $TargetDir 'android'
    $Work = Join-Path $OutDir "work-$Flavor"
    $Stage = Join-Path $Work 'stage'
    $Apk = Join-Path $OutDir "DirectDesk-$Flavor.apk"

    # ------------------------------------------------------------- signing
    # Resolved before the (slow) build so a bad release setup fails fast.
    if ($Release) {
        if ([string]::IsNullOrEmpty($Keystore) -or [string]::IsNullOrEmpty($KeystoreAlias) -or [string]::IsNullOrEmpty($KeystorePassEnv)) {
            Fail "-Release needs -Keystore <path> -KeystoreAlias <alias> -KeystorePassEnv <ENV_VAR_NAME>"
        }
        if (-not (Test-Path $Keystore)) { Fail "keystore not found: $Keystore" }
        if ([string]::IsNullOrEmpty($KeyPassEnv)) { $KeyPassEnv = $KeystorePassEnv }
        foreach ($n in @($KeystorePassEnv, $KeyPassEnv)) {
            if ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($n, 'Process'))) {
                Fail "environment variable '$n' (keystore password) is not set in this session"
            }
        }
        $KsPath = (Resolve-Path $Keystore).Path
        $KsAlias = $KeystoreAlias
        $KsPassVar = $KeystorePassEnv
        $KeyPassVar = $KeyPassEnv
    } else {
        $KsPath = Join-Path $env:USERPROFILE '.android\directdesk-debug.keystore'
        $KsAlias = 'androiddebugkey'
        # The universal Android debug password, passed through the
        # environment like a real one so both paths share one code path.
        $env:DIRECTDESK_DEBUG_KS_PASS = 'android'
        $KsPassVar = 'DIRECTDESK_DEBUG_KS_PASS'
        $KeyPassVar = 'DIRECTDESK_DEBUG_KS_PASS'
        if (-not (Test-Path $KsPath)) {
            Step "Creating debug keystore $KsPath"
            New-Item -ItemType Directory -Force (Split-Path -Parent $KsPath) | Out-Null
            Invoke-Tool 'keytool -genkeypair' $Keytool @(
                '-genkeypair', '-noprompt',
                '-keystore', $KsPath, '-storetype', 'PKCS12',
                '-storepass:env', $KsPassVar, '-keypass:env', $KeyPassVar,
                '-alias', $KsAlias, '-keyalg', 'RSA', '-keysize', '2048',
                '-validity', '10000', '-dname', 'CN=Android Debug,O=Android,C=US')
        }
    }

    # ---------------------------------------------------------------- rust
    Step "Rust targets"
    $triples = @($Abis | ForEach-Object { $AbiTriples[$_] })
    Invoke-Tool 'rustup target add' 'rustup' (@('target', 'add') + $triples)

    Step "cargo ndk build ($($Abis -join ', '), minSdk $MinSdk, release profile)"
    & cargo ndk --version | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail "cargo-ndk is not installed (cargo install cargo-ndk)" }
    $ndkArgs = @('ndk')
    foreach ($a in $Abis) { $ndkArgs += @('-t', $a) }
    $ndkArgs += @('-P', "$MinSdk", 'build', '-p', 'directdesk-android', '--release')
    Invoke-Tool 'cargo ndk build' 'cargo' $ndkArgs

    # ------------------------------------------------------------- package
    Step "Packaging $Apk"
    if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
    New-Item -ItemType Directory -Force $Stage | Out-Null
    $libEntries = @()
    foreach ($a in $Abis) {
        $so = Join-Path $TargetDir "$($AbiTriples[$a])\release\$LibName"
        if (-not (Test-Path $so)) { Fail "build did not produce $so" }
        $dst = Join-Path $Stage "lib\$a"
        New-Item -ItemType Directory -Force $dst | Out-Null
        Copy-Item $so $dst
        $libEntries += "lib/$a/$LibName"
    }

    $BaseApk = Join-Path $Work 'base.apk'
    $AlignedApk = Join-Path $Work 'aligned.apk'
    Invoke-Tool 'aapt2 link' $Aapt2 @('link', '--manifest', $Manifest, '-I', $AndroidJar, '-o', $BaseApk)

    # `aapt add` stores entries under the path exactly as given, so it runs
    # from the staging dir with forward-slash relative paths.
    Push-Location $Stage
    try {
        Invoke-Tool 'aapt add' $Aapt (@('add', $BaseApk) + $libEntries)
    } finally {
        Pop-Location
    }

    Invoke-Tool 'zipalign' $Zipalign @('-p', '-f', '4', $BaseApk, $AlignedApk)

    if (Test-Path $Apk) { Remove-Item -Force $Apk }
    Invoke-Tool 'apksigner sign' $Apksigner @(
        'sign', '--ks', $KsPath, '--ks-key-alias', $KsAlias,
        '--ks-pass', "env:$KsPassVar", '--key-pass', "env:$KeyPassVar",
        '--v4-signing-enabled', 'false',
        '--out', $Apk, $AlignedApk)

    # -------------------------------------------------------------- verify
    Step "Verifying signature"
    Invoke-Tool 'apksigner verify' $Apksigner @('verify', '--verbose', '--print-certs', $Apk)

    $hash = (Get-FileHash -Algorithm SHA256 $Apk).Hash.ToLowerInvariant()
    $size = (Get-Item $Apk).Length
    Write-Host ""
    Write-Host "BUILD OK ($Flavor, $($Abis -join ' + '))" -ForegroundColor Green
    Write-Host "  APK:     $Apk"
    Write-Host ("  Size:    {0:N1} MB" -f ($size / 1MB))
    Write-Host "  SHA-256: $hash"
    exit 0
}
catch {
    Write-Host ""
    Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
