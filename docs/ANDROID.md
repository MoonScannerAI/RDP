# DirectDesk on Android

## What it is

The Windows DirectDesk client's egui app, running on Android as an
`eframe` NativeActivity (`android/` crate, `directdesk-android`; no Java or
Kotlin, `hasCode="false"`). It uses the **Touch** UI profile (`UiProfile::Touch`)
instead of the desktop one. The host is unchanged and the protocol is identical:
an Android client is just another paired client.

v1 scope:

- Video, touch control, and an on-screen keyboard.
- No audio, no lossless tiles, primary monitor only. The client declines these
  in its `Hello` through `StreamCaps::touch_device()`: `system_audio`,
  `lossless_tiles` and `multi_monitor` are off, and the fps preference is 30
  (battery and hardware decoder).
- Video is decoded with the phone's hardware `MediaCodec` (H.264).

## Building

### Prerequisites

| Need | Version / detail |
|---|---|
| JDK | 17 (`JAVA_HOME`) |
| Android SDK | cmdline-tools with `platform-tools`, `platforms;android-34`, `build-tools;34.0.0` (`ANDROID_HOME`) |
| NDK | r27c, `27.2.12479018` (`ANDROID_NDK_HOME`) |
| Rust targets | `aarch64-linux-android`, `x86_64-linux-android` (the script runs `rustup target add`) |
| cargo-ndk | 4.x (`cargo install cargo-ndk`) |

If `JAVA_HOME`, `ANDROID_HOME` or `ANDROID_NDK_HOME` is not set in the current
session, the script reads it from the user environment.

### Build the APK

```powershell
tools\build-android.ps1                  # debug-signed, both ABIs
tools\build-android.ps1 -Abi arm64-v8a   # phone only
tools\build-android.ps1 -Abi x86_64      # emulator only
```

`-Abi` is `arm64-v8a`, `x86_64`, or `all` (default: one APK containing both).
The Rust code is always built with the release profile; "debug" / "release" only
names the signing key. The script exits non-zero on any failure and prints the
APK path, size and SHA-256.

Output: `target\android\DirectDesk-debug.apk` or
`target\android\DirectDesk-release.apk` (under `CARGO_TARGET_DIR` when that is
set).

There is no Gradle. The pipeline is `cargo ndk` -> 16 KB alignment check ->
`aapt2 link` (manifest only) -> `aapt add` of `lib/<abi>/libdirectdesk_android.so`
-> `zipalign` -> `apksigner sign` -> `apksigner verify`.

**16 KB pages.** Android 15+ devices with 16 KB pages refuse a `.so` whose LOAD
segments are aligned to less than 16 KB, and NDK r27 links with 4 KB by default.
The script passes `-z max-page-size=16384` for the Android targets only (the
Windows build is untouched), then fails the build if any LOAD segment of the
built library is aligned to less than `0x4000`.

### Signing

Debug builds are signed with `%USERPROFILE%\.android\directdesk-debug.keystore`,
created on first use (alias `androiddebugkey`, the standard debug password).

**Back this file up.** Android only installs an update over an existing install
if it is signed with the same key. Lose the key and every phone has to uninstall
first, which also forgets its pairing (see Storage and security).

Release builds use your own keystore. The password is never taken on the command
line: put it in an environment variable and pass the variable's *name*.

```powershell
$s = Read-Host -AsSecureString 'keystore password'
$env:DD_KS_PASS = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
tools\build-android.ps1 -Release -Keystore C:\keys\dd.jks `
    -KeystoreAlias directdesk -KeystorePassEnv DD_KS_PASS
Remove-Item env:DD_KS_PASS
```

`-KeyPassEnv` names a separate key-password variable; it defaults to
`-KeystorePassEnv` (PKCS12 keystores use one password for both).

## Checks

`tools\check.ps1` has an Android stage: `cargo ndk -t arm64-v8a -t x86_64 -P 26
clippy -p directdesk-android --lib -- -D warnings`. It runs when
`ANDROID_NDK_HOME` and cargo-ndk are present and counts like any other check.
Otherwise it prints a yellow `SKIP` that is neither PASS nor FAIL and does not
change `OVERALL`.

The Android code is gated with `cfg(target_os = "android")`, and the crate
compiles to an empty library on every other target. The Windows clippy and test
runs therefore never see it; only the Android stage does. Never use
`--all-targets` for Android: the client's dev-dependency on the host crate
(Windows capture/encode) does not build there. Android-only dependencies must
stay under `[target.'cfg(target_os = "android")'.dependencies]` in
`android/Cargo.toml` so their features never unify into the Windows client.

## Installing on a phone

Requirements: an arm64 phone running Android 8.0 or later (`minSdk` 26).

1. Copy `DirectDesk-debug.apk` (or the release APK) to the phone and open it.
2. Allow "Install unknown apps" for the app you opened it from when asked.
3. Play Protect may warn that the app is unrecognised. The APK is not from
   Google Play and is signed with a local key; choose to install anyway.

### Network: Tailscale

The host listens only on Tailscale. The phone needs the Tailscale app, signed
in, with access to the host's machine.

If the host is in someone else's tailnet: that tailnet's admin shares the host
machine to the friend's Tailscale account (admin console, Machines, Share). The
friend accepts the share with his own account. The shared machine keeps its
`100.x` IP; use the IP the Tailscale app shows for it. The full MagicDNS name
works; short names do not.

## Pairing and connecting

1. Someone at the host (or remotely controlling it) clicks **Pair new device**
   in the host UI. The 8-digit code is valid for 5 minutes and single use.
2. On the phone, enter the host's IP and the code. The UDP port is under
   **Advanced** (default 47990).
3. Tap **Pair & Connect**.

Later connects need no code; the host is remembered by its pinned key.

The host serves **one session at a time**. If another client is connected, or a
client vanished without closing (app swiped away mid-session, network drop), the
host reports busy until its 30 s idle timeout.

## Using it

### Gestures (trackpad mode)

| Gesture | Result |
|---|---|
| 1-finger drag | relative cursor move (with speed-based acceleration) |
| Tap | left click at the cursor |
| Two taps in quick succession | two left clicks (host sees a double-click) |
| Tap, touch again, drag | left button down, drag, up on release |
| Tap, touch again, hold 500 ms | left button held, up on release |
| Hold 500 ms, little movement | right click |
| 2-finger tap | right click |
| 2-finger drag | wheel scroll, vertical and horizontal |
| 2-finger pinch | zoom |

Classification does not depend on how long a touch measured, so a tap is still a
tap when the UI is presenting at a few fps.

### Toolbar

A small handle sits at the top centre. Tapping it expands the toolbar, which
hides again 5 s after the last interaction. Buttons: **Keyboard**, **Zoom 1x**
(only while zoomed in), **Diagnostics**, **Disconnect**, **Hide**.

### On-screen keyboard

Emits scan codes directly. Three pages: letters (number row plus QWERTY),
symbols, and function/navigation (Esc, F1-F12, PrtSc, Tab, nav cluster, arrows,
Start). Shift/Ctrl/Alt/Win latch: tap = one-shot (applies to the next key), tap
again = locked, tap again = off. Characters that need Shift add it
automatically. Keys auto-repeat when held. The Android Back button toggles the
keyboard.

### Zoom

Pinch to zoom in; **Zoom 1x** in the toolbar resets to the whole screen.

### Background behaviour

If the app has been in the background for 20 s, a live session is disconnected
cleanly. Returning to the app reconnects automatically, once.

## Storage and security

The client identity and trusted-host pins are stored in `PlainFileStore`, in the
app's `no_backup` directory (`Context.getNoBackupFilesDir()`). That directory is
excluded from both cloud backup and device-to-device transfer, so a pairing is
not cloned to a new phone. `android:allowBackup="false"` is also set.

The files are **plaintext**, protected by the Android app sandbox. They are not
encrypted at rest; wrapping with the Android Keystore is deferred. Compare the
DPAPI storage the Windows client uses in [SECURITY.md](SECURITY.md). Uninstalling
the app deletes the store and forgets the pairing.

## Known limitations and follow-ups

- YUV to RGBA conversion is done on the CPU and uploaded as an RGBA texture. A
  GPU YUV path is a follow-up if phones struggle.
- The emulator's host-GPU mode presents slowly (gfxstream transfer). Test with
  `-gpu swiftshader_indirect`.
- No clipboard, no audio, no in-app log viewer. Use `adb logcat -s DirectDesk`.
- `targetSdk` is 34. Google Play requires 35, so this is sideload only.
- Not yet tested on a physical device; so far verified on the emulator only.

## Testing on the emulator

- AVD: Pixel 6, API 34, x86_64, `google_apis` image. Build with
  `-Abi x86_64`.
- Run headless, e.g. `emulator -avd <name> -no-window -no-audio -no-boot-anim
  -gpu swiftshader_indirect`.
- The emulator reaches the PC's loopback at `10.0.2.2`, so a host running on the
  same PC is at `10.0.2.2` (UDP 47990).
- Install with `adb install -r target\android\DirectDesk-debug.apk`.
- Screenshots from Windows PowerShell 5.1 (its `>` would corrupt binary data, so
  go through `cmd`): `cmd /c "adb exec-out screencap -p > f.png"`.
