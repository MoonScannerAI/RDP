# Building DirectDesk

## Toolchain

DirectDesk targets Windows only (`x86_64-pc-windows-msvc`). The exact
toolchain is pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) at the
repo root:

```toml
[toolchain]
channel = "1.95.0"
components = ["clippy", "rustfmt"]
targets = ["x86_64-pc-windows-msvc"]
```

`rustup` will pick this up automatically the first time you run `cargo` in
this repo — you don't need to `rustup install` manually, but you do need
`rustup` itself installed.

### Requirements

1. **Rust 1.95.0** via [rustup](https://rustup.rs), MSVC host toolchain
   (`x86_64-pc-windows-msvc`, not the GNU one).
2. **Visual Studio Build Tools** — the MSVC linker (`link.exe`) and Windows
   SDK, required for any Windows Rust build with the MSVC toolchain. Install
   via the [Visual Studio Build Tools installer](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio),
   selecting the **"Desktop development with C++"** workload. A full Visual
   Studio IDE install also works but is not required — Build Tools alone is
   enough.
3. Windows 10/11 x64. DirectDesk uses Windows-specific APIs throughout
   (Desktop Duplication, Media Foundation, DPAPI, named pipes, Windows
   services) — there is no cross-platform build target.

### PATH note (PowerShell)

Cargo installs to `%USERPROFILE%\.cargo\bin`, which the rustup installer
normally adds to your permanent user `PATH`. If a fresh shell (or a CI
runner) doesn't see `cargo`/`rustc`, prepend it explicitly for that session:

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"
```

Every script under `tools/` does this itself at the top, so you do not need
to do it manually before running `tools\check.ps1` etc. — it's only needed
if you're invoking `cargo` directly in a shell that hasn't got it on PATH.

## Workspace layout

This is a single Cargo workspace (`Cargo.toml` at the repo root,
`resolver = "2"`) with five members:

```toml
[workspace]
members = ["shared", "host", "client", "service", "tests"]
```

| Crate | Kind | Purpose |
|---|---|---|
| `shared` (`directdesk-shared`) | lib | Wire protocol (`protocol.rs`), stats/route reporting (`stats.rs`), service IPC contract (`svc_ipc.rs`), crypto, transport, video framing, input, adaptive bitrate. This is the compatibility contract every exe depends on — see the crate-level doc comment in `shared/src/lib.rs`. |
| `host` | bin → `DirectDeskHost.exe` | Capture, encode, stream, inject input on the controlled machine. |
| `client` | bin → `DirectDeskClient.exe` | Connect, decode, display, capture input on the controlling machine. |
| `service` | bin → `DirectDeskService.exe` | Windows service exposing the fixed privileged-op menu over `\\.\pipe\DirectDeskSvc`. |
| `tests` | lib (dev-only) | Integration harness driving host/client cores through the deterministic network simulator (`shared::netsim`). |

Workspace-wide dependency versions and profiles live in the root
`Cargo.toml` under `[workspace.dependencies]` / `[profile.*]` — member
crates pull shared deps with `dep = { workspace = true }` rather than
pinning their own versions, so there is one source of truth for e.g. the
`quinn`/`rustls`/`ring` versions.

Release profile (`[profile.release]`): `opt-level = 3`, `lto = "thin"`,
`codegen-units = 1`, `panic = "unwind"`, `strip = "none"` — unwinding is
kept (not aborted) so the panic hook in `shared::logging` can flush a log
line before the process exits, and symbols are left in for post-mortem
debugging since the binaries aren't shipped stripped in this MVP.

## Common commands

Run these from the repo root (`C:\Users\andyl\Desktop\GitHub Apps\rdp` in
this checkout, but any workspace root works).

```powershell
$env:PATH="$env:USERPROFILE\.cargo\bin;$env:PATH"

# Build everything, debug profile
cargo build --workspace

# Build everything, release profile (what the installer packages)
cargo build --workspace --release

# Run all unit + integration tests
cargo test --workspace

# Format check (does not rewrite files)
cargo fmt --check

# Format (rewrites files)
cargo fmt

# Lint, treating warnings as errors — this is what CI/check.ps1 enforces
cargo clippy --workspace -- -D warnings

# Build just one binary
cargo build -p directdesk-host --release
cargo build -p directdesk-client --release
cargo build -p directdesk-service --release
```

Release binaries land in `target\release\DirectDeskHost.exe`,
`target\release\DirectDeskClient.exe`, `target\release\DirectDeskService.exe`
— this is also exactly where `tools\build-installer.ps1` and
`installer\directdesk.iss` expect to find them.

### The all-in-one gate

`tools\check.ps1` runs fmt-check, clippy (`-D warnings`), and
`cargo test --workspace` in sequence and prints a single PASS/FAIL summary
with a matching exit code. Run it before considering any change done:

```powershell
powershell -NoProfile -File tools\check.ps1
```

### A linker gotcha on Windows

If you see `LINK : fatal error LNK1104: cannot open file '...exe'` on a
build/test that otherwise compiled fine, it is almost always a transient
file lock (antivirus scanning the freshly-linked `.exe`, or a previous test
binary still running/held open) rather than a real error — re-run the same
command. Running `cargo build`/`cargo test` from a native PowerShell prompt
rather than through an emulated POSIX shell also avoids some spurious
locking behavior observed with MSYS/Git-Bash wrappers around the MSVC
linker on this toolchain.

## Building the installer

Once you have release binaries, see [`tools/build-installer.ps1`](../tools/build-installer.ps1)
or run it directly — it builds the release binaries and then invokes Inno
Setup 6 (`ISCC.exe`) against [`installer/directdesk.iss`](../installer/directdesk.iss).
Inno Setup itself is a separate, manually-installed tool — see that script's
own header comment for where it looks for `ISCC.exe`.
