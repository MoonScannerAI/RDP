//! RDP-style wallpaper blanking: swap the desktop background for solid black
//! while a remote session is active, and restore exactly what was there
//! before when the session ends.
//!
//! A detailed photo wallpaper makes every keyframe large and every mouse or
//! window move over it expensive to encode; a flat black desktop makes
//! keyframes tiny and deltas near-zero, so "show desktop" scenes stop being
//! laggy over the wire. This mirrors what a classic RDP session does to the
//! console it takes over.
//!
//! [`WallpaperGuard`] is the RAII handle: constructing it blanks the desktop
//! (saving the previous state first, best-effort); dropping it restores
//! whatever was actually saved. Every Win32 call here is failure-tolerant —
//! a wallpaper API failing is logged and otherwise ignored, and must never
//! affect the remote session itself.

use windows::Win32::Foundation::COLORREF;
use windows::Win32::Graphics::Gdi::{GetSysColor, SetSysColors, COLOR_BACKGROUND};
use windows::Win32::UI::WindowsAndMessaging::{
    SystemParametersInfoW, SPIF_SENDWININICHANGE, SPIF_UPDATEINIFILE, SPI_GETDESKWALLPAPER,
    SPI_SETDESKWALLPAPER, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};

/// `SPI_GETDESKWALLPAPER`'s documented contract is a buffer of at least
/// `MAX_PATH` wide characters.
const WALLPAPER_BUF_LEN: usize = 260;

/// State captured before blanking, so restore can put back exactly what was
/// there — nothing more, nothing inferred.
#[derive(Debug, Default, Clone)]
struct SavedState {
    /// The wallpaper path at blank time, if it was readable. `Some("")` means
    /// the user genuinely had no picture wallpaper set.
    wallpaper: Option<String>,
    /// The `COLOR_BACKGROUND` system color at blank time, if it was readable.
    background_color: Option<u32>,
}

/// Blanks the desktop to black on construction and restores the saved state
/// on drop. A no-op guard (nothing saved, nothing to restore) when the
/// feature is disabled by config, so callers can always construct one and let
/// `Drop` do the right thing unconditionally.
pub struct WallpaperGuard {
    saved: SavedState,
}

impl WallpaperGuard {
    /// Save the current wallpaper/color, then blank the desktop to black.
    /// When `enabled` is `false` this saves and changes nothing — the
    /// returned guard is an inert placeholder.
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self {
                saved: SavedState::default(),
            };
        }

        let saved = SavedState {
            wallpaper: get_wallpaper(),
            background_color: get_background_color(),
        };

        if saved.wallpaper.is_none() {
            tracing::warn!("wallpaper blank: could not read current wallpaper path");
        }
        if saved.background_color.is_none() {
            tracing::warn!("wallpaper blank: could not read current background color");
        }

        // Blank the color first, then clear the picture: clearing the picture
        // is what reveals the (now black) background color.
        if !set_background_color(0x0000_0000) {
            tracing::warn!("wallpaper blank: SetSysColors(COLOR_BACKGROUND, black) failed");
        }
        if !set_wallpaper("") {
            tracing::warn!("wallpaper blank: clearing SPI_SETDESKWALLPAPER failed");
        } else {
            tracing::info!("wallpaper blanked to black for the remote session");
        }

        Self { saved }
    }
}

impl Drop for WallpaperGuard {
    fn drop(&mut self) {
        // Only restore the parts that were actually saved — a failed save
        // must not overwrite the user's desktop with something we never
        // observed.
        if let Some(path) = &self.saved.wallpaper {
            if !set_wallpaper(path) {
                tracing::warn!("wallpaper restore: SPI_SETDESKWALLPAPER failed");
            }
        }
        if let Some(color) = self.saved.background_color {
            if !set_background_color(color) {
                tracing::warn!("wallpaper restore: SetSysColors(COLOR_BACKGROUND) failed");
            }
        }
        if self.saved.wallpaper.is_some() || self.saved.background_color.is_some() {
            tracing::info!("wallpaper restored after remote session");
        }
    }
}

/// Read the current desktop wallpaper path via `SPI_GETDESKWALLPAPER`.
/// `Some(String::new())` means "no picture wallpaper is set", not failure.
fn get_wallpaper() -> Option<String> {
    let mut buf = [0u16; WALLPAPER_BUF_LEN];
    // SAFETY: `buf` is a valid, writable buffer of `WALLPAPER_BUF_LEN` wide
    // chars, which meets SPI_GETDESKWALLPAPER's documented minimum (MAX_PATH).
    // The API null-terminates within it and never writes past its length.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETDESKWALLPAPER,
            buf.len() as u32,
            Some(buf.as_mut_ptr() as *mut _),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    if ok.is_err() {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// Set the desktop wallpaper path via `SPI_SETDESKWALLPAPER`. An empty string
/// clears the picture (revealing the solid background color).
fn set_wallpaper(path: &str) -> bool {
    let mut wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a NUL-terminated buffer kept alive for the whole
    // call; SPI_SETDESKWALLPAPER reads it synchronously and does not retain
    // the pointer.
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            Some(wide.as_mut_ptr() as *mut _),
            SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE,
        )
    };
    ok.is_ok()
}

/// Read `COLOR_BACKGROUND` (index 1) via `GetSysColor`.
///
/// `GetSysColor` has no failure return distinct from a legitimate `0`
/// (black) — on a normal desktop the call cannot fail, so this always
/// succeeds. Wrapped in `Option` anyway so the guard's "only restore what
/// was saved" rule has something uniform to check.
fn get_background_color() -> Option<u32> {
    // SAFETY: plain FFI reading a scalar system value; no buffers involved.
    Some(unsafe { GetSysColor(COLOR_BACKGROUND) })
}

/// Set `COLOR_BACKGROUND` (index 1) via `SetSysColors`.
///
/// Note: on systems with visual themes/DWM composition active, `SetSysColors`
/// has historically been ignored for most elements, but `COLOR_BACKGROUND`
/// (the raw desktop fill behind the wallpaper) is still honoured, which is
/// exactly the element a cleared wallpaper reveals.
fn set_background_color(rgb: u32) -> bool {
    let elements: [i32; 1] = [COLOR_BACKGROUND.0];
    let values: [COLORREF; 1] = [COLORREF(rgb)];
    // SAFETY: `elements` and `values` each have length 1, matching the
    // `celements` count passed below; SetSysColors reads them synchronously
    // and does not retain the pointers.
    unsafe { SetSysColors(1, elements.as_ptr(), values.as_ptr()) }.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_guard_saves_and_restores_nothing() {
        let saved = SavedState::default();
        assert!(saved.wallpaper.is_none());
        assert!(saved.background_color.is_none());
    }
}
