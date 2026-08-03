//! The notification-area icon, on a thread of its own.
//!
//! # Why not inside eframe
//!
//! `tray-icon` needs a Win32 message loop on the thread that created the icon.
//! winit's loop would do — but only while it is drawing, and the whole point of
//! this window is that it spends most of its life hidden in the tray. Running
//! our own pump means the icon, its tooltip and its menu keep working with no
//! window on screen at all, which is exactly when a user reaches for
//! "Disconnect client".
//!
//! The thread therefore talks to the listener directly (through
//! [`AppShared::send`]) and only asks the UI for things that are genuinely the
//! UI's job: showing and closing the window.

use std::sync::Arc;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIconBuilder, TrayIconEvent};

use super::{icon, AppShared, TrayView};
use crate::net::NetCommand;

/// How long the pump sleeps between drains. Short enough that a right-click
/// feels instant, long enough to be free.
const PUMP_INTERVAL: Duration = Duration::from_millis(25);

/// Start the tray. The returned handle finishes when the app quits.
///
/// Failures are logged and the thread exits: no tray is bad, but a host that
/// refuses to start because the shell is not ready is worse.
pub fn spawn(shared: Arc<AppShared>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("dd-tray".into())
        .spawn(move || {
            if let Err(e) = run(shared) {
                tracing::error!("tray icon unavailable: {e}");
            }
        })
        .expect("spawning the tray thread")
}

struct Items {
    status: MenuItem,
    disconnect: MenuItem,
    pair: MenuItem,
}

fn run(shared: Arc<AppShared>) -> anyhow::Result<()> {
    let menu = Menu::new();
    let status = MenuItem::new("Starting…", false, None);
    let show = MenuItem::new("Show window", true, None);
    let pair = MenuItem::new("Pair new device", true, None);
    let disconnect = MenuItem::new("Disconnect client", false, None);
    let quit = MenuItem::new("Quit DirectDesk", true, None);
    menu.append_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &show,
        &pair,
        &disconnect,
        &PredefinedMenuItem::separator(),
        &quit,
    ])?;

    install_handlers(
        shared.clone(),
        show.id().clone(),
        pair.id().clone(),
        disconnect.id().clone(),
        quit.id().clone(),
    );

    let mut view = shared.tray_view();
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(&view.tooltip)
        .with_icon(icon::tray_icon(view.state)?)
        .build()?;
    tracing::info!("tray icon created ({:?})", view.state);

    let items = Items {
        status,
        disconnect,
        pair,
    };
    apply(&tray, &items, &view);

    while !shared.quit_requested() {
        pump_messages();
        let next = shared.tray_view();
        if next != view {
            view = next;
            apply(&tray, &items, &view);
        }
        std::thread::sleep(PUMP_INTERVAL);
    }

    // Dropping removes the icon. Hiding it first as well makes the shell reject
    // the second removal and print "Error removing system tray icon" on stderr,
    // which looks like a fault and is not one.
    drop(tray);
    tracing::info!("tray icon removed");
    Ok(())
}

/// Push the current view onto the shell.
fn apply(tray: &tray_icon::TrayIcon, items: &Items, view: &TrayView) {
    if let Err(e) = tray.set_tooltip(Some(&view.tooltip)) {
        tracing::debug!("tray tooltip update failed: {e}");
    }
    match icon::tray_icon(view.state) {
        Ok(i) => {
            if let Err(e) = tray.set_icon(Some(i)) {
                tracing::debug!("tray icon update failed: {e}");
            }
        }
        Err(e) => tracing::debug!("tray icon render failed: {e}"),
    }
    items.status.set_text(&view.status_line);
    items.disconnect.set_enabled(view.can_disconnect);
    items
        .pair
        .set_enabled(view.state != super::TrayState::Disabled);
}

fn install_handlers(
    shared: Arc<AppShared>,
    show: MenuId,
    pair: MenuId,
    disconnect: MenuId,
    quit: MenuId,
) {
    let menu_shared = shared.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id == show {
            menu_shared.show_window();
        } else if event.id == pair {
            // Pairing needs the window: the code has to be readable somewhere.
            if menu_shared.send(NetCommand::ArmPairing) {
                menu_shared.show_window();
            } else {
                tracing::warn!("pairing requested while the listener is stopped");
                menu_shared.show_window();
            }
        } else if event.id == disconnect {
            // Deliberately independent of the window: this must work while the
            // host is minimised, which is when it matters most.
            if !menu_shared.send(NetCommand::DisconnectClient) {
                tracing::warn!("disconnect requested while the listener is stopped");
            }
        } else if event.id == quit {
            tracing::info!("quit requested from the tray");
            menu_shared.request_quit();
        }
    }));

    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        // Double-click is the conventional "give me the window back".
        if let TrayIconEvent::DoubleClick { .. } = event {
            shared.show_window();
        }
    }));
}

/// Drain this thread's message queue so the shell's tray notifications reach
/// `tray-icon`'s window procedure.
fn pump_messages() {
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };
    // SAFETY: `msg` is a live, writable MSG for the duration of each call, and
    // these three functions only ever touch this thread's own message queue.
    unsafe {
        let mut msg = MSG::default();
        while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pump_is_safe_to_call_on_a_thread_with_no_windows() {
        // Not a no-op check: it proves the FFI signatures are right and that
        // draining an empty queue terminates instead of blocking.
        pump_messages();
        pump_messages();
    }

    #[test]
    fn pump_interval_keeps_the_menu_responsive() {
        assert!(PUMP_INTERVAL <= Duration::from_millis(50));
    }
}
