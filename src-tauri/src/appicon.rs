//! Per-app "defender" status badge: a small floating, click-through-free,
//! always-on-top icon docked to the top-right corner of a protected app's own
//! window, showing live protection status at a glance. Click brings Windows
//! Guard's main window to front.
//!
//! Unlike the WhatsApp privacy-blur panel (`wablur.rs`), this does NOT inject
//! into the target app's own UI — most protected apps (Brave's own chrome,
//! WebWork's native Qt UI, Cursor's internal DOM) aren't a documented,
//! stable surface to anchor into the way WhatsApp's chat list is. A separate
//! tiny always-on-top window tracking the target's rect is slower to build
//! per-app polish for, but works uniformly for every protected app with zero
//! per-app maintenance.

use serde::Serialize;
use std::collections::HashMap;
use tauri::{AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::AppState;

const BADGE_SIZE: f64 = 28.0;
const POLL_MS: u64 = 1000;
/// Cadence when no target wants a badge — just often enough to notice the user
/// switching one on.
const IDLE_POLL_MS: u64 = 3000;

#[derive(Serialize, Clone)]
struct BadgeStatus {
    status: &'static str,
    label: String,
}

fn label_for(id: &str) -> String {
    format!("guard-badge-{id}")
}

fn ensure_window(app: &AppHandle, id: &str) -> Option<WebviewWindow> {
    let label = label_for(id);
    if let Some(w) = app.get_webview_window(&label) {
        return Some(w);
    }
    WebviewWindowBuilder::new(app, &label, WebviewUrl::App("guard-badge.html".into()))
        .title("")
        .inner_size(BADGE_SIZE, BADGE_SIZE)
        .decorations(false)
        .transparent(true)
        .always_on_top(true)
        .skip_taskbar(true)
        .shadow(false)
        .visible(false)
        .resizable(false)
        .focused(false)
        // The badge is a live readout of WHICH apps are protected and their
        // exact status — precisely what the user is hiding. Leaving it out of
        // the capture exclusion would leak that into the very screenshots this
        // app exists to defend against, so it protects itself unconditionally.
        .content_protected(true)
        .build()
        .ok()
}

fn status_str(s: crate::winapi::CaptureStatus) -> &'static str {
    match s {
        crate::winapi::CaptureStatus::Protected => "protected",
        crate::winapi::CaptureStatus::Partial => "partial",
        crate::winapi::CaptureStatus::Unprotected => "unprotected",
        crate::winapi::CaptureStatus::NotRunning => "not-running",
        // Running but no countable window: either harmlessly tray-minimized or
        // we genuinely cannot see its windows (UIPI/session/renamed exe), which
        // means the user may be exposed. Never render that as protected.
        crate::winapi::CaptureStatus::NoWindows => "unknown",
    }
}

/// One supervisor tick: show/reposition/hide a badge per target with
/// `show_icon` on, and close badges for targets that no longer want one.
/// Returns true if at least one badge is currently wanted, so the supervisor
/// can idle cheaply when the feature is off (the common case).
fn tick(app: &AppHandle, live: &mut HashMap<String, ()>) -> bool {
    let targets = {
        let st = app.state::<AppState>();
        // Recover a poisoned lock rather than unwrapping. This is the badge
        // supervisor's only read of the config, and it runs forever: if some
        // other holder panicked while holding the mutex, unwrapping here would
        // kill this thread for the rest of the session and freeze every badge
        // on its last drawn status — a stale "protected" dot is indistinguishable
        // from a live one.
        let guard = st.config.lock().unwrap_or_else(|e| e.into_inner());
        guard.targets.clone()
    };

    let mut wanted: HashMap<String, ()> = HashMap::new();
    for t in targets.iter().filter(|t| t.show_icon) {
        wanted.insert(t.id.clone(), ());
        let wins = crate::winapi::matched_windows(&t.process, &t.class, &t.title, t.all_windows);
        let Some(target_win) = wins.first() else {
            // Target isn't running: close the badge rather than just hiding it.
            // Hidden windows were never reclaimed, so an app the user opens and
            // closes repeatedly left a webview behind every time.
            if let Some(w) = app.get_webview_window(&label_for(&t.id)) {
                let _ = w.close();
            }
            live.remove(&t.id);
            continue;
        };
        let Some((_, top, right, _)) = crate::winapi::window_rect(target_win.hwnd) else {
            continue;
        };
        let Some(w) = ensure_window(app, &t.id) else { continue };
        let _ = w.set_size(LogicalSize::new(BADGE_SIZE, BADGE_SIZE));
        // `GetWindowRect` reports PHYSICAL pixels, so the offsets derived from it
        // must be physical too. Feeding them to `LogicalPosition` made Tauri scale
        // them a second time, putting the badge progressively further from its
        // window the further right it sat and the higher the display scaling —
        // visible on any scaled or multi-monitor desktop.
        let scale = w.scale_factor().unwrap_or(1.0);
        let inset = ((BADGE_SIZE + 10.0) * scale).round() as i32;
        let margin = (10.0 * scale).round() as i32;
        let _ = w.set_position(PhysicalPosition::new(right - inset, top + margin));
        let _ = w.show();

        let probe = crate::winapi::probe(&t.process, &t.class, &t.title, t.all_windows);
        let _ = w.emit_to(
            &label_for(&t.id),
            "badge-status",
            &BadgeStatus { status: status_str(probe.status), label: t.name.clone() },
        );
    }

    // Close badges whose target lost `show_icon` (or was removed) since last tick.
    live.retain(|id, _| {
        if wanted.contains_key(id) {
            return true;
        }
        if let Some(w) = app.get_webview_window(&label_for(id)) {
            let _ = w.close();
        }
        false
    });
    for id in wanted.keys() {
        live.insert(id.clone(), ());
    }
    !wanted.is_empty()
}

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        let mut live: HashMap<String, ()> = HashMap::new();
        loop {
            // `tick` creates and closes badge webviews, which is a
            // main-thread-only operation on Windows. Calling
            // `WebviewWindowBuilder::build()` straight from this worker parks
            // it on the event loop while the event loop waits on us, and the
            // whole app deadlocks. Marshal the tick over and wait for the
            // answer so the poll cadence below still reflects real state.
            let (tx, rx) = std::sync::mpsc::channel::<(bool, HashMap<String, ()>)>();
            let mut taken = std::mem::take(&mut live);
            let app2 = app.clone();
            if app
                .run_on_main_thread(move || {
                    let active = tick(&app2, &mut taken);
                    // Hand the map back: it tracks which badges exist, so
                    // dropping it here would leak a webview per target.
                    let _ = tx.send((active, taken));
                })
                .is_err()
            {
                // Event loop is gone (app shutting down) - stop the supervisor
                // rather than spinning against a dead handle.
                return;
            }
            let active = match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok((active, returned)) => {
                    live = returned;
                    active
                }
                Err(_) => false,
            };
            // Each tick enumerates windows and probes every badged target. With
            // no badges enabled — the default, and every target's current state —
            // that work is pure waste at 1Hz, so back off hard until the user
            // turns one on. Responsiveness only matters while a badge is visible.
            let wait = if active { POLL_MS } else { IDLE_POLL_MS };
            std::thread::sleep(std::time::Duration::from_millis(wait));
        }
    });
}
