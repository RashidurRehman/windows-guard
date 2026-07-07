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
use tauri::{AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::AppState;

const BADGE_SIZE: f64 = 28.0;
const POLL_MS: u64 = 1000;

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
        .build()
        .ok()
}

fn status_str(s: crate::winapi::CaptureStatus) -> &'static str {
    match s {
        crate::winapi::CaptureStatus::Protected => "protected",
        crate::winapi::CaptureStatus::Partial => "partial",
        crate::winapi::CaptureStatus::Unprotected => "unprotected",
        crate::winapi::CaptureStatus::NotRunning => "not-running",
    }
}

/// One supervisor tick: show/reposition/hide a badge per target with
/// `show_icon` on, and close badges for targets that no longer want one.
fn tick(app: &AppHandle, live: &mut HashMap<String, ()>) {
    let targets = {
        let st = app.state::<AppState>();
        let targets = st.config.lock().unwrap().targets.clone();
        targets
    };

    let mut wanted: HashMap<String, ()> = HashMap::new();
    for t in targets.iter().filter(|t| t.show_icon) {
        wanted.insert(t.id.clone(), ());
        let wins = crate::winapi::matched_windows(&t.process, &t.class, &t.title, t.all_windows);
        let Some(target_win) = wins.first() else {
            if let Some(w) = app.get_webview_window(&label_for(&t.id)) {
                let _ = w.hide();
            }
            continue;
        };
        let Some((_, top, right, _)) = crate::winapi::window_rect(target_win.hwnd) else {
            continue;
        };
        let Some(w) = ensure_window(app, &t.id) else { continue };
        let _ = w.set_size(LogicalSize::new(BADGE_SIZE, BADGE_SIZE));
        let _ = w.set_position(LogicalPosition::new((right - BADGE_SIZE as i32 - 10) as f64, (top + 10) as f64));
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
}

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        let mut live: HashMap<String, ()> = HashMap::new();
        loop {
            tick(&app, &mut live);
            std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
        }
    });
}
