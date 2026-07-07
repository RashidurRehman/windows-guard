//! A tiny, transparent, click-through, always-on-top overlay window that
//! blinks a colored dot at the top of the screen — the visual "you're being
//! watched right now" alert for a detected screenshot (ported from Sync
//! Monitor's native layered-window indicator).
//!
//! Rather than hand-roll a `UpdateLayeredWindow` GDI renderer, this reuses
//! Tauri's own window/webview stack: a second tiny webview (`overlay.html`)
//! does the actual blinking via a CSS transition, and this module only owns
//! positioning, show/hide, and triggering the JS-side animation.

use serde::Serialize;
use std::time::Duration;
use tauri::{
    AppHandle, Emitter, LogicalPosition, LogicalSize, Manager, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder,
};

const OVERLAY_LABEL: &str = "sync-overlay";
const WIN_W: f64 = 160.0;
const WIN_H: f64 = 90.0;
const ON_MS: u64 = 180;
const OFF_MS: u64 = 130;
const BLINK_COUNT: u64 = 3;

#[derive(Serialize, Clone)]
struct BlinkPayload {
    color: String,
    blink_count: u32,
    on_ms: u64,
    off_ms: u64,
}

fn ensure_window(app: &AppHandle) -> Option<WebviewWindow> {
    if let Some(w) = app.get_webview_window(OVERLAY_LABEL) {
        return Some(w);
    }
    WebviewWindowBuilder::new(app, OVERLAY_LABEL, WebviewUrl::App("overlay.html".into()))
        .title("")
        .inner_size(WIN_W, WIN_H)
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

fn position_top_center(app: &AppHandle, w: &WebviewWindow) {
    if let Ok(Some(monitor)) = app.primary_monitor() {
        let size = monitor.size();
        let scale = monitor.scale_factor();
        let screen_w = size.width as f64 / scale;
        let x = ((screen_w - WIN_W) / 2.0).max(0.0);
        let _ = w.set_position(LogicalPosition::new(x, 4.0));
    }
    let _ = w.set_size(LogicalSize::new(WIN_W, WIN_H));
}

/// Trigger a blink alert. Safe to call from any thread; non-blocking.
pub fn trigger(app: &AppHandle) {
    let Some(w) = ensure_window(app) else { return };
    position_top_center(app, &w);
    let _ = w.set_ignore_cursor_events(true);
    let _ = w.show();

    let payload = BlinkPayload {
        color: "#3ddc97".into(),
        blink_count: BLINK_COUNT as u32,
        on_ms: ON_MS,
        off_ms: OFF_MS,
    };
    let _ = w.emit_to(OVERLAY_LABEL, "blink-trigger", &payload);

    let app2 = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(BLINK_COUNT * (ON_MS + OFF_MS) + 150));
        if let Some(w) = app2.get_webview_window(OVERLAY_LABEL) {
            let _ = w.hide();
        }
    });
}
