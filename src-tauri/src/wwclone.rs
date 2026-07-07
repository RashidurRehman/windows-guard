//! Watches WebWorkTracker's own local screenshot folder and instantly copies
//! any new screenshot into our own data directory, before WebWork can delete
//! it after upload.
//!
//! WebWorkTracker writes each screenshot to
//! `%LOCALAPPDATA%\Temp\WebWorkTracker\screenshots\<accountId>\<file>.jpg`,
//! then uploads and deletes it. Rather than guess from a RAM spike (too noisy
//! for this specific tracker — see `syncmon.rs`), we watch that folder
//! directly via `ReadDirectoryChangesW` (through the `notify` crate) and clone
//! the file the instant it's created — an exact, non-heuristic capture.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::AppHandle;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::AppState;
use tauri::Manager;

fn source_dir() -> Option<PathBuf> {
    let base = std::env::var("LOCALAPPDATA").ok()?;
    Some(Path::new(&base).join("Temp").join("WebWorkTracker").join("screenshots"))
}

/// Only accept `<srcRoot>/<accountId>/<file>.jpg|.jpeg` (depth 2) — excludes
/// WebWork's own `frames/`, `tempScreenshots/`, etc.
fn is_watched_file(src_root: &Path, full: &Path) -> bool {
    let Ok(rel) = full.strip_prefix(src_root) else {
        return false;
    };
    let parts: Vec<_> = rel.components().collect();
    if parts.len() != 2 {
        return false;
    }
    let low = full.to_string_lossy().to_ascii_lowercase();
    low.ends_with(".jpg") || low.ends_with(".jpeg")
}

/// Poll the file size until it stops changing (WebWork may still be flushing
/// it when the create event fires), max ~600ms, then confirm it's non-empty.
fn wait_for_stable_size(p: &Path, max_wait: Duration) -> bool {
    let deadline = std::time::Instant::now() + max_wait;
    let mut last: i64 = -1;
    while std::time::Instant::now() < deadline {
        let Ok(meta) = std::fs::metadata(p) else {
            return false;
        };
        let size = meta.len() as i64;
        if size > 0 && size == last {
            return true;
        }
        last = size;
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false)
}

fn clone_file(app: &AppHandle, src: &Path, dst_dir: &Path) {
    if !wait_for_stable_size(src, Duration::from_millis(600)) {
        return;
    }
    let now = std::time::SystemTime::now();
    let stamp = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dst = dst_dir.join(format!("shot_{stamp}.jpg"));
    if std::fs::copy(src, &dst).is_err() {
        let _ = std::fs::remove_file(&dst);
        return;
    }
    crate::syncmon::record_external_event(app, "WebWorkTracker", 0);
}

fn run_watcher(app: &AppHandle, src_root: &Path, dst_dir: &Path) {
    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(_) => return,
    };
    if watcher.watch(src_root, RecursiveMode::Recursive).is_err() {
        return;
    }

    for res in rx {
        let Ok(event) = res else { continue };
        if !matches!(event.kind, EventKind::Create(_)) {
            continue;
        }
        for path in event.paths {
            if path.is_dir() || !is_watched_file(src_root, &path) {
                continue;
            }
            let app2 = app.clone();
            let dst = dst_dir.to_path_buf();
            std::thread::spawn(move || clone_file(&app2, &path, &dst));
        }
        // Bail out if the enclosing feature got disabled mid-watch, so the
        // outer retry loop can pick up config changes without a restart.
        if !enabled(app) {
            return;
        }
    }
}

fn enabled(app: &AppHandle) -> bool {
    app.state::<AppState>().config.lock().unwrap().sync_monitor.enabled
}

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        let Some(src_root) = source_dir() else { return };
        let dst_dir = app.state::<AppState>().config_dir.join("webwork-clones");
        let _ = std::fs::create_dir_all(&dst_dir);

        loop {
            if enabled(&app) && src_root.exists() {
                run_watcher(&app, &src_root, &dst_dir);
            }
            std::thread::sleep(Duration::from_secs(30));
        }
    });
}
