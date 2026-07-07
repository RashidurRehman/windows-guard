//! The self-healing monitor: polls each protected app and re-applies protection
//! whenever a window is found unprotected (e.g. the app was closed and reopened).

use crate::config::Method;
use crate::winapi::{self, CaptureStatus};
use crate::{first_line, push_log, AppState, TargetStatus};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        // Rate-limit re-apply attempts and de-dupe repeated log lines per app.
        let mut last_attempt: HashMap<String, Instant> = HashMap::new();
        let mut last_msg: HashMap<String, String> = HashMap::new();

        loop {
            let (interval, master, targets, engine) = {
                let st = app.state::<AppState>();
                let cfg = st.config.lock().unwrap();
                (
                    cfg.interval_secs.max(1),
                    cfg.master_enabled,
                    cfg.targets.clone(),
                    st.engine.clone(),
                )
            };

            let mut statuses: Vec<TargetStatus> = Vec::with_capacity(targets.len());
            let mut alive: HashSet<u32> = HashSet::new();

            for t in &targets {
                let before = winapi::probe(&t.process, &t.class, &t.title, t.all_windows);
                let active = master && t.enabled;
                let mut after = before;

                // Track live pids of every target so we can prune hooks for apps
                // that have since closed.
                for pid in winapi::pids_for_process(&t.process) {
                    alive.insert(pid);
                }

                if active && before.status != CaptureStatus::NotRunning {
                    // Re-affirm protection via the signed helper DLL. This hooks any
                    // instance the event watcher missed (e.g. a launch during the
                    // app's startup burst) and re-applies exclusion to every window
                    // — main, floating widgets, owned dialogs/popups/modals. For
                    // Electron apps it also keeps native OS dialogs covered.
                    crate::hook::protect_target(&t.process);

                    // Electron: re-run the self-patch (for persistence) only when the
                    // main window is unprotected — e.g. after a Cursor update wiped it.
                    let needs_fix = matches!(
                        before.status,
                        CaptureStatus::Unprotected | CaptureStatus::Partial
                    );
                    if needs_fix {
                        // Give the DLL a moment to apply before re-reading status.
                        std::thread::sleep(Duration::from_millis(250));
                    }
                    after = winapi::probe(&t.process, &t.class, &t.title, t.all_windows);
                    if t.method == Method::ElectronPatch && needs_fix {
                        let go = last_attempt
                            .get(&t.id)
                            .map_or(true, |i| i.elapsed() >= Duration::from_secs(60));
                        if go {
                            last_attempt.insert(t.id.clone(), Instant::now());
                            if let Err(e) = engine.apply(t) {
                                let msg = format!("{}: {}", t.name, first_line(&e));
                                log_once(&app, &mut last_msg, &t.id, "warn", &msg);
                            }
                        }
                    }

                    // Log only when the main window went unprotected -> protected.
                    if needs_fix {
                        let msg = format!(
                            "Re-protected {} ({} window{})",
                            t.name,
                            after.windows_protected,
                            if after.windows_protected == 1 { "" } else { "s" }
                        );
                        log_once(&app, &mut last_msg, &t.id, "info", &msg);
                    } else {
                        last_msg.remove(&t.id);
                    }
                }

                statuses.push(TargetStatus {
                    id: t.id.clone(),
                    status: after.status,
                    windows_total: after.windows_total,
                    windows_protected: after.windows_protected,
                });
            }

            // Release hook bookkeeping for any target process that has exited.
            crate::hook::prune_dead(alive);

            let _ = app.emit("status-update", &statuses);
            let _ = app.emit(
                "system-status",
                serde_json::json!({ "fullscreen_active": winapi::exclusive_fullscreen_active() }),
            );
            std::thread::sleep(Duration::from_secs(interval));
        }
    });
}

fn log_once(
    app: &AppHandle,
    last_msg: &mut HashMap<String, String>,
    id: &str,
    level: &str,
    msg: &str,
) {
    if last_msg.get(id).map(|s| s.as_str()) != Some(msg) {
        push_log(app, level, msg);
        last_msg.insert(id.to_string(), msg.to_string());
    }
}
