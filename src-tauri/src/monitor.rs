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
                // A panic anywhere else in the app poisons this mutex. Unwrapping
                // would kill THIS thread — and a dead monitor is invisible: the UI
                // keeps showing the last statuses it emitted, which were green.
                // Recover the data instead and keep self-healing.
                let cfg = match st.config.lock() {
                    Ok(cfg) => cfg,
                    Err(poisoned) => poisoned.into_inner(),
                };
                (
                    cfg.interval_secs.max(1),
                    cfg.master_enabled,
                    cfg.targets.clone(),
                    st.engine.clone(),
                )
            };

            let mut statuses: Vec<TargetStatus> = Vec::with_capacity(targets.len());
            let mut patch_states: Vec<serde_json::Value> = Vec::with_capacity(targets.len());
            let mut alive: HashSet<u32> = HashSet::new();

            // ONE process-table snapshot for the whole tick. Taking it costs
            // ~9ms, versus ~0.1ms for an EnumWindows pass, and the old code took
            // it up to 12 times per tick (twice per target via probe, once more
            // via pids_for_process) — which is why an idle tray app was burning
            // over 1% CPU continuously.
            let pids = winapi::process_snapshot();

            for t in &targets {
                let before = winapi::probe_in(&t.process, &t.class, &t.title, t.all_windows, &pids);
                let active = master && t.enabled;
                let mut after = before;

                // Track live pids of every target so we can prune hooks for apps
                // that have since closed.
                for pid in winapi::pids_for_process_in(&t.process, &pids) {
                    alive.insert(pid);
                }

                // An electron-patch target's patch can be silently deleted by an
                // app update. Check the marker ON DISK, independently of what the
                // probe reports: a still-running instance keeps reading
                // "Protected" from a patch that no longer exists, so waiting for
                // the probe to report failure means never noticing at all.
                if active && t.method == Method::ElectronPatch {
                    if let Some(false) = crate::actions::electron_patch_present(&t.process) {
                        let go = last_attempt
                            .get(&t.id)
                            .map_or(true, |i| i.elapsed() >= Duration::from_secs(60));
                        if go {
                            last_attempt.insert(t.id.clone(), Instant::now());
                            match engine.apply(t) {
                                Ok(_) => log_once(
                                    &app,
                                    &mut last_msg,
                                    &t.id,
                                    "warn",
                                    &format!(
                                        "{} was updated and lost its protection patch — \
                                         re-applied. Fully quit and relaunch {} to activate.",
                                        t.name, t.name
                                    ),
                                ),
                                Err(e) => log_once(
                                    &app,
                                    &mut last_msg,
                                    &t.id,
                                    "error",
                                    &format!("{}: {}", t.name, first_line(&e)),
                                ),
                            }
                        }
                    }
                }

                // `NoWindows` still means the process is alive, so keep hooking
                // it — its windows may simply be minimized to tray, and a hook
                // placed now covers whatever it opens next.
                if active && before.status != CaptureStatus::NotRunning {
                    // Re-affirm protection via the signed helper DLL. This hooks any
                    // instance the event watcher missed (e.g. a launch during the
                    // app's startup burst) and re-applies exclusion to every window
                    // — main, floating widgets, owned dialogs/popups/modals. For
                    // Electron apps it also keeps native OS dialogs covered.
                    crate::hook::protect_target(&t.process);

                    let needs_fix = matches!(
                        before.status,
                        CaptureStatus::Unprotected | CaptureStatus::Partial
                    );
                    if needs_fix {
                        // Give the DLL a moment to apply, then re-read. Only
                        // re-probe when something actually changed — the old code
                        // paid for a second full probe on every tick.
                        std::thread::sleep(Duration::from_millis(250));
                        after = winapi::probe_in(
                            &t.process,
                            &t.class,
                            &t.title,
                            t.all_windows,
                            &pids,
                        );

                        let msg = format!(
                            "Re-protected {} ({} of {} window{})",
                            t.name,
                            after.windows_protected,
                            after.windows_total,
                            if after.windows_total == 1 { "" } else { "s" }
                        );
                        log_once(&app, &mut last_msg, &t.id, "info", &msg);
                    } else {
                        last_msg.remove(&t.id);
                    }
                }

                // Patch state is emitted alongside (not inside) TargetStatus so
                // this stays within the monitor's own files; `TargetStatus` is
                // shared with other call sites.
                patch_states.push(serde_json::json!({
                    "id": t.id,
                    "patch_state": engine.patch_state(t, after.status),
                }));

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
            let _ = app.emit("patch-state-update", &patch_states);
            let _ = app.emit(
                "system-status",
                serde_json::json!({
                    "fullscreen_active": winapi::exclusive_fullscreen_active(),
                    // Live engine health rides along with every tick so the UI
                    // banner corrects itself without a reload — hooks can start
                    // failing long after startup (a target relaunches elevated).
                    "engine_health": crate::engine_health(),
                }),
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
