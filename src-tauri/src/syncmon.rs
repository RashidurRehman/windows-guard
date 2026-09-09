//! Tracker/monitoring-software detector (ported from the standalone Sync
//! Monitor app).
//!
//! Employee-monitoring tools (WebWorkTracker, Hubstaff, TimeDoctor, ...) take
//! screenshots silently in the background. This module watches for known
//! tracker processes and, once one is running, watches its RSS for a sudden
//! jump — a screenshot capture allocates and compresses an image buffer, which
//! shows up as a short-lived memory spike well above idle noise. When a spike
//! crosses the configured threshold we treat it as "a screenshot was just
//! taken" and surface it (event log + optional blink alert), so the user
//! knows they're being watched right as it happens.
//!
//! WebWorkTracker specifically is excluded from the RAM-spike check: its
//! spikes are too noisy to threshold reliably, so it's covered instead by a
//! dedicated file-watcher on its own screenshot folder (see `wwclone.rs`),
//! which is exact rather than heuristic.

use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

use windows::Win32::Foundation::{BOOL, CloseHandle};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ};

use crate::config::SyncConfig;
use crate::AppState;

static PAUSED_OVERRIDE: AtomicBool = AtomicBool::new(false);
/// Epoch-ms when a timed pause ("meeting mode") lifts; 0 = not timed-paused.
static PAUSED_UNTIL_MS: AtomicU64 = AtomicU64::new(0);

static LAST_MEM_KB: AtomicU64 = AtomicU64::new(0);
static LAST_EVENT_MS: AtomicU64 = AtomicU64::new(0);
static LAST_POLL_MS: AtomicU64 = AtomicU64::new(0);
static TRACKER_PID: AtomicU64 = AtomicU64::new(0);
static TODAY_COUNT: AtomicU64 = AtomicU64::new(0);
static TODAY_KEY: Mutex<String> = Mutex::new(String::new());
static TRACKER_NAME: Mutex<String> = Mutex::new(String::new());

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SyncEvent {
    pub datetime: String,
    pub date: String,
    pub time: String,
    pub spike_kb: u64,
    pub source: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub enabled: bool,
    pub running: bool,
    pub paused: bool,
    pub paused_until_ms: u64,
    pub tracker_name: String,
    pub tracker_pid: u32,
    pub last_poll_ms: u64,
    pub last_event_ms: u64,
    pub today_count: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn config_snapshot(app: &AppHandle) -> SyncConfig {
    { let st = app.state::<AppState>(); let g = st.config.lock().unwrap_or_else(|e| e.into_inner()); g.sync_monitor.clone() }
}

/// Manually pause/resume (independent of any timed meeting-mode pause).
pub fn set_paused(paused: bool) {
    PAUSED_OVERRIDE.store(paused, Ordering::Relaxed);
    if !paused {
        PAUSED_UNTIL_MS.store(0, Ordering::Relaxed);
    }
}

/// Pause for the next `secs` seconds ("meeting mode"); auto-resumes after.
pub fn pause_for(secs: u64) {
    PAUSED_OVERRIDE.store(true, Ordering::Relaxed);
    PAUSED_UNTIL_MS.store(now_ms() + secs.saturating_mul(1000), Ordering::Relaxed);
}

fn is_paused() -> bool {
    let until = PAUSED_UNTIL_MS.load(Ordering::Relaxed);
    if until != 0 && now_ms() >= until {
        PAUSED_OVERRIDE.store(false, Ordering::Relaxed);
        PAUSED_UNTIL_MS.store(0, Ordering::Relaxed);
        return false;
    }
    PAUSED_OVERRIDE.load(Ordering::Relaxed)
}

/// Register a sync event detected by an external producer (the WebWorkTracker
/// file-watcher) that bypasses the RAM-spike check entirely.
pub fn record_external_event(app: &AppHandle, source: &str, pid: u32) {
    let cfg = config_snapshot(app);
    let quiet = in_quiet_hours(now_ms(), &cfg.quiet_from, &cfg.quiet_to);
    emit_event(app, 0, source, pid, quiet);
}

fn day_key(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86400);
    // Simple proleptic Gregorian civil-from-days (Howard Hinnant's algorithm),
    // good enough for a display-only date key — avoids adding a chrono dep.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn clock(ms: u64) -> String {
    let secs = (ms / 1000) % 86400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
}

fn emit_event(app: &AppHandle, spike_kb: u64, source: &str, pid: u32, quiet: bool) {
    let now = now_ms();
    LAST_EVENT_MS.store(now, Ordering::Relaxed);
    let date = day_key(now);
    {
        let mut key = TODAY_KEY.lock().unwrap_or_else(|e| e.into_inner());
        if *key != date {
            *key = date.clone();
            TODAY_COUNT.store(0, Ordering::Relaxed);
        }
    }
    TODAY_COUNT.fetch_add(1, Ordering::Relaxed);

    let evt = SyncEvent {
        datetime: format!("{date} {}", clock(now)),
        date,
        time: clock(now),
        spike_kb,
        source: source.to_string(),
        pid,
    };
    crate::push_log(
        app,
        "warn",
        &format!("Possible screenshot detected: {} (pid {})", source, pid),
    );
    let base = app.state::<AppState>().config_dir.clone();
    crate::synclog::append(&base, &evt);
    let _ = app.emit("sync-event", &evt);
    if !quiet {
        crate::overlay::trigger(app);
    }
}

fn in_quiet_hours(now: u64, from: &str, to: &str) -> bool {
    if from.is_empty() || to.is_empty() {
        return false;
    }
    let parse = |s: &str| -> Option<(u32, u32)> {
        let (h, m) = s.split_once(':')?;
        Some((h.parse().ok()?, m.parse().ok()?))
    };
    let (Some((fh, fm)), Some((th, tm))) = (parse(from), parse(to)) else {
        return false;
    };
    let now_min = ((now / 1000 / 60) % 1440) as u32;
    let from_min = fh * 60 + fm;
    let to_min = th * 60 + tm;
    if from_min <= to_min {
        now_min >= from_min && now_min < to_min
    } else {
        now_min >= from_min || now_min < to_min
    }
}

fn rss_kb(pid: u32) -> Option<u64> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, BOOL(0), pid).ok()?;
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        let ok = GetProcessMemoryInfo(h, &mut counters, counters.cb).is_ok();
        let _ = CloseHandle(h);
        if ok {
            Some(counters.WorkingSetSize as u64 / 1024)
        } else {
            None
        }
    }
}

fn tick(app: &AppHandle, cfg: &SyncConfig) {
    let mut names: Vec<String> = cfg.known_trackers.clone();
    names.extend(cfg.custom_trackers.iter().cloned());

    let found = crate::winapi::find_any_process(&names);
    let Some((name, pid)) = found else {
        *TRACKER_NAME.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
        TRACKER_PID.store(0, Ordering::Relaxed);
        LAST_MEM_KB.store(0, Ordering::Relaxed);
        return;
    };
    *TRACKER_NAME.lock().unwrap_or_else(|e| e.into_inner()) = name.clone();
    TRACKER_PID.store(pid as u64, Ordering::Relaxed);

    // WebWorkTracker's screenshots are caught exactly by the file-watcher
    // instead — RAM-spike thresholding on it is too noisy to be useful.
    if name.eq_ignore_ascii_case("WebWorkTracker") {
        LAST_MEM_KB.store(0, Ordering::Relaxed);
        return;
    }

    let Some(current) = rss_kb(pid) else { return };
    let last = LAST_MEM_KB.load(Ordering::Relaxed);
    LAST_MEM_KB.store(current, Ordering::Relaxed);
    if last == 0 {
        return; // first sample after tracker appeared — nothing to diff against yet
    }

    let diff_kb = current.saturating_sub(last);
    if diff_kb <= cfg.spike_threshold_kb as u64 {
        return;
    }

    let now = now_ms();
    let last_evt = LAST_EVENT_MS.load(Ordering::Relaxed);
    if last_evt != 0 && now.saturating_sub(last_evt) < cfg.cooldown_secs.saturating_mul(1000) {
        return;
    }
    // Quiet hours: still logged for the record, but no blink/toast alert.
    let quiet = in_quiet_hours(now, &cfg.quiet_from, &cfg.quiet_to);
    emit_event(app, diff_kb, &name, pid, quiet);
}

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || loop {
        let cfg = config_snapshot(&app);
        let paused = is_paused() || cfg.paused;
        LAST_POLL_MS.store(now_ms(), Ordering::Relaxed);

        let base = app.state::<AppState>().config_dir.clone();
        crate::synclog::maybe_prune_daily(&base, &day_key(now_ms()), cfg.log_retention_days, cfg.log_max_mb);

        if !cfg.enabled {
            std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs.max(1)));
            continue;
        }

        if paused {
            *TRACKER_NAME.lock().unwrap_or_else(|e| e.into_inner()) = String::new();
            TRACKER_PID.store(0, Ordering::Relaxed);
            LAST_MEM_KB.store(0, Ordering::Relaxed);
        } else {
            tick(&app, &cfg);
        }

        let _ = app.emit("sync-status", &status(&app));
        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs.max(1)));
    });
}

pub fn status(app: &AppHandle) -> SyncStatus {
    let cfg = config_snapshot(app);
    SyncStatus {
        enabled: cfg.enabled,
        running: cfg.enabled,
        paused: is_paused() || cfg.paused,
        paused_until_ms: PAUSED_UNTIL_MS.load(Ordering::Relaxed),
        tracker_name: TRACKER_NAME.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        tracker_pid: TRACKER_PID.load(Ordering::Relaxed) as u32,
        last_poll_ms: LAST_POLL_MS.load(Ordering::Relaxed),
        last_event_ms: LAST_EVENT_MS.load(Ordering::Relaxed),
        today_count: TODAY_COUNT.load(Ordering::Relaxed),
    }
}
