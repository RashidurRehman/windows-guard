mod actions;
mod activity;
mod appicon;
mod config;
mod elevate;
mod events;
mod hook;
mod monitor;
mod overlay;
mod privilege;
mod syncmon;
mod synclog;
mod wablur;
mod winapi;
mod wwclone;

use actions::Engine;
use config::{ActivityConfig, Config, Method, SafeKey, SyncConfig, Target};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::{ManagerExt, MacosLauncher};
use tauri_plugin_opener::OpenerExt;

// ---------------------------------------------------------------------------
// Shared state & payloads
// ---------------------------------------------------------------------------

pub struct AppState {
    pub config: Mutex<Config>,
    pub engine: Engine,
    pub config_dir: PathBuf,
    pub log: Mutex<VecDeque<LogEntry>>,
    pub installed_cache: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetStatus {
    pub id: String,
    pub status: winapi::CaptureStatus,
    pub windows_total: usize,
    pub windows_protected: usize,
}

#[derive(Serialize)]
pub struct FullState {
    config: Config,
    statuses: Vec<TargetStatus>,
    autostart_enabled: bool,
    is_elevated: bool,
    elevated_task_installed: bool,
    fullscreen_active: bool,
    log: Vec<LogEntry>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn first_line(s: &str) -> String {
    s.lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .unwrap_or(s)
        .to_string()
}

pub fn push_log(app: &AppHandle, level: &str, message: &str) {
    let entry = LogEntry {
        ts_ms: now_ms(),
        level: level.to_string(),
        message: message.to_string(),
    };
    if let Some(st) = app.try_state::<AppState>() {
        let mut log = st.log.lock().unwrap();
        log.push_back(entry.clone());
        while log.len() > 300 {
            log.pop_front();
        }
    }
    let _ = app.emit("log", &entry);
}

/// Compute live protection status for every configured target (native, cheap).
pub fn snapshot(cfg: &Config) -> Vec<TargetStatus> {
    cfg.targets
        .iter()
        .map(|t| {
            let p = winapi::probe(&t.process, &t.class, &t.title, t.all_windows);
            TargetStatus {
                id: t.id.clone(),
                status: p.status,
                windows_total: p.windows_total,
                windows_protected: p.windows_protected,
            }
        })
        .collect()
}

/// Run apply/remove for a target on a background thread so the UI never blocks
/// on PowerShell, then emit a fresh status snapshot + a log line.
pub(crate) fn engage_target(app: &AppHandle, target: Target, enable: bool) {
    let app = app.clone();
    std::thread::spawn(move || {
        let st = app.state::<AppState>();
        let res = if enable {
            st.engine.apply(&target)
        } else {
            st.engine.remove(&target)
        };
        match res {
            Ok(_) => push_log(
                &app,
                "info",
                &format!(
                    "{} protection {}",
                    target.name,
                    if enable { "turned ON" } else { "turned OFF" }
                ),
            ),
            Err(e) => push_log(&app, "error", &format!("{}: {}", target.name, first_line(&e))),
        }
        let statuses = {
            let cfg = st.config.lock().unwrap();
            snapshot(&cfg)
        };
        let _ = app.emit("status-update", &statuses);
    });
}

fn save_config(app: &AppHandle) {
    let st = app.state::<AppState>();
    let dir = st.config_dir.clone();
    let cfg = st.config.lock().unwrap();
    let _ = cfg.save(&dir);
}

fn slug(name: &str) -> String {
    let base: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed = base.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "app".into()
    } else {
        trimmed
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_state(app: AppHandle) -> FullState {
    let st = app.state::<AppState>();
    let config = st.config.lock().unwrap().clone();
    let statuses = snapshot(&config);
    let log = st.log.lock().unwrap().iter().cloned().collect();
    let autostart_enabled = app.autolaunch().is_enabled().unwrap_or(false);
    FullState {
        config,
        statuses,
        autostart_enabled,
        is_elevated: privilege::is_elevated(),
        elevated_task_installed: elevate::task_installed(),
        fullscreen_active: winapi::exclusive_fullscreen_active(),
        log,
    }
}

#[tauri::command]
fn refresh_now(app: AppHandle) -> Vec<TargetStatus> {
    let st = app.state::<AppState>();
    let cfg = st.config.lock().unwrap();
    let statuses = snapshot(&cfg);
    let _ = app.emit("status-update", &statuses);
    statuses
}

#[tauri::command]
fn set_master(app: AppHandle, enabled: bool) -> Vec<TargetStatus> {
    let targets: Vec<Target> = {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        cfg.master_enabled = enabled;
        cfg.targets.clone()
    };
    save_config(&app);
    push_log(
        &app,
        "info",
        if enabled {
            "Protection resumed"
        } else {
            "Protection paused"
        },
    );
    for t in targets.iter().filter(|t| t.enabled) {
        engage_target(&app, t.clone(), enabled);
    }
    let st = app.state::<AppState>();
    let cfg = st.config.lock().unwrap();
    snapshot(&cfg)
}

#[tauri::command]
fn set_target_enabled(app: AppHandle, id: String, enabled: bool) -> Result<Vec<TargetStatus>, String> {
    let (target, master) = {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        let t = cfg.find_mut(&id).ok_or("unknown app")?;
        t.enabled = enabled;
        (t.clone(), cfg.master_enabled)
    };
    save_config(&app);
    if master {
        engage_target(&app, target, enabled);
    }
    let st = app.state::<AppState>();
    let cfg = st.config.lock().unwrap();
    Ok(snapshot(&cfg))
}

#[tauri::command]
fn set_target_show_icon(app: AppHandle, id: String, show_icon: bool) -> Result<Config, String> {
    let st = app.state::<AppState>();
    let mut cfg = st.config.lock().unwrap();
    let t = cfg.find_mut(&id).ok_or("unknown app")?;
    t.show_icon = show_icon;
    let _ = cfg.save(&st.config_dir);
    Ok(cfg.clone())
}

#[tauri::command]
fn focus_main_window(app: AppHandle) {
    show_main(&app);
}

#[tauri::command]
fn protect_now(app: AppHandle, id: String) -> Result<String, String> {
    let (target, engine) = {
        let st = app.state::<AppState>();
        let cfg = st.config.lock().unwrap();
        let t = cfg.find(&id).ok_or("unknown app")?.clone();
        (t, st.engine.clone())
    };
    let out = engine.apply(&target).map_err(|e| first_line(&e))?;
    push_log(&app, "info", &format!("Manually protected {}", target.name));
    let statuses = {
        let st = app.state::<AppState>();
        let cfg = st.config.lock().unwrap();
        snapshot(&cfg)
    };
    let _ = app.emit("status-update", &statuses);
    Ok(out)
}

#[tauri::command]
fn unprotect_now(app: AppHandle, id: String) -> Result<String, String> {
    let (target, engine) = {
        let st = app.state::<AppState>();
        let cfg = st.config.lock().unwrap();
        let t = cfg.find(&id).ok_or("unknown app")?.clone();
        (t, st.engine.clone())
    };
    let out = engine.remove(&target).map_err(|e| first_line(&e))?;
    push_log(&app, "info", &format!("Manually removed protection from {}", target.name));
    let statuses = {
        let st = app.state::<AppState>();
        let cfg = st.config.lock().unwrap();
        snapshot(&cfg)
    };
    let _ = app.emit("status-update", &statuses);
    Ok(out)
}

#[derive(Deserialize)]
struct NewTarget {
    name: String,
    process: String,
    #[serde(default)]
    class: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    all_windows: bool,
    #[serde(default)]
    method: Option<String>,
}

#[tauri::command]
fn add_target(app: AppHandle, target: NewTarget) -> Result<Config, String> {
    let name = target.name.trim().to_string();
    let process = target.process.trim().trim_end_matches(".exe").to_string();
    if name.is_empty() || process.is_empty() {
        return Err("Name and process are required".into());
    }
    let method = match target.method.as_deref() {
        Some("hide-during-capture") => Method::HideDuringCapture,
        Some("electron-patch") => Method::ElectronPatch,
        _ => Method::Inject,
    };

    let st = app.state::<AppState>();
    let mut cfg = st.config.lock().unwrap();
    // unique id
    let mut id = slug(&name);
    let mut n = 2;
    while cfg.targets.iter().any(|t| t.id == id) {
        id = format!("{}-{}", slug(&name), n);
        n += 1;
    }
    cfg.targets.push(Target {
        id,
        name: name.clone(),
        method,
        process,
        class: target.class.trim().to_string(),
        title: target.title.trim().to_string(),
        all_windows: target.all_windows,
        enabled: true,
        builtin: false,
        show_icon: false,
    });
    let _ = cfg.save(&st.config_dir);
    let out = cfg.clone();
    drop(cfg);
    push_log(&app, "info", &format!("Added {}", name));
    Ok(out)
}

#[tauri::command]
fn remove_target(app: AppHandle, id: String) -> Result<Config, String> {
    let (removed, cfg_clone) = {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        let idx = cfg
            .targets
            .iter()
            .position(|t| t.id == id)
            .ok_or("unknown app")?;
        if cfg.targets[idx].builtin {
            return Err("Built-in apps can be disabled but not removed".into());
        }
        let removed = cfg.targets.remove(idx);
        let _ = cfg.save(&st.config_dir);
        (removed, cfg.clone())
    };
    // best-effort remove protection
    engage_target(&app, removed.clone(), false);
    push_log(&app, "info", &format!("Removed {}", removed.name));
    Ok(cfg_clone)
}

#[derive(Deserialize)]
struct Settings {
    interval_secs: Option<u64>,
    start_minimized: Option<bool>,
}

#[tauri::command]
fn update_settings(app: AppHandle, settings: Settings) -> Config {
    let st = app.state::<AppState>();
    let mut cfg = st.config.lock().unwrap();
    if let Some(iv) = settings.interval_secs {
        cfg.interval_secs = iv.clamp(1, 60);
    }
    if let Some(sm) = settings.start_minimized {
        cfg.start_minimized = sm;
    }
    let _ = cfg.save(&st.config_dir);
    cfg.clone()
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let mgr = app.autolaunch();
    if enabled {
        mgr.enable().map_err(|e| e.to_string())?;
    } else {
        mgr.disable().map_err(|e| e.to_string())?;
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        cfg.start_on_login = enabled;
        let _ = cfg.save(&st.config_dir);
    }
    push_log(
        &app,
        "info",
        if enabled {
            "Start on login enabled"
        } else {
            "Start on login disabled"
        },
    );
    Ok(mgr.is_enabled().unwrap_or(enabled))
}

#[tauri::command]
fn detect_app_type(process: String) -> winapi::AppTypeInfo {
    winapi::detect(process.trim().trim_end_matches(".exe"))
}

#[tauri::command]
fn list_installed_apps(app: AppHandle, refresh: bool) -> Result<serde_json::Value, String> {
    let st = app.state::<AppState>();
    if !refresh {
        let cached = st.installed_cache.lock().unwrap().clone();
        if let Some(json) = cached {
            return parse_apps(&json);
        }
    }
    let json = st.engine.list_installed_apps()?;
    *st.installed_cache.lock().unwrap() = Some(json.clone());
    parse_apps(&json)
}

#[tauri::command]
fn get_app_icons(app: AppHandle, processes: Vec<String>) -> Result<serde_json::Value, String> {
    let joined = processes.join(",");
    if joined.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let json = app.state::<AppState>().engine.app_icons(&joined)?;
    serde_json::from_str::<serde_json::Value>(&json).map_err(|e| e.to_string())
}

fn parse_apps(json: &str) -> Result<serde_json::Value, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    Ok(if v.is_array() {
        v
    } else if v.is_null() {
        serde_json::json!([])
    } else {
        serde_json::json!([v])
    })
}

#[tauri::command]
fn set_elevated_mode(app: AppHandle, enabled: bool) -> Result<bool, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if enabled {
        elevate::install_task(&exe)?;
        // Elevated auto-start supersedes the normal (non-elevated) Run entry.
        let _ = app.autolaunch().disable();
    } else {
        elevate::remove_task()?;
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        cfg.elevated_mode = enabled;
        if enabled {
            cfg.start_on_login = false;
        }
        let _ = cfg.save(&st.config_dir);
    }
    push_log(
        &app,
        "info",
        if enabled {
            "Elevated mode enabled (auto-starts elevated at logon)"
        } else {
            "Elevated mode disabled"
        },
    );
    Ok(elevate::task_installed())
}

#[tauri::command]
fn restart_elevated(app: AppHandle) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    elevate::restart_elevated(&exe)?;
    // The elevated instance is starting; step aside. Unhook first — see the
    // note on hook::shutdown().
    hook::shutdown();
    app.exit(0);
    Ok(())
}

/// Called by the frontend right before `update.install()`, which exits this
/// process internally (inside the updater plugin) to let the installer
/// replace the exe. Our own code never gets a chance to run after that
/// happens, so hooks must be cleanly removed here, first — see the note on
/// `hook::shutdown()`.
#[tauri::command]
fn prepare_for_update_install() {
    hook::shutdown();
}

#[tauri::command]
fn set_self_protection(app: AppHandle, enabled: bool) -> Result<bool, String> {
    if let Some(w) = app.get_webview_window("main") {
        w.set_content_protected(enabled).map_err(|e| e.to_string())?;
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        cfg.protect_self = enabled;
        let _ = cfg.save(&st.config_dir);
    }
    push_log(
        &app,
        "info",
        if enabled {
            "Windows Guard self-protection ON"
        } else {
            "Windows Guard self-protection OFF"
        },
    );
    Ok(enabled)
}

#[tauri::command]
fn set_privacy_veil(app: AppHandle, enabled: bool) -> Result<wablur::WaBlurStatus, String> {
    wablur::set_enabled(enabled);
    {
        let st = app.state::<AppState>();
        let mut cfg = st.config.lock().unwrap();
        cfg.privacy_veil = enabled;
        let _ = cfg.save(&st.config_dir);
    }
    push_log(
        &app,
        "info",
        if enabled {
            "WhatsApp privacy blur ON"
        } else {
            "WhatsApp privacy blur OFF"
        },
    );
    Ok(wablur::status())
}

#[tauri::command]
fn get_wablur_status() -> wablur::WaBlurStatus {
    wablur::status()
}

#[derive(Deserialize)]
struct ActivitySettings {
    enabled: Option<bool>,
    idle_threshold_secs: Option<u64>,
    keys_per_burst: Option<u32>,
    press_gap_min_ms: Option<u64>,
    press_gap_max_ms: Option<u64>,
    hold_min_ms: Option<u64>,
    hold_max_ms: Option<u64>,
}

#[tauri::command]
fn get_activity_config(app: AppHandle) -> ActivityConfig {
    app.state::<AppState>().config.lock().unwrap().activity.clone()
}

#[tauri::command]
fn get_activity_status(app: AppHandle) -> activity::ActivityStatus {
    activity::status(&app)
}

#[tauri::command]
fn set_activity_config(app: AppHandle, settings: ActivitySettings) -> ActivityConfig {
    let cfg = {
        let st = app.state::<AppState>();
        let mut c = st.config.lock().unwrap();
        let a = &mut c.activity;
        if let Some(v) = settings.enabled {
            a.enabled = v;
            activity::set_enabled(v);
        }
        if let Some(v) = settings.idle_threshold_secs {
            a.idle_threshold_secs = v.clamp(5, 3600);
        }
        if let Some(v) = settings.keys_per_burst {
            a.keys_per_burst = v.clamp(1, 30);
        }
        if let Some(v) = settings.press_gap_min_ms {
            a.press_gap_min_ms = v.clamp(20, 5000);
        }
        if let Some(v) = settings.press_gap_max_ms {
            a.press_gap_max_ms = v.clamp(20, 5000);
        }
        if let Some(v) = settings.hold_min_ms {
            a.hold_min_ms = v.clamp(10, 1000);
        }
        if let Some(v) = settings.hold_max_ms {
            a.hold_max_ms = v.clamp(10, 1000);
        }
        let _ = c.save(&st.config_dir);
        c.activity.clone()
    };
    push_log(
        &app,
        "info",
        if cfg.enabled {
            "Activity simulator ON"
        } else {
            "Activity simulator OFF"
        },
    );
    cfg
}

#[tauri::command]
fn add_safe_key(app: AppHandle, label: String, vks: Vec<u16>) -> Result<ActivityConfig, String> {
    activity::validate_combo(&vks)?;
    let label = label.trim().to_string();
    if label.is_empty() {
        return Err("Give this key combo a name".into());
    }
    let st = app.state::<AppState>();
    let mut c = st.config.lock().unwrap();
    if c.activity.safe_keys.iter().any(|k| k.label == label) {
        return Err("A key with that name already exists".into());
    }
    c.activity.safe_keys.push(SafeKey { label: label.clone(), vks });
    let _ = c.save(&st.config_dir);
    let cfg = c.activity.clone();
    drop(c);
    push_log(&app, "info", &format!("Added safe key \"{label}\""));
    Ok(cfg)
}

#[tauri::command]
fn remove_safe_key(app: AppHandle, label: String) -> ActivityConfig {
    let st = app.state::<AppState>();
    let mut c = st.config.lock().unwrap();
    c.activity.safe_keys.retain(|k| k.label != label);
    let _ = c.save(&st.config_dir);
    c.activity.clone()
}

#[derive(Deserialize)]
struct SyncSettings {
    enabled: Option<bool>,
    spike_threshold_kb: Option<u32>,
    poll_interval_secs: Option<u64>,
    cooldown_secs: Option<u64>,
    quiet_from: Option<String>,
    quiet_to: Option<String>,
    log_max_mb: Option<u32>,
}

#[tauri::command]
fn get_sync_config(app: AppHandle) -> SyncConfig {
    app.state::<AppState>().config.lock().unwrap().sync_monitor.clone()
}

#[tauri::command]
fn get_sync_status(app: AppHandle) -> syncmon::SyncStatus {
    syncmon::status(&app)
}

#[tauri::command]
fn set_sync_config(app: AppHandle, settings: SyncSettings) -> SyncConfig {
    let cfg = {
        let st = app.state::<AppState>();
        let mut c = st.config.lock().unwrap();
        let s = &mut c.sync_monitor;
        if let Some(v) = settings.enabled {
            s.enabled = v;
        }
        if let Some(v) = settings.spike_threshold_kb {
            s.spike_threshold_kb = v.clamp(10, 100_000);
        }
        if let Some(v) = settings.poll_interval_secs {
            s.poll_interval_secs = v.clamp(1, 300);
        }
        if let Some(v) = settings.cooldown_secs {
            s.cooldown_secs = v.clamp(0, 3600);
        }
        if let Some(v) = settings.quiet_from {
            s.quiet_from = v;
        }
        if let Some(v) = settings.quiet_to {
            s.quiet_to = v;
        }
        if let Some(v) = settings.log_max_mb {
            s.log_max_mb = v.clamp(1, 2000);
        }
        let _ = c.save(&st.config_dir);
        c.sync_monitor.clone()
    };
    push_log(
        &app,
        "info",
        if cfg.enabled {
            "Sync Monitor ON"
        } else {
            "Sync Monitor OFF"
        },
    );
    cfg
}

#[tauri::command]
fn add_sync_tracker(app: AppHandle, name: String) -> Result<SyncConfig, String> {
    let name = name.trim().trim_end_matches(".exe").to_string();
    if name.is_empty() {
        return Err("Enter a process name".into());
    }
    let st = app.state::<AppState>();
    let mut c = st.config.lock().unwrap();
    if c.sync_monitor.known_trackers.iter().any(|n| n.eq_ignore_ascii_case(&name))
        || c.sync_monitor.custom_trackers.iter().any(|n| n.eq_ignore_ascii_case(&name))
    {
        return Err("Already tracked".into());
    }
    c.sync_monitor.custom_trackers.push(name.clone());
    let _ = c.save(&st.config_dir);
    let cfg = c.sync_monitor.clone();
    drop(c);
    push_log(&app, "info", &format!("Sync Monitor: now watching \"{name}\""));
    Ok(cfg)
}

#[tauri::command]
fn remove_sync_tracker(app: AppHandle, name: String) -> SyncConfig {
    let st = app.state::<AppState>();
    let mut c = st.config.lock().unwrap();
    c.sync_monitor.custom_trackers.retain(|n| !n.eq_ignore_ascii_case(&name));
    let _ = c.save(&st.config_dir);
    c.sync_monitor.clone()
}

#[tauri::command]
fn set_sync_paused(app: AppHandle, paused: bool) -> syncmon::SyncStatus {
    syncmon::set_paused(paused);
    {
        let st = app.state::<AppState>();
        let mut c = st.config.lock().unwrap();
        c.sync_monitor.paused = paused;
        let _ = c.save(&st.config_dir);
    }
    push_log(
        &app,
        "info",
        if paused {
            "Sync Monitor paused"
        } else {
            "Sync Monitor resumed"
        },
    );
    syncmon::status(&app)
}

#[tauri::command]
fn set_sync_meeting_mode(app: AppHandle, minutes: u64) -> syncmon::SyncStatus {
    syncmon::pause_for(minutes.saturating_mul(60));
    push_log(&app, "info", &format!("Sync Monitor: meeting mode for {minutes} min"));
    syncmon::status(&app)
}

#[tauri::command]
fn get_sync_events(app: AppHandle, limit: Option<usize>) -> Vec<syncmon::SyncEvent> {
    let base = app.state::<AppState>().config_dir.clone();
    let mut all = synclog::load_all(&base);
    if let Some(n) = limit {
        all.truncate(n);
    }
    all
}

#[tauri::command]
fn get_sync_day_index(app: AppHandle) -> Vec<synclog::DaySummary> {
    let base = app.state::<AppState>().config_dir.clone();
    synclog::index(&base)
}

#[tauri::command]
fn get_sync_day_events(app: AppHandle, date: String) -> Vec<syncmon::SyncEvent> {
    let base = app.state::<AppState>().config_dir.clone();
    synclog::load_day(&base, &date)
}

#[tauri::command]
fn wipe_sync_events(app: AppHandle) {
    let base = app.state::<AppState>().config_dir.clone();
    synclog::wipe_all(&base);
    push_log(&app, "info", "Sync Monitor event log wiped");
}

#[tauri::command]
fn open_sync_log_folder(app: AppHandle) {
    let dir = app.state::<AppState>().config_dir.join("sync-logs");
    let _ = std::fs::create_dir_all(&dir);
    let _ = app.opener().open_path(dir.to_string_lossy().to_string(), None::<String>);
}

#[derive(Serialize)]
struct ScreenshotInfo {
    filename: String,
    taken_at_ms: u64,
    data_uri: String,
}

/// The most recent cloned WebWorkTracker screenshots, newest first, as data
/// URIs for a thumbnail grid. Only WebWorkTracker has actual recovered image
/// data — every other tracker is detected via the RAM-spike heuristic only,
/// so there's no captured image to show for those.
#[tauri::command]
fn list_webwork_screenshots(app: AppHandle, limit: Option<usize>) -> Vec<ScreenshotInfo> {
    let dir = app.state::<AppState>().config_dir.join("webwork-clones");
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };

    let mut files: Vec<(std::path::PathBuf, std::time::SystemTime)> = entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jpg"))
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()).map(|t| (e.path(), t)))
        .collect();
    files.sort_by(|a, b| b.1.cmp(&a.1));
    files.truncate(limit.unwrap_or(24));

    files
        .into_iter()
        .filter_map(|(path, modified)| {
            let bytes = std::fs::read(&path).ok()?;
            let taken_at_ms = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Some(ScreenshotInfo {
                filename: path.file_name()?.to_string_lossy().to_string(),
                taken_at_ms,
                data_uri: format!(
                    "data:image/jpeg;base64,{}",
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
                ),
            })
        })
        .collect()
}

#[tauri::command]
fn open_webwork_screenshots_folder(app: AppHandle) {
    let dir = app.state::<AppState>().config_dir.join("webwork-clones");
    let _ = std::fs::create_dir_all(&dir);
    let _ = app.opener().open_path(dir.to_string_lossy().to_string(), None::<String>);
}

#[tauri::command]
fn open_config_folder(app: AppHandle) {
    let dir = app.state::<AppState>().config_dir.clone();
    let _ = app
        .opener()
        .open_path(dir.to_string_lossy().to_string(), None::<String>);
}

// ---------------------------------------------------------------------------
// Tray + window
// ---------------------------------------------------------------------------

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open_i = MenuItem::with_id(app, "open", "Open Windows Guard", true, None::<&str>)?;
    let pause_i = MenuItem::with_id(app, "pause", "Pause / Resume protection", true, None::<&str>)?;
    let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open_i, &pause_i, &sep, &quit_i])?;

    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| tauri::Error::AssetNotFound("window icon".into()))?;

    TrayIconBuilder::with_id("main-tray")
        .icon(icon)
        .tooltip("Windows Guard — capture protection")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "pause" => {
                let enabled = {
                    let st = app.state::<AppState>();
                    let cfg = st.config.lock().unwrap();
                    cfg.master_enabled
                };
                let _ = set_master(app.clone(), !enabled);
            }
            "quit" => {
                hook::shutdown();
                wablur::shutdown();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(&tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .invoke_handler(tauri::generate_handler![
            get_state,
            refresh_now,
            set_master,
            set_target_enabled,
            set_target_show_icon,
            focus_main_window,
            prepare_for_update_install,
            protect_now,
            unprotect_now,
            add_target,
            remove_target,
            update_settings,
            set_autostart,
            detect_app_type,
            list_installed_apps,
            get_app_icons,
            set_self_protection,
            set_elevated_mode,
            restart_elevated,
            set_privacy_veil,
            get_wablur_status,
            get_activity_config,
            get_activity_status,
            set_activity_config,
            add_safe_key,
            remove_safe_key,
            get_sync_config,
            get_sync_status,
            set_sync_config,
            add_sync_tracker,
            remove_sync_tracker,
            set_sync_paused,
            set_sync_meeting_mode,
            get_sync_events,
            get_sync_day_index,
            get_sync_day_events,
            list_webwork_screenshots,
            open_webwork_screenshots_folder,
            wipe_sync_events,
            open_sync_log_folder,
            open_config_folder,
        ])
        .setup(|app| {
            let handle = app.handle().clone();

            // Resolve the app config dir; install the engine scripts beside it.
            let config_dir = app
                .path()
                .app_config_dir()
                .expect("no app config dir");
            let engine = Engine::install(&config_dir.join("engine"))
                .expect("failed to install engine scripts");
            let config = Config::load_or_default(&config_dir);

            // Elevated mode means EVERY start of Windows Guard should end up
            // running elevated, not just the one at logon. If we're not
            // currently elevated, hand off to the already-registered logon
            // task right now — Task Scheduler lets an unelevated process
            // trigger a task pre-authorized with highest privileges, with no
            // new UAC prompt — then exit so only the elevated copy survives.
            // Skip silently if the hand-off fails (e.g. task missing); the
            // app just continues unelevated rather than getting stuck.
            if config.elevated_mode && !privilege::is_elevated() && elevate::task_installed() {
                if elevate::run_task_now().is_ok() {
                    std::process::exit(0);
                }
            }

            // Rename migration: clean up any scheduled task from a prior
            // product name, and if elevated mode is on but the (new-name)
            // logon task doesn't exist yet, register it now. Both no-ops
            // unless we're already elevated (e.g. launched by the OLD task at
            // logon), in which case they happen with zero extra UAC prompts.
            elevate::cleanup_retired_tasks();
            if config.elevated_mode && privilege::is_elevated() && !elevate::task_installed() {
                if let Ok(exe) = std::env::current_exe() {
                    let _ = elevate::install_task(&exe);
                }
            }

            // Reconcile autostart with the saved preference.
            let mgr = app.autolaunch();
            if config.start_on_login {
                let _ = mgr.enable();
            }

            let start_minimized =
                config.start_minimized || std::env::args().any(|a| a == "--minimized");
            let protect_self = config.protect_self;
            let privacy_veil = config.privacy_veil;
            let activity_enabled = config.activity.enabled;

            app.manage(AppState {
                config: Mutex::new(config),
                engine,
                config_dir,
                log: Mutex::new(VecDeque::new()),
                installed_cache: Mutex::new(None),
            });

            build_tray(&handle)?;

            // When elevated, enable SeDebugPrivilege for the broadest process reach.
            if privilege::is_elevated() {
                privilege::enable_se_debug();
                push_log(&handle, "info", "Running elevated — SeDebugPrivilege enabled");
            }

            // Bring up the signed hook engine (extracts + trusts the helper DLL,
            // loads it, starts the owner thread). Degrades gracefully if the DLL
            // can't be prepared.
            match hook::init() {
                Ok(()) => push_log(&handle, "info", "Protection engine ready (signed hook DLL)"),
                Err(e) => push_log(&handle, "error", &format!("Protection engine unavailable: {e}")),
            }

            events::spawn(handle.clone()); // instant, event-driven detection
            monitor::spawn(handle.clone()); // slow safety backstop

            // WhatsApp privacy blur (in-page CDP injection; anti shoulder-surfing).
            wablur::spawn(handle.clone());
            wablur::set_enabled(privacy_veil);

            // Idle-triggered activity simulator (harmless key bursts).
            activity::spawn(handle.clone());
            activity::set_enabled(activity_enabled);

            // Tracker/monitoring-software detector (Sync Monitor port).
            syncmon::spawn(handle.clone());
            wwclone::spawn(handle.clone()); // exact WebWorkTracker screenshot clone

            // Per-app defender status badges (floating icon on protected apps).
            appicon::spawn(handle.clone());

            push_log(&handle, "info", "Windows Guard started");

            // Exclude our own window from capture (we own it — direct, no injection).
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_content_protected(protect_self);
                if start_minimized {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides to tray so protection keeps running.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
