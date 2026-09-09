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

impl AppState {
    /// Lock the config, surviving a poisoned mutex.
    ///
    /// A `Mutex` is poisoned when a thread panics while holding it — and the
    /// command handlers in this file are the likeliest place for that first
    /// panic to happen. With a bare `.unwrap()` every subsequent acquisition
    /// panics on contact, so one unlucky panic would permanently break every
    /// command the user has for reacting to it, while the background threads
    /// (already poison-tolerant) kept emitting the last status they computed:
    /// a frozen green light that nothing can clear.
    ///
    /// The config behind the lock is a plain data struct with no cross-field
    /// invariant that a mid-write panic could tear, so recovering it is safe —
    /// strictly better than refusing to run.
    pub fn cfg(&self) -> std::sync::MutexGuard<'_, Config> {
        self.config.lock().unwrap_or_else(|e| e.into_inner())
    }
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
    engine_health: EngineHealth,
    /// Set when the saved config could not be read normally (corrupt and reset,
    /// or present but unreadable). Silent state loss is exactly what a user must
    /// be told about, and the log pane is a channel they never read.
    config_notice: Option<String>,
    log: Vec<LogEntry>,
}

/// Whether the protection engine can actually protect anything right now.
///
/// This exists because the engine used to fail *silently*: an unelevated
/// instance cannot install its hooks (no SeDebugPrivilege), every
/// `SetWindowsHookExW` returns access-denied, and nothing anywhere said so —
/// the UI reported every target as protected while nothing was. Any state
/// other than `Ready` means the user must be told.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum EngineHealth {
    /// Hook DLL loaded and we have the rights to inject it.
    Ready,
    /// The engine could not start at all — nothing is protected.
    Unavailable { reason: String },
    /// The engine started but cannot protect everything it was asked to
    /// (e.g. running unelevated, so elevated targets refuse the hook).
    Degraded { reason: String },
}

static ENGINE_HEALTH: Mutex<Option<EngineHealth>> = Mutex::new(None);

/// A one-off warning about the config that was loaded at startup (corrupt and
/// reset, or unreadable). Held so `get_state` can surface it in the UI rather
/// than it existing only as a log line that scrolls away unread.
static CONFIG_NOTICE: Mutex<Option<String>> = Mutex::new(None);

/// Record the startup config warning, if there was one.
pub fn set_config_notice(notice: Option<String>) {
    if let Ok(mut slot) = CONFIG_NOTICE.lock() {
        *slot = notice;
    }
}

/// The startup config warning, if any.
pub fn config_notice() -> Option<String> {
    CONFIG_NOTICE.lock().ok().and_then(|s| s.clone())
}

/// Record the engine's health. Called once at startup and again whenever a
/// condition that changes it is observed.
pub fn set_engine_health(h: EngineHealth) {
    if let Ok(mut slot) = ENGINE_HEALTH.lock() {
        *slot = Some(h);
    }
}

/// Current engine health, defaulting to `Unavailable` until startup sets it —
/// never optimistically `Ready`, so a startup that dies before wiring this up
/// cannot present itself as healthy.
///
/// `Unavailable` and `Degraded` are sticky decisions made at startup; on top of
/// those we fold in the hook engine's LIVE view, because targets fail after
/// startup too (an app relaunches elevated, a 32-bit target appears). A stored
/// `Ready` is therefore only reported when nothing is currently failing.
pub fn engine_health() -> EngineHealth {
    let stored = ENGINE_HEALTH
        .lock()
        .ok()
        .and_then(|s| s.clone())
        .unwrap_or(EngineHealth::Unavailable {
            reason: "Protection engine has not started yet.".into(),
        });
    match stored {
        // Already the worst news — nothing to add.
        EngineHealth::Unavailable { .. } | EngineHealth::Degraded { .. } => stored,
        // The engine came up; ask it whether it is actually protecting things.
        // hook::degraded_reason() aggregates per target (a target counts as
        // failed only when NONE of its GUI threads hooked) and its wording
        // distinguishes a privilege problem from a bitness one, so it is passed
        // through verbatim rather than re-worded here.
        EngineHealth::Ready => match hook::degraded_reason() {
            Some(reason) => EngineHealth::Degraded { reason },
            None => EngineHealth::Ready,
        },
    }
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

// THE LOGON-START INVARIANT. Exactly one mechanism may start Windows Guard at
// logon:
//
//   * `elevated_mode` ON  -> the scheduled task owns logon start, and the
//     `HKCU\...\Run` key MUST stay absent.
//   * `elevated_mode` OFF -> the Run key owns logon start, and follows
//     `start_on_login`.
//
// `start_on_login` records the user's INTENT ("start at logon"); which of the
// two mechanisms carries it out is decided solely by `elevated_mode`. Never
// clear the intent when switching mechanism, and never let both mechanisms be
// registered at once.
//
// Why it matters: the Run key always launches an UNELEVATED copy (that hive
// uses the plain user token) and fires at the same instant as the task's logon
// trigger. With both registered they race, and an unelevated instance cannot
// install its hooks — so it runs looking perfectly healthy while protecting
// nothing. That was the app's headline bug: "after a reboot everything is
// captureable". Registering the Run key alongside the task rebuilds it.
//
// Enforced at four places, all of which must agree:
//   1. `resolve_logon_ownership()` — removes the Run key before the builder.
//   2. `setup()`'s autostart reconcile — re-asserts it via the plugin.
//   3. `set_autostart()` — refuses to write the key in elevated mode.
//   4. `set_elevated_mode()` — switches mechanism, preserves intent both ways.

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
            let cfg = st.cfg();
            snapshot(&cfg)
        };
        let _ = app.emit("status-update", &statuses);
    });
}

fn save_config(app: &AppHandle) {
    let st = app.state::<AppState>();
    let dir = st.config_dir.clone();
    let cfg = st.cfg();
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
    let config = st.cfg().clone();
    let statuses = snapshot(&config);
    let log = st.log.lock().unwrap().iter().cloned().collect();
    // In elevated mode the scheduled task starts us at logon and the HKCU\Run
    // key is deliberately absent, so the plugin reports "not enabled" even
    // though start-on-login genuinely is. Trust the saved preference there, or
    // the settings toggle renders itself off on every load.
    let autostart_enabled = if config.elevated_mode {
        config.start_on_login
    } else {
        app.autolaunch().is_enabled().unwrap_or(false)
    };
    FullState {
        config,
        statuses,
        autostart_enabled,
        is_elevated: privilege::is_elevated(),
        elevated_task_installed: elevate::task_installed(),
        fullscreen_active: winapi::exclusive_fullscreen_active(),
        engine_health: engine_health(),
        config_notice: config_notice(),
        log,
    }
}

#[tauri::command]
fn refresh_now(app: AppHandle) -> Vec<TargetStatus> {
    let st = app.state::<AppState>();
    let cfg = st.cfg();
    let statuses = snapshot(&cfg);
    let _ = app.emit("status-update", &statuses);
    statuses
}

#[tauri::command]
fn set_master(app: AppHandle, enabled: bool) -> Vec<TargetStatus> {
    let targets: Vec<Target> = {
        let st = app.state::<AppState>();
        let mut cfg = st.cfg();
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
    let cfg = st.cfg();
    snapshot(&cfg)
}

#[tauri::command]
fn set_target_enabled(app: AppHandle, id: String, enabled: bool) -> Result<Vec<TargetStatus>, String> {
    let (target, master) = {
        let st = app.state::<AppState>();
        let mut cfg = st.cfg();
        let t = cfg.find_mut(&id).ok_or("unknown app")?;
        t.enabled = enabled;
        (t.clone(), cfg.master_enabled)
    };
    save_config(&app);
    if master {
        engage_target(&app, target, enabled);
    }
    let st = app.state::<AppState>();
    let cfg = st.cfg();
    Ok(snapshot(&cfg))
}

#[tauri::command]
fn set_target_show_icon(app: AppHandle, id: String, show_icon: bool) -> Result<Config, String> {
    let st = app.state::<AppState>();
    let mut cfg = st.cfg();
    let t = cfg.find_mut(&id).ok_or("unknown app")?;
    t.show_icon = show_icon;
    let _ = cfg.save(&st.config_dir);
    Ok(cfg.clone())
}

#[tauri::command]
fn focus_main_window(app: AppHandle) -> bool {
    show_main(&app)
}

#[tauri::command]
fn protect_now(app: AppHandle, id: String) -> Result<String, String> {
    let (target, engine) = {
        let st = app.state::<AppState>();
        let cfg = st.cfg();
        let t = cfg.find(&id).ok_or("unknown app")?.clone();
        (t, st.engine.clone())
    };
    let out = engine.apply(&target).map_err(|e| first_line(&e))?;
    push_log(&app, "info", &format!("Manually protected {}", target.name));
    let statuses = {
        let st = app.state::<AppState>();
        let cfg = st.cfg();
        snapshot(&cfg)
    };
    let _ = app.emit("status-update", &statuses);
    Ok(out)
}

#[tauri::command]
fn unprotect_now(app: AppHandle, id: String) -> Result<String, String> {
    let (target, engine) = {
        let st = app.state::<AppState>();
        let cfg = st.cfg();
        let t = cfg.find(&id).ok_or("unknown app")?.clone();
        (t, st.engine.clone())
    };
    let out = engine.remove(&target).map_err(|e| first_line(&e))?;
    push_log(&app, "info", &format!("Manually removed protection from {}", target.name));
    let statuses = {
        let st = app.state::<AppState>();
        let cfg = st.cfg();
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
    let mut cfg = st.cfg();
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
        let mut cfg = st.cfg();
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
    let mut cfg = st.cfg();
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
    // In elevated mode the scheduled task owns logon start, and the HKCU\Run
    // key must stay gone: registering both makes them race, and the Run key's
    // copy is always unelevated (that hive uses the plain user token), so it
    // can win the race and leave an instance running that cannot protect
    // anything. Writing the key here would recreate exactly the racer that
    // `resolve_logon_ownership()` removes at every start.
    let elevated_mode = app.state::<AppState>().cfg().elevated_mode;

    let mgr = app.autolaunch();
    if enabled && !elevated_mode {
        mgr.enable().map_err(|e| e.to_string())?;
    } else {
        // Elevated mode: the task already starts us at logon, so honour the
        // user's "start on login" preference by recording it without adding a
        // second launcher.
        mgr.disable().map_err(|e| e.to_string())?;
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.cfg();
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
    // In elevated mode the Run key is deliberately absent — the scheduled task
    // starts us instead — so `is_enabled()` reads false even though start-on-
    // login is genuinely on. Reporting that would make the toggle flip itself
    // back off in front of the user. The saved preference is the truth here.
    if elevated_mode {
        return Ok(enabled);
    }
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
    // Does the user currently want to start at logon? The mechanism changes
    // with elevated mode, but the preference itself must survive the switch.
    let wants_autostart = app.state::<AppState>().cfg().start_on_login;

    if enabled {
        elevate::install_task(&exe)?;
        // The task now owns logon start; the Run key would be a second,
        // unelevated racer for it, so it goes.
        let _ = app.autolaunch().disable();
    } else {
        elevate::remove_task()?;
        // Hand logon start back to the Run key, otherwise turning elevated mode
        // off would silently leave NOTHING starting the app: the task is gone
        // and the key was removed when elevated mode was turned on.
        if wants_autostart {
            let _ = app.autolaunch().enable();
        }
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.cfg();
        cfg.elevated_mode = enabled;
        // `start_on_login` is deliberately NOT cleared when enabling: it records
        // the user's intent, and the scheduled task is what carries it out in
        // elevated mode. Clearing it made the settings toggle read "off" while
        // the app was in fact still starting at every logon, and left the user
        // with no autostart at all if they later turned elevated mode back off.
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
///
/// An update that FAILS, though, leaves this process alive with every hook torn
/// down and no code path that puts them back: protection would be silently off
/// until the next restart while the UI still showed green. So we arm a watchdog
/// — if we're still running a few seconds later, the install didn't take, and
/// protection is restored.
#[tauri::command]
fn prepare_for_update_install(app: AppHandle) {
    hook::shutdown();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(10));
        // Still here => `update.install()` never replaced us. Bring the engine
        // back up and re-protect everything the config asks for.
        if hook::init().is_ok() {
            let targets = {
                let st = app.state::<AppState>();
                let cfg = st.cfg();
                cfg.master_enabled.then(|| cfg.targets.clone())
            };
            for t in targets.into_iter().flatten().filter(|t| t.enabled) {
                hook::protect_target(&t.process);
            }
        }
        push_log(
            &app,
            "warn",
            "Update did not install — protection has been re-applied.",
        );
    });
}

#[tauri::command]
fn set_self_protection(app: AppHandle, enabled: bool) -> Result<bool, String> {
    if let Some(w) = app.get_webview_window("main") {
        w.set_content_protected(enabled).map_err(|e| e.to_string())?;
    }
    {
        let st = app.state::<AppState>();
        let mut cfg = st.cfg();
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
        let mut cfg = st.cfg();
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
    app.state::<AppState>().cfg().activity.clone()
}

#[tauri::command]
fn get_activity_status(app: AppHandle) -> activity::ActivityStatus {
    activity::status(&app)
}

#[tauri::command]
fn set_activity_config(app: AppHandle, settings: ActivitySettings) -> ActivityConfig {
    let cfg = {
        let st = app.state::<AppState>();
        let mut c = st.cfg();
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
    let mut c = st.cfg();
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
    let mut c = st.cfg();
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
    app.state::<AppState>().cfg().sync_monitor.clone()
}

#[tauri::command]
fn get_sync_status(app: AppHandle) -> syncmon::SyncStatus {
    syncmon::status(&app)
}

#[tauri::command]
fn set_sync_config(app: AppHandle, settings: SyncSettings) -> SyncConfig {
    let cfg = {
        let st = app.state::<AppState>();
        let mut c = st.cfg();
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
    let mut c = st.cfg();
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
    let mut c = st.cfg();
    c.sync_monitor.custom_trackers.retain(|n| !n.eq_ignore_ascii_case(&name));
    let _ = c.save(&st.config_dir);
    c.sync_monitor.clone()
}

#[tauri::command]
fn set_sync_paused(app: AppHandle, paused: bool) -> syncmon::SyncStatus {
    syncmon::set_paused(paused);
    {
        let st = app.state::<AppState>();
        let mut c = st.cfg();
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

/// Bring the main window up from ANY state, and verify it actually happened.
///
/// The old version called `show()`/`unminimize()`/`set_focus()` and discarded
/// all three Results, so a failure was completely invisible: the tray click ran
/// this, nothing appeared, and nothing was logged. Two things make that failure
/// mode real rather than theoretical:
///
///   * `show()` goes through Tauri's async path, so its error is dropped even
///     when it is returned;
///   * we normally run ELEVATED while explorer.exe (which delivers the tray
///     click) does not, and UIPI blocks the foreground hand-off between them.
///
/// So we do not trust return values here. After asking Tauri nicely we check
/// the window's REAL state with `IsWindowVisible` and, if it is still hidden,
/// fall back to a direct `ShowWindow` on our own HWND — a synchronous user32
/// call with no IPC in the way. Focus is treated as best-effort and is never
/// allowed to make the call report failure: a visible-but-unfocused window is
/// a good outcome, an invisible one is the bug we are fixing.
///
/// Returns true if the window ended up visible.
fn show_main(app: &AppHandle) -> bool {
    let Some(w) = app.get_webview_window("main") else {
        push_log(app, "error", "Cannot open window: main window not found");
        return false;
    };

    // Ask Tauri first — it keeps the webview's own state in sync.
    let _ = w.unminimize();
    let _ = w.show();

    // Ground truth: what does the OS actually say? Anything else is a guess.
    let hwnd = w.hwnd().ok().map(|h| winapi::hwnd_from_raw(h.0 as isize));
    let visible = match hwnd {
        Some(h) => {
            if !winapi::is_window_visible(h) || winapi::is_window_minimized(h) {
                // Tauri's show() didn't take. Go straight at the HWND.
                winapi::show_window_native(h);
            }
            winapi::is_window_visible(h)
        }
        // No HWND to check against: fall back to Tauri's own view.
        None => w.is_visible().unwrap_or(false),
    };

    if !visible {
        push_log(
            app,
            "error",
            "Window did not become visible (show and native fallback both failed)",
        );
        return false;
    }

    // Visible now. Focus is best-effort — under UIPI the activation can stay
    // refused, and force_foreground's last resort still raises the window so
    // the user can see and click it.
    let _ = w.set_focus();
    if let Some(h) = hwnd {
        if !winapi::force_foreground(h) {
            push_log(
                app,
                "warn",
                "Window shown but could not take focus (foreground refused) — raised instead",
            );
        }
    }
    true
}

/// Tray left-click behaviour: show when hidden, hide when already in front.
fn toggle_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let visible = match w.hwnd().ok().map(|h| winapi::hwnd_from_raw(h.0 as isize)) {
            Some(h) => winapi::is_window_visible(h) && !winapi::is_window_minimized(h),
            None => w.is_visible().unwrap_or(false),
        };
        // Only fold away a window that is genuinely in front. If it is visible
        // but buried behind something else, the click means "bring it to me",
        // not "hide it".
        if visible {
            let focused = w.is_focused().unwrap_or(false);
            if focused {
                let _ = w.hide();
                return;
            }
        }
    }
    show_main(app);
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
            "open" => {
                show_main(app);
            }
            "pause" => {
                let enabled = {
                    let st = app.state::<AppState>();
                    let cfg = st.cfg();
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
                toggle_main(&tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Settle which copy of Windows Guard owns this logon, before the Tauri builder
/// (and therefore the single-instance lock) exists.
///
/// The bug this fixes: two independent mechanisms started us at logon — the
/// HKCU\Run key (always UNELEVATED, because that key uses the plain user token)
/// and the scheduled task (elevated). Both fired at once. The Run key's copy
/// called `schtasks /Run`, collided with the task's own LogonTrigger, got
/// ERROR_TASK_ALREADY_RUNNING, read that as a FAILED hand-off and so did not
/// exit. An unelevated instance cannot install its hooks — SetWindowsHookExW
/// returns access-denied without SeDebugPrivilege — so every target stayed
/// capturable while the UI cheerfully reported them protected.
///
/// Runs before `setup()` because the single-instance plugin kills whichever
/// process starts second: if the unelevated copy took that lock first, the
/// elevated copy would be killed as a duplicate and the bug would become
/// permanent.
fn resolve_logon_ownership() {
    // Read the config directly. Tauri's path resolver isn't available this
    // early, and this must not depend on anything the builder sets up.
    let Some(config_dir) = std::env::var("APPDATA").ok().map(|a| {
        std::path::PathBuf::from(a).join("com.rashid.capture-guard")
    }) else {
        return;
    };
    let config = Config::load_or_default(&config_dir);
    if !config.elevated_mode {
        // The user opted out of elevated mode, so the Run key legitimately owns
        // logon. Nothing to arbitrate, and nothing to clean up.
        return;
    }

    // Drop the HKCU\Run entry NOW, before the single-instance lock exists —
    // and do it whatever our own elevation is. It is the second racer: it
    // starts an unelevated copy at every logon, and if that copy reaches the
    // builder first it takes the lock and the ELEVATED copy is killed as the
    // duplicate, which is precisely the bug this function exists to prevent.
    //
    // Doing this before the `is_elevated()` return matters. On a healthy
    // machine the elevated copy is the one that survives, so it is the only
    // instance that ever gets here — gate this on being unelevated and the
    // stale key is only ever removed on the boots where the user is ALREADY
    // broken, and survives indefinitely on the boots where it still needs to
    // go. Deleting an HKCU value needs no elevation, is idempotent, and a
    // missing value is not an error, so it is safe to run unconditionally.
    // (`app.autolaunch()` can't be used here — no AppHandle exists yet.)
    elevate::remove_run_key();

    if privilege::is_elevated() {
        // We're already the elevated copy: the hand-off below is for handing
        // control TO such a copy, so there is nothing left to arbitrate.
        return;
    }

    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    // Make sure the task exists. On first run this is the ONE UAC prompt the
    // user ever sees; if they decline we carry on unelevated rather than
    // getting stuck, and don't retry until the next launch.
    let mut have_task = elevate::task_installed();
    if !have_task {
        have_task = elevate::install_task(&exe).is_ok();
    }
    if !have_task {
        return;
    }

    // Hand off to the elevated copy and step aside — but only once we've
    // confirmed it actually exists. `schtasks /Run` returns as soon as the
    // request is QUEUED, not when the process has started, so exiting on its
    // return alone can leave zero instances running: the user's app would
    // simply be gone after logon.
    if elevate::run_task_now().is_ok()
        && elevate::wait_for_other_instance(&exe, std::time::Duration::from_secs(10))
    {
        // No hooks to release: this runs before the engine starts.
        std::process::exit(0);
    }
    // Fall through: no elevated copy appeared. Keep running unelevated so the
    // user has *something*, and let setup() raise the engine-health banner
    // explaining that it cannot protect anything.
}

pub fn run() {
    // Decide who owns this logon BEFORE the single-instance plugin can act.
    //
    // The plugin kills whichever process starts SECOND. On an existing install
    // the stale HKCU\Run key is still there, and its copy is unelevated: if it
    // wins the race it would take the single-instance lock and the elevated
    // copy from the scheduled task would be killed as a duplicate — locking in
    // the exact bug we're fixing, permanently. The Run key is therefore removed
    // in here, before any lock exists, and an unelevated copy stands aside for
    // the elevated one rather than claiming the lock.
    resolve_logon_ownership();

    tauri::Builder::default()
        // MUST be the first plugin registered. Two instances of Windows Guard
        // must never run at once: they would fight over the same hooks and the
        // same config file. Nothing in-process used to arbitrate this — the app
        // relied entirely on the scheduled task's MultipleInstancesPolicy, which
        // cannot see an instance the Run key started.
        //
        // The second instance exits and its argv is handed to the one already
        // running, which surfaces its window — so double-clicking the exe while
        // it sits in the tray brings it up instead of doing nothing.
        //
        // This deliberately does NOT interfere with the elevation hand-off in
        // `setup()`: the hand-off runs an ELEVATED copy, and this callback fires
        // in the *existing* process. When the unelevated launcher hands off, it
        // has already exited by the time the elevated copy is up, so the
        // elevated copy is not treated as a second instance.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app);
        }))
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
            // Neither step may be fatal: this runs before the tray exists, so a
            // panic here kills the process with no window, no tray icon and no
            // error the user can see — indistinguishable from "it just didn't
            // start".
            let config_dir = app.path().app_config_dir().unwrap_or_else(|_| {
                std::env::var("APPDATA")
                    .map(|a| std::path::PathBuf::from(a).join("com.rashid.capture-guard"))
                    .unwrap_or_else(|_| std::env::temp_dir().join("com.rashid.capture-guard"))
            });
            let engine_result = Engine::install(&config_dir.join("engine"));
            let engine_error = engine_result
                .as_ref()
                .err()
                .map(|e| first_line(&e.to_string()));
            // Engine is just a bundle of script paths. If writing them out
            // failed, still point at where they would be: every use shells out
            // to PowerShell and returns a normal Err, so a missing script
            // degrades that one action instead of killing startup.
            let engine = engine_result.unwrap_or_else(|_| {
                let dir = config_dir.join("engine");
                Engine {
                    electron_ps: dir.join("Enable-ElectronContentProtection.ps1"),
                    hide_ps: dir.join("Protect-WhatsAppCapture.ps1"),
                    apps_ps: dir.join("List-InstalledApps.ps1"),
                    icons_ps: dir.join("Get-AppIcons.ps1"),
                }
            });
            // Whether a config already existed must be sampled BEFORE anything can
            // write one, otherwise "is this the first launch?" answers itself
            // wrongly. Read once here; used below for `start_minimized`.
            let config_existed = Config::config_path(&config_dir).exists();
            // `load_reporting` distinguishes a genuine first run from a config
            // that is corrupt (renamed aside) or merely unreadable (defaults
            // used in memory, the file left alone). Silently starting on
            // defaults is how a user loses every target they configured without
            // ever being told, so the warning is surfaced rather than dropped.
            let (config, config_warning) = Config::load_reporting(&config_dir);

            // AppState is managed FIRST: every #[tauri::command] panics on an
            // unmanaged state, and the elevation hand-off below shells out to
            // schtasks, which can take seconds. Nothing above this line touches
            // state, so there is no window where a command can arrive early.
            let elevated_mode = config.elevated_mode;
            let start_on_login = config.start_on_login;
            let protect_self = config.protect_self;
            let privacy_veil = config.privacy_veil;
            let activity_enabled = config.activity.enabled;
            // The persisted preference is authoritative. `--minimized` is only a
            // hint for the very first launch (before the user has a saved config):
            // treating it as an override meant an autostart launch forced the
            // window hidden even after the user switched "start minimized" OFF,
            // so their toggle looked broken. The flag can still arrive from a
            // manual launch or a legacy Run-key entry, so we keep honouring it —
            // just not at the expense of an explicit choice.
            let start_minimized = if config_existed {
                config.start_minimized
            } else {
                config.start_minimized || std::env::args().any(|a| a == "--minimized")
            };

            app.manage(AppState {
                config: Mutex::new(config),
                engine,
                config_dir,
                log: Mutex::new(VecDeque::new()),
                installed_cache: Mutex::new(None),
            });

            if let Some(e) = engine_error {
                push_log(&handle, "error", &format!("Engine scripts unavailable: {e}"));
            }
            if let Some(w) = &config_warning {
                push_log(&handle, "warn", w);
            }
            set_config_notice(config_warning);

            // --- who starts us at logon ------------------------------------
            //
            // Exactly ONE mechanism may do it. With elevated mode on that is the
            // scheduled task, and the HKCU\Run key must be gone — registering
            // both makes them race. The Run key's copy is always UNELEVATED
            // (HKCU\Run uses the plain user token); it fires at the same moment
            // as the task's LogonTrigger, so its `run_task_now()` collides with
            // MultipleInstancesPolicy=IgnoreNew and comes back
            // ERROR_TASK_ALREADY_RUNNING. That used to read as a FAILED hand-off,
            // so the unelevated copy did not exit — and an unelevated instance
            // can never install its hooks (no SeDebugPrivilege), leaving every
            // target capturable while the UI reported them protected.
            //
            // `run_task_now()` now treats ALREADY_RUNNING as success, and the Run
            // key is removed whenever the task owns logon, so there is no second
            // racer left. The removal itself already happened in
            // `resolve_logon_ownership()` (it has to, to beat the single-instance
            // lock); this re-asserts it through the plugin so the two agree and
            // the toggle keeps working for non-elevated setups.
            let mgr = app.autolaunch();
            if elevated_mode {
                let _ = mgr.disable();
            } else if start_on_login {
                let _ = mgr.enable();
            }

            // The elevation hand-off itself already happened in
            // `resolve_logon_ownership()`, before the builder ran. Reaching here
            // unelevated with elevated mode on means it could not produce an
            // elevated copy; the engine-health banner below says so.
            // (Running unelevated with elevated mode on is reported once the
            // engine is up, alongside the rest of the engine-health state.)

            // Rename migration: clean up any scheduled task from a prior
            // product name, and if elevated mode is on but the (new-name)
            // logon task doesn't exist yet, register it now. Both no-ops
            // unless we're already elevated (e.g. launched by the OLD task at
            // logon), in which case they happen with zero extra UAC prompts.
            elevate::cleanup_retired_tasks();
            if elevated_mode && privilege::is_elevated() && !elevate::task_installed() {
                if let Ok(exe) = std::env::current_exe() {
                    let _ = elevate::install_task(&exe);
                }
            }

            // Never fatal. If the tray fails to build and we propagate the error,
            // setup() aborts — and because the window starts hidden, that leaves a
            // running process with no tray icon AND no window, reachable only via
            // Task Manager. Log it and carry on; protection still runs, and the
            // window can still be opened by relaunching the exe.
            if let Err(e) = build_tray(&handle) {
                push_log(
                    &handle,
                    "error",
                    &format!("Tray icon unavailable: {e} — use the app window to control Windows Guard"),
                );
            }

            // When elevated, enable SeDebugPrivilege for the broadest process reach.
            if privilege::is_elevated() {
                privilege::enable_se_debug();
                push_log(&handle, "info", "Running elevated — SeDebugPrivilege enabled");
            }

            // Bring up the signed hook engine (extracts + trusts the helper DLL,
            // loads it, starts the owner thread). Degrades gracefully if the DLL
            // can't be prepared.
            let init_result = hook::init();
            let engine_started_ok = init_result.is_ok();
            match init_result {
                Ok(()) => {
                    push_log(&handle, "info", "Protection engine ready (signed hook DLL)");
                    set_engine_health(EngineHealth::Ready);
                }
                Err(e) => {
                    push_log(&handle, "error", &format!("Protection engine unavailable: {e}"));
                    set_engine_health(EngineHealth::Unavailable { reason: e.clone() });
                    // A failed init used to be permanent for the session: the
                    // engine never set up its channel, so every protect request
                    // silently no-opped until the app was restarted. Retry in the
                    // background — the usual causes (an antivirus holding the DLL,
                    // %LOCALAPPDATA% not ready this early at logon) clear on their
                    // own within seconds.
                    let h = handle.clone();
                    std::thread::spawn(move || loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                        if hook::init().is_ok() {
                            push_log(&h, "info", "Protection engine recovered");
                            // Only clear the failure we own. Recovering the DLL
                            // does not grant us rights we never had, so an
                            // unelevated instance must stay Degraded — flipping
                            // it to Ready here would re-hide the exact condition
                            // this whole state was added to expose.
                            if privilege::is_elevated() {
                                set_engine_health(EngineHealth::Ready);
                            }
                            break;
                        }
                    });
                }
            }

            // Elevated mode is on but we are NOT elevated: the hand-off in
            // `resolve_logon_ownership()` could not produce an elevated copy.
            // Protection will fail for every target that is itself elevated, so
            // say so plainly instead of presenting a healthy-looking UI over an
            // engine that cannot do its job. This is the state the user's
            // original bug left the app in, silently, after every reboot.
            //
            // Only downgrade from Ready: if the engine failed to start at all it
            // is already Unavailable, which is the more severe report of the two.
            if elevated_mode && !privilege::is_elevated() && engine_started_ok {
                let reason = if elevate::task_installed() {
                    "Windows Guard is running without administrator rights, so it cannot protect \
                     other apps. Windows did not start the elevated copy at logon — use \
                     \"Restart elevated\" to fix this now."
                } else {
                    "Windows Guard is running without administrator rights, so it cannot protect \
                     other apps. Its elevated start-up task isn't registered — use \"Restart \
                     elevated\" and approve the prompt to set it up."
                }
                .to_string();
                push_log(&handle, "error", &reason);
                set_engine_health(EngineHealth::Degraded { reason });
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
            // The window starts hidden (tauri.conf.json's "visible": false) so
            // there's no race with Tauri's own default show-on-ready behavior;
            // we explicitly show it here unless the user wants it minimized.
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_content_protected(protect_self);
                if !start_minimized {
                    // Same verified path the tray click uses, so a failure to
                    // appear at startup is logged instead of looking like the
                    // app never launched.
                    show_main(&handle);
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides to tray so protection keeps running.
            // Only safe while there is a tray icon to get back in through — if
            // the tray failed to build, hiding here would strand the user with
            // no window and no icon, so in that case we let the close proceed.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                if app.tray_by_id("main-tray").is_some() {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    hook::shutdown();
                    wablur::shutdown();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
