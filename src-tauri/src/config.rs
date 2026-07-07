//! Configuration model: the set of apps we protect, how, and global settings.
//! Persisted as JSON in the app config dir.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// How a given app is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    /// Signed hook-DLL show-through (non-Electron apps we can't patch: WhatsApp,
    /// Brave, most games). A signed helper DLL is mapped into the target via the
    /// documented `SetWindowsHookEx` mechanism — no remote-thread injection — and
    /// excludes the app's windows from capture while they stay visible to the
    /// user. The DLL also self-heals new windows in-process; the monitor re-hooks
    /// the app if it restarts.
    Inject,
    /// Patch the app's own Electron bundle so it calls setContentProtection on
    /// itself (Cursor, VS Code, other Electron apps). Permanent across restarts;
    /// an app update wipes it, so we re-apply after updates. No injection.
    ElectronPatch,
    /// Fallback with no injection: hide the window only for the moment of a
    /// capture, then restore it. Weaker but AV-safe.
    HideDuringCapture,
}

impl Method {
    pub fn label(&self) -> &'static str {
        match self {
            Method::Inject => "Injection show-through",
            Method::ElectronPatch => "Electron self-patch",
            Method::HideDuringCapture => "Hide during capture",
        }
    }
}

/// A single protected application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Stable identifier, e.g. "whatsapp".
    pub id: String,
    /// Display name shown in the UI.
    pub name: String,
    pub method: Method,
    /// Process name WITHOUT the .exe suffix (used for status reads and -Process).
    pub process: String,
    /// Optional window-class filter (empty = any).
    #[serde(default)]
    pub class: String,
    /// Optional case-insensitive title substring the window must contain.
    #[serde(default)]
    pub title: String,
    /// Include hidden/untitled top-level windows (e.g. floating widgets).
    #[serde(default)]
    pub all_windows: bool,
    /// Whether protection is currently turned ON for this app.
    #[serde(default)]
    pub enabled: bool,
    /// Shipped default: can be disabled but not deleted from the UI.
    #[serde(default)]
    pub builtin: bool,
    /// Show a small floating "Windows Guard" status badge docked to this
    /// app's window (click to jump to it in the main window). Independent of
    /// whether capture-protection itself is on. See `appicon.rs`.
    #[serde(default)]
    pub show_icon: bool,
}

fn default_true() -> bool {
    true
}
fn default_interval() -> u64 {
    // Backstop cadence only — the event watcher reacts instantly, so this can be
    // slow to keep idle work near zero.
    15
}

/// A key (or key combo, e.g. Win+Shift) the activity simulator is allowed to
/// press. `vks` holds one or more Win32 virtual-key codes pressed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeKey {
    /// Friendly display label, e.g. "Shift", "Win + Shift", "F15".
    pub label: String,
    pub vks: Vec<u16>,
}

fn default_idle_secs() -> u64 {
    120
}
fn default_keys_per_burst() -> u32 {
    5
}
fn default_gap_min_ms() -> u64 {
    150
}
fn default_gap_max_ms() -> u64 {
    400
}
fn default_hold_min_ms() -> u64 {
    30
}
fn default_hold_max_ms() -> u64 {
    100
}

/// Win32 virtual-key codes used by the default safe-key set. See
/// https://learn.microsoft.com/windows/win32/inputdev/virtual-key-codes
pub const VK_LSHIFT: u16 = 0xA0;
pub const VK_LCONTROL: u16 = 0xA2;
pub const VK_F15: u16 = 0x7E;

fn default_safe_keys() -> Vec<SafeKey> {
    vec![
        SafeKey { label: "Shift".into(), vks: vec![VK_LSHIFT] },
        SafeKey { label: "Ctrl".into(), vks: vec![VK_LCONTROL] },
        // F15: virtually never bound to anything on a real keyboard/OS shortcut,
        // and doesn't type or toggle anything — a favorite of "keep-alive"-style
        // tools for exactly this reason.
        SafeKey { label: "F15".into(), vks: vec![VK_F15] },
    ]
}

/// Idle-triggered activity simulator: after a period of no real input, presses
/// a burst of harmless keys (modifiers / unbound function keys) so nothing
/// visible happens but the OS/other apps see genuine input. See `activity.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_idle_secs")]
    pub idle_threshold_secs: u64,
    #[serde(default = "default_keys_per_burst")]
    pub keys_per_burst: u32,
    #[serde(default = "default_gap_min_ms")]
    pub press_gap_min_ms: u64,
    #[serde(default = "default_gap_max_ms")]
    pub press_gap_max_ms: u64,
    #[serde(default = "default_hold_min_ms")]
    pub hold_min_ms: u64,
    #[serde(default = "default_hold_max_ms")]
    pub hold_max_ms: u64,
    #[serde(default = "default_safe_keys")]
    pub safe_keys: Vec<SafeKey>,
}

impl Default for ActivityConfig {
    fn default() -> Self {
        ActivityConfig {
            enabled: false,
            idle_threshold_secs: default_idle_secs(),
            keys_per_burst: default_keys_per_burst(),
            press_gap_min_ms: default_gap_min_ms(),
            press_gap_max_ms: default_gap_max_ms(),
            hold_min_ms: default_hold_min_ms(),
            hold_max_ms: default_hold_max_ms(),
            safe_keys: default_safe_keys(),
        }
    }
}

fn default_activity() -> ActivityConfig {
    ActivityConfig::default()
}

// --- Sync Monitor: detects when tracker/monitoring software is watching you ---

fn default_spike_threshold_kb() -> u32 {
    300
}
fn default_sync_poll_secs() -> u64 {
    5
}
fn default_cooldown_secs() -> u64 {
    2
}
fn default_log_max_mb() -> u32 {
    100
}
fn default_known_trackers() -> Vec<String> {
    [
        "WebWorkTracker", "Hubstaff", "TimeDoctor", "DeskTime", "ActivTrak", "Monitask",
        "TimeCamp", "Insightful", "Workpuls", "Teramind", "Veriato", "Controlio", "Kickidler",
        "StaffCop", "Sneek", "Prodoscore", "Interguard", "Trackabi", "Toggl", "Clockify",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Detects and alerts when known employee-monitoring/tracker software is
/// running and appears to be capturing a screenshot (a RAM-spike heuristic,
/// plus a dedicated file-watcher for WebWorkTracker specifically). See
/// `syncmon.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_spike_threshold_kb")]
    pub spike_threshold_kb: u32,
    #[serde(default = "default_sync_poll_secs")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_known_trackers")]
    pub known_trackers: Vec<String>,
    #[serde(default)]
    pub custom_trackers: Vec<String>,
    #[serde(default = "default_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default)]
    pub paused: bool,
    /// Epoch-ms deadline for a timed "meeting mode" pause; `None` = paused
    /// indefinitely (when `paused` is true) or not paused at all.
    #[serde(default)]
    pub paused_until_ms: Option<u64>,
    /// "HH:MM" 24h; empty = no quiet hours. During this window, events are
    /// still logged but not surfaced (no blink/notification).
    #[serde(default)]
    pub quiet_from: String,
    #[serde(default)]
    pub quiet_to: String,
    #[serde(default = "default_log_max_mb")]
    pub log_max_mb: u32,
    /// `None` = keep forever; `Some(n)` = prune events older than n days.
    #[serde(default)]
    pub log_retention_days: Option<u32>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            enabled: false,
            spike_threshold_kb: default_spike_threshold_kb(),
            poll_interval_secs: default_sync_poll_secs(),
            known_trackers: default_known_trackers(),
            custom_trackers: Vec::new(),
            cooldown_secs: default_cooldown_secs(),
            paused: false,
            paused_until_ms: None,
            quiet_from: String::new(),
            quiet_to: String::new(),
            log_max_mb: default_log_max_mb(),
            log_retention_days: None,
        }
    }
}

fn default_sync_monitor() -> SyncConfig {
    SyncConfig::default()
}

/// Top-level persisted configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Global kill-switch. When false, nothing is protected regardless of
    /// per-app toggles, and the monitor idles.
    #[serde(default = "default_true")]
    pub master_enabled: bool,
    /// How often (seconds) the monitor re-checks and re-applies protection.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Launch the guardian automatically at logon.
    #[serde(default)]
    pub start_on_login: bool,
    /// Start hidden to the tray (no window) when launched.
    #[serde(default)]
    pub start_minimized: bool,
    /// Exclude Windows Guard's OWN window from screen capture (we own it, so this
    /// is a direct, injection-free setContentProtection on ourselves).
    #[serde(default = "default_true")]
    pub protect_self: bool,
    /// Auto-start elevated at logon via a scheduled task (highest privileges),
    /// which unlocks protecting elevated apps + SeDebugPrivilege broad coverage.
    #[serde(default)]
    pub elevated_mode: bool,
    /// WhatsApp privacy blur: injects a control panel into WhatsApp's own
    /// WebView2 (via CDP) that blurs chats/messages/header against
    /// shoulder-surfing, revealing only what's hovered. Independent of
    /// capture-hiding. See `wablur.rs`.
    #[serde(default)]
    pub privacy_veil: bool,
    /// Idle-triggered activity simulator (harmless key bursts after inactivity).
    #[serde(default = "default_activity")]
    pub activity: ActivityConfig,
    /// Tracker/monitoring-software detector + WebWorkTracker screenshot clone
    /// (ported from the standalone Sync Monitor app). See `syncmon.rs`.
    #[serde(default = "default_sync_monitor")]
    pub sync_monitor: SyncConfig,
    pub targets: Vec<Target>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            master_enabled: true,
            interval_secs: 15,
            start_on_login: true,
            start_minimized: true,
            protect_self: true,
            elevated_mode: true,
            privacy_veil: false,
            activity: ActivityConfig::default(),
            sync_monitor: SyncConfig::default(),
            targets: default_targets(),
        }
    }
}

/// No apps are pre-added — a fresh install starts with an empty list so the
/// user has full control over exactly what gets protected. Previously this
/// shipped WhatsApp/Brave/Cursor as opinionated defaults, which isn't
/// appropriate for machines that don't even have those apps installed.
pub fn default_targets() -> Vec<Target> {
    Vec::new()
}

impl Config {
    pub fn config_path(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }

    /// Load config from the app config dir, or create a default one on first run.
    pub fn load_or_default(dir: &Path) -> Config {
        let path = Self::config_path(dir);
        match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Config>(&text) {
                Ok(mut cfg) => {
                    // Make sure new builtin defaults appear for existing users
                    // without clobbering their toggles.
                    cfg.merge_missing_builtins();
                    cfg
                }
                Err(_) => Config::default(),
            },
            Err(_) => {
                let cfg = Config::default();
                let _ = cfg.save(dir);
                cfg
            }
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let text = serde_json::to_string_pretty(self).unwrap_or_default();
        fs::write(Self::config_path(dir), text)
    }

    fn merge_missing_builtins(&mut self) {
        for def in default_targets() {
            if !self.targets.iter().any(|t| t.id == def.id) {
                self.targets.push(def);
            }
        }
    }

    pub fn find(&self, id: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.id == id)
    }

    pub fn find_mut(&mut self, id: &str) -> Option<&mut Target> {
        self.targets.iter_mut().find(|t| t.id == id)
    }
}
