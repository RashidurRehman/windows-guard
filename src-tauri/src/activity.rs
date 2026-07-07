//! Idle-triggered activity simulator.
//!
//! After a configurable period of no real user input (system-wide — any app),
//! presses a short burst of harmless keys so other software (idle detectors,
//! away-status timers, screensavers) sees genuine input, without anything
//! visible happening: no character is typed, no window is affected. Real user
//! input mid-burst aborts it immediately.
//!
//! Idle detection uses `GetLastInputInfo`, the standard Win32 API for this —
//! it tracks the timestamp of the last input (mouse OR keyboard) system-wide,
//! updated by the OS itself, so no custom hook/listener/debounce logic is
//! needed. Because our own simulated presses go through `SendInput`, they also
//! update this timestamp, so the idle timer naturally restarts after each
//! burst — matching the intended "idle N seconds, burst, wait N more" cadence.

use crate::config::ActivityConfig;
use rand::Rng;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

use windows::Win32::Foundation::HWND;
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetLastInputInfo, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, LASTINPUTINFO, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{GetClassNameW, GetForegroundWindow, GetWindow, GW_OWNER};

/// Two well-known single keys that are NOT safe to press alone (Alt alone can
/// highlight/focus a window's menu bar on release; Win alone opens the Start
/// menu). Multi-key combos including either are fine — it's holding them
/// *alone* that has a visible effect.
pub const VK_LMENU: u16 = 0xA4;
pub const VK_RMENU: u16 = 0xA5;
pub const VK_LWIN: u16 = 0x5B;
pub const VK_RWIN: u16 = 0x5C;

static ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_IDLE_MS: AtomicU64 = AtomicU64::new(0);
static LAST_BURST_TICK: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct ActivityStatus {
    pub enabled: bool,
    pub idle_secs: u64,
    pub threshold_secs: u64,
}

fn config_snapshot(app: &AppHandle) -> ActivityConfig {
    let st = app.state::<crate::AppState>();
    let cfg = st.config.lock().unwrap().activity.clone();
    cfg
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Reject single-key combos everyone agrees are NOT invisible (Alt/Win alone).
/// Anything else — including Alt/Win combined with another key — is allowed;
/// the caller (frontend) additionally warns on well-known bound shortcuts.
pub fn validate_combo(vks: &[u16]) -> Result<(), String> {
    if vks.is_empty() {
        return Err("Pick at least one key".into());
    }
    if vks.len() == 1 {
        let vk = vks[0];
        if vk == VK_LMENU || vk == VK_RMENU {
            return Err("Alt alone can highlight a window's menu — combine it with another key (e.g. Ctrl+Alt)".into());
        }
        if vk == VK_LWIN || vk == VK_RWIN {
            return Err("Windows key alone opens the Start menu — combine it with another key (e.g. Win+Shift)".into());
        }
    }
    Ok(())
}

// --- idle detection --------------------------------------------------------

fn idle_ms() -> u64 {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        let _ = GetLastInputInfo(&mut lii);
    }
    let now = unsafe { GetTickCount() };
    now.wrapping_sub(lii.dwTime) as u64
}

/// Is the current foreground window a dialog/popup? We deliberately skip
/// firing a burst into these: some apps' "are you still there?" / confirm
/// dialogs (e.g. time-tracker idle-check prompts) treat ANY keypress — even a
/// bare modifier like Shift — as "dismiss", which would otherwise make the
/// simulator silently auto-close a dialog the user actually wants to read and
/// respond to. Two standard signals: it's owned by another window (the
/// classic dialog/popup relationship, set by well-behaved apps including Qt),
/// or its class is the stock Win32 dialog class used by MessageBox/DialogBox.
fn foreground_is_dialog() -> bool {
    unsafe {
        let fg = GetForegroundWindow();
        if fg == HWND::default() {
            return false;
        }
        if let Ok(owner) = GetWindow(fg, GW_OWNER) {
            if owner != HWND::default() {
                return true;
            }
        }
        let mut buf = [0u16; 64];
        let n = GetClassNameW(fg, &mut buf);
        if n > 0 && String::from_utf16_lossy(&buf[..n as usize]) == "#32770" {
            return true;
        }
        false
    }
}

// --- input simulation --------------------------------------------------------

fn send_key(vk: u16, key_up: bool) {
    let flags: KEYBD_EVENT_FLAGS = if key_up {
        KEYEVENTF_KEYUP
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

fn press_combo(vks: &[u16], hold_ms: u64) {
    for &vk in vks {
        send_key(vk, false);
    }
    std::thread::sleep(Duration::from_millis(hold_ms));
    for &vk in vks.iter().rev() {
        send_key(vk, true);
    }
}

fn rand_range(rng: &mut impl Rng, lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        lo
    } else {
        rng.gen_range(lo..=hi)
    }
}

/// Fire one burst: a handful of random safe-key presses, aborting immediately
/// if real input arrives mid-burst (checked by comparing idle time before vs.
/// after each press — a real event resets idle_ms to ~0 from something other
/// than our own press).
fn do_burst(cfg: &ActivityConfig) {
    if cfg.safe_keys.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    let base = cfg.keys_per_burst.max(1);
    let n = rng.gen_range(base.saturating_sub(1).max(1)..=(base + 2));

    for _ in 0..n {
        let idle_before = idle_ms();
        let key = &cfg.safe_keys[rng.gen_range(0..cfg.safe_keys.len())];
        let hold = rand_range(&mut rng, cfg.hold_min_ms, cfg.hold_max_ms);
        press_combo(&key.vks, hold);

        let gap = rand_range(&mut rng, cfg.press_gap_min_ms, cfg.press_gap_max_ms);
        std::thread::sleep(Duration::from_millis(gap));

        // If idle time jumped up instead of resetting near 0, or a burst of
        // real input landed in the gap, someone's actually using the machine —
        // stop immediately rather than fighting them.
        let idle_after = idle_ms();
        if idle_after > idle_before && idle_after > gap + hold + 50 {
            return;
        }
    }
}

fn dbg(msg: &str) {
    if std::env::var("CG_ACTIVITY_DEBUG").as_deref() == Ok("1") {
        if let Ok(dir) = std::env::var("TEMP") {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{dir}\\cg-activity-debug.log"))
            {
                let _ = writeln!(f, "{msg}");
            }
        }
    }
}

// --- supervisor ----------------------------------------------------------------

pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || loop {
        let cfg = config_snapshot(&app);
        let enabled = cfg.enabled && ENABLED.load(Ordering::Relaxed);
        let idle = idle_ms();
        LAST_IDLE_MS.store(idle, Ordering::Relaxed);
        dbg(&format!("tick enabled={enabled} idle_ms={idle}"));

        if enabled {
            let threshold_ms = cfg.idle_threshold_secs.saturating_mul(1000);
            let now_tick = unsafe { GetTickCount() } as u64;
            let since_last_burst = now_tick.wrapping_sub(LAST_BURST_TICK.load(Ordering::Relaxed));
            if idle >= threshold_ms && since_last_burst >= threshold_ms {
                if foreground_is_dialog() {
                    // Don't touch LAST_BURST_TICK — retry next tick (~1s) so we
                    // fire the moment the dialog is gone, instead of waiting a
                    // full idle_threshold_secs more.
                    dbg("BURST skipped: foreground is a dialog");
                } else {
                    dbg("BURST firing");
                    do_burst(&cfg);
                    LAST_BURST_TICK.store(unsafe { GetTickCount() } as u64, Ordering::Relaxed);
                }
            }
        }

        let _ = app.emit(
            "activity-status",
            &ActivityStatus {
                enabled: cfg.enabled,
                idle_secs: idle / 1000,
                threshold_secs: cfg.idle_threshold_secs,
            },
        );

        std::thread::sleep(Duration::from_secs(1));
    });
}

pub fn status(app: &AppHandle) -> ActivityStatus {
    let cfg = config_snapshot(app);
    ActivityStatus {
        enabled: cfg.enabled,
        idle_secs: LAST_IDLE_MS.load(Ordering::Relaxed) / 1000,
        threshold_secs: cfg.idle_threshold_secs,
    }
}

