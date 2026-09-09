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

/// Every virtual-key the simulator is ever allowed to press: modifiers, lock
/// keys, Pause, and F13-F24. What they have in common is that none of them
/// types a character or activates anything on its own, so a burst is invisible
/// no matter which window has focus.
///
/// This mirrors `ACTIVITY_KEY_MAP` in `src/main.ts`, which restricts what the
/// key recorder will accept. That UI check used to be the ONLY thing standing
/// between the simulator and a printable key: `validate_combo` rejected just
/// bare Alt/Win, so a hand-edited `config.json` (or any other path that reaches
/// the config without going through the recorder) could install e.g. `A` or
/// `Enter` as a "safe" key and have it typed into whatever the user had in
/// focus. Keep the two lists in sync; this one is authoritative.
const ALLOWED_VKS: &[u16] = &[
    0xA0, 0xA1, // Shift L/R
    0xA2, 0xA3, // Ctrl L/R
    0xA4, 0xA5, // Alt L/R
    0x5B, 0x5C, // Win L/R
    0x91, // Scroll Lock
    0x14, // Caps Lock
    0x90, // Num Lock
    0x13, // Pause
    // F13-F24: not present on normal keyboards and unbound by default.
    0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
];

fn vk_allowed(vk: u16) -> bool {
    ALLOWED_VKS.contains(&vk)
}

/// Drop any safe key holding a virtual-key outside `ALLOWED_VKS`, or that
/// `validate_combo` rejects. Applied to whatever comes off disk, because the
/// config is deserialized straight into `ActivityConfig` with no validation of
/// its own — an edited or hand-written file would otherwise be trusted.
/// Returns the labels that were dropped so the caller can log them.
pub fn sanitize_safe_keys(cfg: &mut ActivityConfig) -> Vec<String> {
    let mut dropped = Vec::new();
    cfg.safe_keys.retain(|k| {
        if validate_combo(&k.vks).is_ok() {
            return true;
        }
        dropped.push(k.label.clone());
        false
    });
    dropped
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static LAST_IDLE_MS: AtomicU64 = AtomicU64::new(0);
static LAST_BURST_TICK: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize)]
pub struct ActivityStatus {
    pub enabled: bool,
    pub idle_secs: u64,
    pub threshold_secs: u64,
}

/// Snapshot the activity settings. Recovers from a poisoned config mutex
/// instead of unwrapping: this runs on a supervisor thread that must live for
/// the whole session, and a panic in any OTHER holder of the lock would
/// otherwise take this thread down with it — silently, leaving the UI showing
/// the last status it emitted forever.
fn config_snapshot(app: &AppHandle) -> ActivityConfig {
    let st = app.state::<crate::AppState>();
    let guard = st.config.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = guard.activity.clone();
    drop(guard);
    // Enforce the allowlist on every read rather than once at load. The config
    // is deserialized straight from disk with no validation, so a hand-edited
    // file could otherwise install a printable key; and this is the only path
    // by which the simulator ever obtains its key list, so nothing can reach
    // `do_burst` without passing through here.
    let dropped = sanitize_safe_keys(&mut cfg);
    if !dropped.is_empty() {
        dbg(&format!("dropped disallowed safe keys: {}", dropped.join(", ")));
    }
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
    // Anything that can type a character or trigger an action is refused
    // outright, whatever it is combined with — a burst goes to whichever
    // window happens to have focus, so this is the check that keeps the
    // simulator from typing into the user's documents, chats or password
    // fields.
    if let Some(bad) = vks.iter().copied().find(|vk| !vk_allowed(*vk)) {
        return Err(format!(
            "Key 0x{bad:02X} can type or trigger something — only modifiers, lock keys, Pause and F13-F24 are allowed"
        ));
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

/// Tick of the most recent system-wide input event, from the same clock as
/// `GetTickCount`.
fn last_input_tick() -> u64 {
    let mut lii = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    unsafe {
        let _ = GetLastInputInfo(&mut lii);
    }
    lii.dwTime as u64
}

/// True when the system has seen input that cannot be accounted for by our own
/// last injected key. `SendInput` updates the same last-input timestamp the
/// user's typing does, so we allow a small window around our own injection and
/// treat anything newer than that as genuine user input.
fn real_input_since_our_last_inject() -> bool {
    const SLACK_MS: u64 = 60;
    let ours = LAST_INJECT_TICK.load(Ordering::Relaxed);
    if ours == 0 {
        return false;
    }
    last_input_tick().wrapping_sub(ours) > SLACK_MS
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

/// Marker stamped into `dwExtraInfo` on every key we synthesise. `GetLastInputInfo`
/// cannot tell our input from the user's — both just bump the same timestamp —
/// so instead of trying to read intent out of the idle clock we record what we
/// injected ourselves and compare against that. Value is arbitrary; it only has
/// to be unlikely to collide with another tool's marker.
const CG_INJECTED_TAG: usize = 0x4347_4143;

/// `GetTickCount` at the moment we last injected a key. Anything that moves the
/// idle clock without matching this is the user.
static LAST_INJECT_TICK: AtomicU64 = AtomicU64::new(0);

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
                dwExtraInfo: CG_INJECTED_TAG,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
    LAST_INJECT_TICK.store(unsafe { GetTickCount() } as u64, Ordering::Relaxed);
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
        let key = &cfg.safe_keys[rng.gen_range(0..cfg.safe_keys.len())];
        let hold = rand_range(&mut rng, cfg.hold_min_ms, cfg.hold_max_ms);
        press_combo(&key.vks, hold);

        let gap = rand_range(&mut rng, cfg.press_gap_min_ms, cfg.press_gap_max_ms);
        std::thread::sleep(Duration::from_millis(gap));

        // Did anything OTHER than our own press touch the input clock during
        // that gap? `GetLastInputInfo` is updated by our SendInput too, so the
        // previous comparison of idle-before vs idle-after could never fire:
        // after a press idle_ms() is ~0 whether the last event was ours or the
        // user's. Comparing the last-input timestamp against the tick of our
        // own last injection separates the two — if the machine saw input
        // measurably newer than anything we sent, the user is back, so stop
        // rather than fighting them for the keyboard.
        if real_input_since_our_last_inject() {
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

