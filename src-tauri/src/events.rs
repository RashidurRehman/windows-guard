//! Event-driven detection of app launches / new windows.
//!
//! Instead of polling, we install a `SetWinEventHook` for `EVENT_OBJECT_SHOW`.
//! Windows calls us the instant any top-level window appears (an app opening,
//! restarting, or spawning a new window). This is in-process, needs no admin,
//! and costs ~nothing while idle — the monitor's slow poll stays only as a
//! safety backstop.

use crate::config::Method;
use crate::AppState;
use std::sync::OnceLock;
use tauri::{AppHandle, Emitter, Manager};
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, GetWindowThreadProcessId, KillTimer, SetTimer, TranslateMessage,
    EVENT_OBJECT_SHOW, MSG, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS, WM_TIMER,
};

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Install the window-show hook on a dedicated thread with its own message loop
/// (required for out-of-context hook delivery).
pub fn spawn(app: AppHandle) {
    let _ = APP.set(app.clone());
    std::thread::spawn(move || unsafe {
        let install = || {
            SetWinEventHook(
                EVENT_OBJECT_SHOW,
                EVENT_OBJECT_SHOW,
                HMODULE::default(),
                Some(win_event_proc),
                0, // all processes
                0, // all threads
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            )
        };

        let mut hook = install();
        if hook.is_invalid() {
            // Previously this failure was silent: the thread went straight into
            // its message loop and the app looked healthy while instant
            // detection did not exist. Say so — the 15s backstop is all that is
            // left, and the user should know their cover is slower than claimed.
            crate::push_log(
                &app,
                "error",
                "Instant window detection unavailable — falling back to the periodic check.",
            );
        }

        // Re-arm periodically. A WinEvent hook is per-session and can be dropped
        // by the OS across suspend/resume, a fast user switch, or a desktop
        // switch, WITHOUT telling us — the thread keeps pumping an empty queue
        // forever and every app launch silently falls back to the slow poll.
        // A cheap timer lets us notice and reinstall.
        let mut msg = MSG::default();
        let timer = SetTimer(None, 0, REARM_MS, None);
        loop {
            let got = GetMessageW(&mut msg, HWND::default(), 0, 0).0;
            if got <= 0 {
                break;
            }
            if msg.message == WM_TIMER {
                // Reinstall only when we know we have nothing valid. Hooks that
                // are still live are left strictly alone — tearing down a
                // working hook to replace it would open a real gap.
                if hook.is_invalid() {
                    hook = install();
                    if !hook.is_invalid() {
                        crate::push_log(&app, "info", "Instant window detection restored.");
                    }
                } else if !hook_is_alive() {
                    let _ = UnhookWinEvent(hook);
                    hook = install();
                    if !hook.is_invalid() {
                        crate::push_log(&app, "info", "Instant window detection re-armed.");
                    }
                }
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if timer != 0 {
            let _ = KillTimer(None, timer);
        }
        if !hook.is_invalid() {
            let _ = UnhookWinEvent(hook);
        }
    });
}

/// How often to check that the window-show hook is still installed.
const REARM_MS: u32 = 30_000;

/// Has our hook been delivering?
///
/// `SetWinEventHook` offers no "is this handle still valid" API, so liveness has
/// to be inferred, and the inference must be conservative in the right
/// direction. A quiet desktop (screen locked, user away) legitimately produces
/// no SHOW events, so "no events" alone does NOT mean the hook died — treating
/// it that way would reinstall the hook every 30s all night.
///
/// So we only suspect the hook when the desktop was demonstrably NOT idle and we
/// still saw nothing: real user input happened, yet no window-show event
/// arrived. Reinstalling is idempotent and cheap, so a false positive costs one
/// syscall, while a false negative costs silent loss of instant protection.
fn hook_is_alive() -> bool {
    use std::sync::atomic::Ordering;
    let seen = EVENTS_SEEN.swap(0, Ordering::Relaxed);
    if seen > 0 {
        return true;
    }
    // No events. Only call it dead if the user was actually active.
    idle_millis().map_or(true, |idle| idle >= REARM_MS as u64)
}

/// Milliseconds since the last real user input, or `None` if it can't be read.
fn idle_millis() -> Option<u64> {
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    unsafe {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if !GetLastInputInfo(&mut lii).as_bool() {
            return None;
        }
        Some(GetTickCount().wrapping_sub(lii.dwTime) as u64)
    }
}

/// Counts callbacks between re-arm checks; see `hook_is_alive`.
static EVENTS_SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    _id_child: i32,
    _thread: u32,
    _time: u32,
) {
    // Window-level SHOW events only (dialogs included — no top-level filter).
    if event != EVENT_OBJECT_SHOW || id_object != 0 || hwnd == HWND::default() {
        return;
    }
    // Proof-of-life for the re-arm check; counts every delivery, including ones
    // we go on to ignore, since any delivery means the hook is still installed.
    EVENTS_SEEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
    on_window_shown(hwnd, pid);
}

fn on_window_shown(hwnd: HWND, pid: u32) {
    let Some(app) = APP.get() else {
        return;
    };
    // Cheap size gate first — skips tiny helper windows without a process lookup.
    if !crate::winapi::is_substantial_window(hwnd) {
        return;
    }
    let name = match crate::winapi::process_base_name(pid) {
        Some(n) => n,
        None => return,
    };

    let target = {
        let st = app.state::<AppState>();
        // Never unwrap a poisoned lock here: this runs on the WinEvent thread,
        // and a panic would take instant detection down for the rest of the
        // session with nothing visible to say so.
        let cfg = match st.config.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !cfg.master_enabled {
            return;
        }
        cfg.targets
            .iter()
            .find(|t| t.enabled && t.process.to_ascii_lowercase().trim_end_matches(".exe") == name)
            .cloned()
    };
    let Some(t) = target else {
        return;
    };

    // Only the DLL-backed methods need the process hooked; hide-during-capture
    // does nothing persistent.
    if !matches!(t.method, Method::Inject | Method::ElectronPatch) {
        return;
    }

    // A window for this target appeared (launch, restart, or a new dialog/popup).
    // Ensure the owning process is hooked so the signed helper DLL excludes ALL
    // of its windows — main, floating widgets, owned dialogs/modals — from
    // capture. This just queues a request to the hook engine (instant); the DLL
    // itself also watches the process for further windows in-process.
    crate::hook::protect_process(pid);

    // Reflect the new state in the UI once the DLL has had a moment to apply.
    let app2 = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let st = app2.state::<AppState>();
        let statuses = {
            let cfg = match st.config.lock() {
                Ok(c) => c,
                Err(poisoned) => poisoned.into_inner(),
            };
            crate::snapshot(&cfg)
        };
        let _ = app2.emit("status-update", &statuses);
    });
}
