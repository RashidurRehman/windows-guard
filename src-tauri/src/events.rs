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
    DispatchMessageW, GetMessageW, GetWindowThreadProcessId, TranslateMessage, EVENT_OBJECT_SHOW,
    MSG, WINEVENT_OUTOFCONTEXT, WINEVENT_SKIPOWNPROCESS,
};

static APP: OnceLock<AppHandle> = OnceLock::new();

/// Install the window-show hook on a dedicated thread with its own message loop
/// (required for out-of-context hook delivery).
pub fn spawn(app: AppHandle) {
    let _ = APP.set(app);
    std::thread::spawn(|| unsafe {
        let hook = SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            HMODULE::default(),
            Some(win_event_proc),
            0, // all processes
            0, // all threads
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );

        // Pump messages so the OS can deliver hook callbacks to this thread.
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).0 > 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if !hook.is_invalid() {
            let _ = UnhookWinEvent(hook);
        }
    });
}

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
        let cfg = st.config.lock().unwrap();
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
            let cfg = st.config.lock().unwrap();
            crate::snapshot(&cfg)
        };
        let _ = app2.emit("status-update", &statuses);
    });
}
