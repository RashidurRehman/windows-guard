//! Windows Guard in-process helper DLL.
//!
//! The main app maps this DLL into a target process the *documented, legitimate*
//! way — `SetWindowsHookEx(WH_GETMESSAGE, ...)` — instead of remote-thread
//! shellcode injection. Once mapped, this code runs INSIDE the target, so it can
//! legally call `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on the target's
//! own windows (the OS blocks that call cross-process, which is why injection was
//! ever needed). It also installs an in-process `SetWinEventHook` so any window
//! the target opens *later* (dialogs, popups, modals, floating widgets) is
//! excluded from capture the instant it appears — no polling.
//!
//! The host toggles protection by `PostThreadMessage`-ing a registered control
//! message to the hooked thread; the hook proc sees it and enables/clears
//! protection. All work happens in normal hook-proc context (never under loader
//! lock), and every static here is per-process, so no cross-process state.

#![cfg(windows)]

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};

use windows::core::w;
use windows::Win32::Foundation::{BOOL, HMODULE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, HWINEVENTHOOK};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, EnumWindows, GetWindowRect, GetWindowThreadProcessId, IsWindowVisible,
    RegisterWindowMessageW, SetWindowDisplayAffinity, EVENT_OBJECT_SHOW, HHOOK, MSG,
    WDA_EXCLUDEFROMCAPTURE, WDA_NONE, WINEVENT_OUTOFCONTEXT,
};

/// Enable/clear protection for the whole process. wParam: 1 = protect, 0 = clear.
/// Must match the string the host registers.
const CONTROL_MSG_NAME: windows::core::PCWSTR = w!("CaptureGuardControl_v1");

static INITED: AtomicBool = AtomicBool::new(false);
static PROTECTED: AtomicBool = AtomicBool::new(false);
static CONTROL_MSG: AtomicU32 = AtomicU32::new(0);
/// The in-process EVENT_OBJECT_SHOW hook handle, stored as isize (0 = none).
static WATCHER: AtomicIsize = AtomicIsize::new(0);

/// The exported hook procedure. Windows maps this DLL into the target and calls
/// this for every message the hooked thread retrieves.
#[no_mangle]
pub unsafe extern "system" fn WindowsGuardHookProc(
    code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if code >= 0 && lparam.0 != 0 {
        let msg = &*(lparam.0 as *const MSG);
        let ctrl = control_msg();
        if msg.message == ctrl {
            if msg.wParam.0 == 1 {
                enable_protection();
            } else {
                disable_protection();
            }
        } else if !INITED.load(Ordering::Relaxed) {
            // We were only ever mapped in because the host wanted protection ON,
            // so switch it on at the first opportunity.
            enable_protection();
        }
    }
    CallNextHookEx(HHOOK(core::ptr::null_mut()), code, wparam, lparam)
}

fn control_msg() -> u32 {
    let cached = CONTROL_MSG.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let m = unsafe { RegisterWindowMessageW(CONTROL_MSG_NAME) };
    CONTROL_MSG.store(m, Ordering::Relaxed);
    m
}

fn enable_protection() {
    INITED.store(true, Ordering::Relaxed);
    PROTECTED.store(true, Ordering::Relaxed);
    apply_all(true);
    install_watcher();
}

fn disable_protection() {
    INITED.store(true, Ordering::Relaxed);
    PROTECTED.store(false, Ordering::Relaxed);
    remove_watcher();
    apply_all(false);
}

/// Set (or clear) WDA_EXCLUDEFROMCAPTURE on every substantial top-level window
/// that belongs to THIS process — main window, floating widgets, owned dialogs
/// and modals are all top-level windows, so this one pass covers them all.
fn apply_all(protect: bool) {
    let aff = if protect { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
    let mut list: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(collect_cb), LPARAM(&mut list as *mut _ as isize));
    }
    let me = unsafe { GetCurrentProcessId() };
    for h in list {
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(h, Some(&mut pid)) };
        if pid != me || !substantial(h) {
            continue;
        }
        unsafe {
            let _ = SetWindowDisplayAffinity(h, aff);
        }
    }
}

unsafe extern "system" fn collect_cb(h: HWND, l: LPARAM) -> BOOL {
    let out = &mut *(l.0 as *mut Vec<HWND>);
    out.push(h);
    BOOL(1)
}

/// Visible and at least 40x16 — big enough to be a real window, small enough that
/// thin floating toolbars still qualify; skips tiny message-only helper windows.
fn substantial(h: HWND) -> bool {
    unsafe {
        if !IsWindowVisible(h).as_bool() {
            return false;
        }
        let mut r = RECT::default();
        if GetWindowRect(h, &mut r).is_err() {
            return false;
        }
        (r.right - r.left) >= 40 && (r.bottom - r.top) >= 16
    }
}

/// Watch THIS process for newly shown windows so dialogs/popups are excluded the
/// instant they appear. OUTOFCONTEXT events are delivered on the thread that
/// installed the hook (the hooked GUI thread), via its normal message loop.
fn install_watcher() {
    if WATCHER.load(Ordering::Acquire) != 0 {
        return;
    }
    let me = unsafe { GetCurrentProcessId() };
    let hook = unsafe {
        SetWinEventHook(
            EVENT_OBJECT_SHOW,
            EVENT_OBJECT_SHOW,
            HMODULE::default(),
            Some(win_event_proc),
            me, // only this process
            0,  // any thread
            WINEVENT_OUTOFCONTEXT,
        )
    };
    if hook.0.is_null() {
        return;
    }
    // Claim the slot atomically: two GUI threads can enter here at once, and a
    // plain store would orphan the loser's hook — a leaked handle inside the
    // user's browser, which we never get another chance to release.
    if WATCHER
        .compare_exchange(0, hook.0 as isize, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        unsafe {
            let _ = UnhookWinEvent(hook);
        }
    }
}

fn remove_watcher() {
    let raw = WATCHER.swap(0, Ordering::AcqRel);
    if raw != 0 {
        unsafe {
            let _ = UnhookWinEvent(HWINEVENTHOOK(raw as *mut c_void));
        }
    }
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
    // Window-level SHOW only (id_object 0 == OBJID_WINDOW).
    if event != EVENT_OBJECT_SHOW || id_object != 0 || hwnd.0.is_null() {
        return;
    }
    if !PROTECTED.load(Ordering::Relaxed) || !substantial(hwnd) {
        return;
    }
    let _ = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
}
