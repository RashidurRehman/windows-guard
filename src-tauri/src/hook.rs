//! The non-flaggable protection engine: load a signed helper DLL into each target
//! via `SetWindowsHookEx(WH_GETMESSAGE, ...)` — the documented Windows injection
//! path used by IMEs and accessibility tools — instead of remote-thread shellcode.
//! The DLL (see the `windows-guard-hook` crate) then excludes the target's own
//! windows from capture from the inside.
//!
//! All `SetWindowsHookEx`/`UnhookWindowsHookEx` calls run on one dedicated
//! owner thread that lives for the whole app, so hook handles are never orphaned
//! by a short-lived worker thread. Callers just send it commands over a channel.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write;
use std::sync::mpsc::{self, Sender};
use std::sync::OnceLock;

use windows::core::{s, w, PCWSTR};
use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, WPARAM};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostThreadMessageW,
    RegisterWindowMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, HOOKPROC, WH_GETMESSAGE,
};

/// The signed helper DLL, embedded so it ships as part of the (signed) exe and is
/// extracted to disk at runtime. Bytes are identical to the file we sign, so the
/// on-disk copy stays a verified-publisher binary.
const HOOK_DLL: &[u8] = include_bytes!("../hook/windows_guard_hook.dll");

/// Must match the DLL's `CONTROL_MSG_NAME`.
const CONTROL_MSG_NAME: PCWSTR = w!("CaptureGuardControl_v1");

enum Cmd {
    Protect(u32),
    Unprotect(u32),
    Prune(HashSet<u32>),
}

static TX: OnceLock<Sender<Cmd>> = OnceLock::new();

/// Extract + trust the DLL, load it, resolve the hook proc, and start the owner
/// thread. Returns Err (protection unavailable) if the DLL can't be prepared.
pub fn init() -> Result<(), String> {
    if TX.get().is_some() {
        return Ok(());
    }
    let path = extract_and_trust_dll()?;

    // Load the DLL into ourselves so we hold its module handle + a pointer to the
    // exported hook proc; Windows maps the same on-disk DLL into each target.
    let (hmod_raw, pfn_raw, ctrl) = unsafe {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let hmod = LoadLibraryW(PCWSTR(wide.as_ptr()))
            .map_err(|e| format!("LoadLibrary(hook dll) failed: {e}"))?;
        let proc = GetProcAddress(hmod, s!("WindowsGuardHookProc"))
            .ok_or("hook proc export not found")?;
        let ctrl = RegisterWindowMessageW(CONTROL_MSG_NAME);
        if ctrl == 0 {
            return Err("RegisterWindowMessage failed".into());
        }
        (hmod.0 as isize, proc as usize, ctrl)
    };

    let (tx, rx) = mpsc::channel::<Cmd>();
    std::thread::spawn(move || {
        // Rebuild the (Send-unfriendly) handles inside the owner thread.
        let hmod = HMODULE(hmod_raw as *mut c_void);
        let pfn: HOOKPROC = unsafe { std::mem::transmute::<usize, HOOKPROC>(pfn_raw) };
        // pid -> (thread id -> hook handle). We hook EVERY GUI thread of a target
        // and re-scan its threads on each Protect, so an app that is still spinning
        // up (e.g. a cold-starting Store app whose first UI thread isn't pumping
        // yet) still gets the DLL mapped via whichever thread pumps first, and
        // newly-created UI threads are picked up on the next monitor tick.
        let mut hooks: HashMap<u32, HashMap<u32, HHOOK>> = HashMap::new();

        while let Ok(cmd) = rx.recv() {
            match cmd {
                Cmd::Protect(pid) => {
                    let threads = gui_threads_of(pid);
                    if threads.is_empty() {
                        continue;
                    }
                    let entry = hooks.entry(pid).or_default();
                    for tid in threads {
                        if !entry.contains_key(&tid) {
                            if let Ok(hook) =
                                unsafe { SetWindowsHookExW(WH_GETMESSAGE, pfn, hmod, tid) }
                            {
                                entry.insert(tid, hook);
                            }
                            // (Err = bitness mismatch / access denied — just skip.)
                        }
                        send_control(tid, ctrl, true);
                    }
                }
                Cmd::Unprotect(pid) => {
                    if let Some(entry) = hooks.get(&pid) {
                        for &tid in entry.keys() {
                            send_control(tid, ctrl, false);
                        }
                    }
                }
                Cmd::Prune(alive) => {
                    hooks.retain(|pid, threads| {
                        if alive.contains(pid) {
                            true
                        } else {
                            for hook in threads.values() {
                                unsafe { let _ = UnhookWindowsHookEx(*hook); }
                            }
                            false
                        }
                    });
                }
            }
        }
    });

    let _ = TX.set(tx);
    Ok(())
}

fn send_control(tid: u32, ctrl: u32, protect: bool) {
    unsafe {
        // Wakes the thread's message loop AND carries the protect/clear order to
        // the injected hook proc, which reads it and (un)excludes the process.
        let _ = PostThreadMessageW(tid, ctrl, WPARAM(protect as usize), LPARAM(0));
    }
}

/// Ensure `pid` is hooked and its windows excluded from capture. Idempotent.
pub fn protect_process(pid: u32) {
    if let Some(tx) = TX.get() {
        let _ = tx.send(Cmd::Protect(pid));
    }
}

/// Tell `pid`'s helper to clear capture-exclusion (window becomes capturable
/// again). The hook stays installed so re-enabling is instant.
pub fn unprotect_process(pid: u32) {
    if let Some(tx) = TX.get() {
        let _ = tx.send(Cmd::Unprotect(pid));
    }
}

/// Protect every running instance of a process name (no .exe).
pub fn protect_target(process: &str) {
    for pid in crate::winapi::pids_for_process(process) {
        protect_process(pid);
    }
}

/// Clear protection on every running instance of a process name.
pub fn unprotect_target(process: &str) {
    for pid in crate::winapi::pids_for_process(process) {
        unprotect_process(pid);
    }
}

/// Drop hook bookkeeping for processes that have exited (their thread hooks are
/// already gone; this just unhooks + frees our map entries).
pub fn prune_dead(alive: HashSet<u32>) {
    if let Some(tx) = TX.get() {
        let _ = tx.send(Cmd::Prune(alive));
    }
}

// --- helpers -----------------------------------------------------------------

/// Every GUI thread of a process (threads that own a visible top-level window) —
/// we install a WH_GETMESSAGE hook on each so the DLL maps in via whichever one
/// pumps messages first. Hooking all of them (rather than just the first) is what
/// makes protection reliable for apps that are still initializing.
fn gui_threads_of(pid: u32) -> Vec<u32> {
    let mut ctx: (u32, Vec<u32>) = (pid, Vec::new());
    unsafe {
        let _ = EnumWindows(Some(collect_threads_cb), LPARAM(&mut ctx as *mut _ as isize));
    }
    ctx.1
}

unsafe extern "system" fn collect_threads_cb(
    h: HWND,
    l: LPARAM,
) -> windows::Win32::Foundation::BOOL {
    let ctx = &mut *(l.0 as *mut (u32, Vec<u32>));
    if IsWindowVisible(h).as_bool() {
        let mut pid = 0u32;
        let tid = GetWindowThreadProcessId(h, Some(&mut pid));
        if pid == ctx.0 && tid != 0 && !ctx.1.contains(&tid) {
            ctx.1.push(tid);
        }
    }
    windows::Win32::Foundation::BOOL(1)
}

/// Write the embedded DLL to `%LOCALAPPDATA%\Windows Guard`, and grant
/// read+execute to app packages so sandboxed Store apps (e.g. WhatsApp) can
/// load it too.
fn extract_and_trust_dll() -> Result<String, String> {
    let base = std::env::var("LOCALAPPDATA").map_err(|_| "no LOCALAPPDATA")?;
    let dir = std::path::Path::new(&base).join("Windows Guard");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("windows_guard_hook.dll");

    let need_write = match std::fs::metadata(&path) {
        Ok(m) => m.len() as usize != HOOK_DLL.len(),
        Err(_) => true,
    };
    if need_write {
        // If an old copy is still mapped in a running target the create can fail;
        // that's fine — the existing (same-name) file is what we'll load.
        if let Ok(mut f) = std::fs::File::create(&path) {
            f.write_all(HOOK_DLL).map_err(|e| e.to_string())?;
        }
    }

    grant_app_packages(&dir);
    grant_app_packages(&path);
    Ok(path.to_string_lossy().to_string())
}

/// `icacls <p> /grant *S-1-15-2-1:(RX) *S-1-15-2-2:(RX)` — ALL APPLICATION
/// PACKAGES + ALL RESTRICTED APPLICATION PACKAGES, so AppContainer processes can
/// read/execute the helper. No admin needed for files we own.
fn grant_app_packages(p: &std::path::Path) {
    use std::process::Command;
    #[cfg(windows)]
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new("icacls");
    cmd.arg(p.as_os_str())
        .arg("/grant")
        .arg("*S-1-15-2-1:(RX)")
        .arg("/grant")
        .arg("*S-1-15-2-2:(RX)");
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let _ = cmd.output();
}
