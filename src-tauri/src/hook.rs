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
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows::core::{s, w, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_HOOK_NEEDS_HMOD, ERROR_INVALID_HOOK_HANDLE, HMODULE,
    HWND, LPARAM, WIN32_ERROR, WPARAM,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
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
    UnhookAll(Sender<()>),
}

static TX: OnceLock<Sender<Cmd>> = OnceLock::new();

/// Why a target's hooks couldn't be installed. The distinction matters to the
/// user: `Privilege` is fixable by restarting elevated, `Bitness` never is —
/// telling someone to elevate for a 32-bit target sends them on a chase that
/// cannot work, and they conclude the app is broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailKind {
    /// ERROR_ACCESS_DENIED — we lack the rights to hook that process (typically
    /// running unelevated against an elevated/protected target).
    Privilege,
    /// A 64-bit helper cannot be mapped into a 32-bit process (or vice versa).
    Bitness,
    /// The helper module itself couldn't be used (unreadable, untrusted, bad handle).
    Module,
    Other(u32),
}

impl FailKind {
    /// Classify a `SetWindowsHookExW` failure for `pid`.
    ///
    /// Bitness is deliberately checked FIRST and independently of the error
    /// code: Windows does not report an architecture mismatch distinctly (it
    /// commonly surfaces as access-denied), so trusting the code alone would
    /// tell a user with a 32-bit app to "restart elevated" — a fix that can
    /// never work for them.
    fn classify(pid: u32, err: u32) -> FailKind {
        if is_arch_mismatch(pid) {
            return FailKind::Bitness;
        }
        match WIN32_ERROR(err) {
            ERROR_ACCESS_DENIED => FailKind::Privilege,
            ERROR_HOOK_NEEDS_HMOD | ERROR_INVALID_HOOK_HANDLE => FailKind::Module,
            _ => FailKind::Other(err),
        }
    }
}

/// Whether `pid`'s architecture differs from ours, which makes mapping our
/// helper into it impossible. Returns false when it can't be determined, so an
/// unreadable process is never misreported as a bitness problem.
fn is_arch_mismatch(pid: u32) -> bool {
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut target_wow64 = windows::Win32::Foundation::BOOL(0);
        let ok = IsWow64Process(h, &mut target_wow64).is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(h);
        if !ok {
            return false;
        }
        // We are a 64-bit binary, so a WOW64 (32-bit) target is a mismatch.
        // On a 32-bit host the comparison inverts, hence the cfg.
        #[cfg(target_pointer_width = "64")]
        {
            target_wow64.as_bool()
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            !target_wow64.as_bool()
        }
    }
}

/// Per-target hook health, aggregated **per PID, not per thread**: a target has
/// only failed when *zero* of its GUI threads hooked. Partial success is normal
/// and benign — GUI threads come and go.
#[derive(Debug, Clone)]
struct TargetHealth {
    installed: usize,
    failed: usize,
    kind: Option<FailKind>,
    /// Set while a fully-failed target is backing off, so a permanently-failing
    /// process stops re-issuing the identical failing call every monitor tick.
    retry_after: Option<Instant>,
    backoff: Duration,
}

impl Default for TargetHealth {
    fn default() -> Self {
        TargetHealth {
            installed: 0,
            failed: 0,
            kind: None,
            retry_after: None,
            backoff: BACKOFF_MIN,
        }
    }
}

const BACKOFF_MIN: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

/// Health of every PID we've tried to hook, readable by the UI layer.
static HEALTH: Mutex<Option<HashMap<u32, TargetHealth>>> = Mutex::new(None);

/// One-line reason the engine is degraded, or `None` when it's healthy.
///
/// "Degraded" means at least one target we were asked to protect has **zero**
/// working hooks — i.e. the host would otherwise report it as protected while
/// nothing is actually excluded from capture. Returns the most actionable
/// reason when several targets fail for different causes.
pub fn degraded_reason() -> Option<String> {
    let guard = HEALTH.lock().ok()?;
    let map = guard.as_ref()?;

    let failed: Vec<(&u32, &TargetHealth)> = map
        .iter()
        .filter(|(_, h)| h.installed == 0 && h.failed > 0)
        .collect();
    if failed.is_empty() {
        return None;
    }
    let total_attempted = map.values().filter(|h| h.installed > 0 || h.failed > 0).count();
    let wholesale = failed.len() == total_attempted && total_attempted > 0;

    // Privilege is the most actionable, so it wins when causes are mixed.
    let kind = failed
        .iter()
        .find(|(_, h)| h.kind == Some(FailKind::Privilege))
        .or_else(|| failed.iter().find(|(_, h)| h.kind == Some(FailKind::Module)))
        .or_else(|| failed.first())
        .and_then(|(_, h)| h.kind);

    let n = failed.len();
    let scope = if wholesale {
        "No app could be protected".to_string()
    } else if n == 1 {
        "1 app could not be protected".to_string()
    } else {
        format!("{n} apps could not be protected")
    };

    Some(match kind {
        Some(FailKind::Privilege) => format!(
            "{scope} — Windows Guard is running without administrator rights. \
             Restart it elevated to protect these apps."
        ),
        Some(FailKind::Bitness) => format!(
            "{scope} — the app is 32-bit and this build's helper is 64-bit, so it \
             cannot be loaded into it. Restarting elevated will not help."
        ),
        Some(FailKind::Module) => format!(
            "{scope} — the protection helper could not be loaded. It may be \
             missing, blocked, or untrusted."
        ),
        Some(FailKind::Other(e)) => format!("{scope} — Windows error {e} while installing the hook."),
        None => scope,
    })
}

/// Extract + trust the DLL, load it, resolve the hook proc, and start the owner
/// thread. Returns Err (protection unavailable) if the DLL can't be prepared.
///
/// Safe (and cheap) to call repeatedly: once the engine is up this is a no-op,
/// and a **failed** attempt leaves nothing behind, so calling again genuinely
/// retries. That matters because the conditions that make init fail — losing an
/// elevation race at logon, a helper file briefly locked — are transient, and a
/// permanently dead engine that still reports itself as monitoring is exactly
/// the invisible failure this app must not have.
pub fn init() -> Result<(), String> {
    if TX.get().is_some() {
        return Ok(());
    }
    // Serialize retries: without this, two callers could both pass the check
    // above and each spawn an owner thread, orphaning one of them.
    static INIT_LOCK: Mutex<()> = Mutex::new(());
    let _init = INIT_LOCK.lock().map_err(|_| "hook init lock poisoned")?;
    // Re-check under the lock — another caller may have finished while we waited.
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

                    // A target whose hooks all failed backs off, so a permanently
                    // failing process (e.g. we're unelevated and it isn't) stops
                    // re-issuing the identical failing call every monitor tick.
                    if in_backoff(pid) {
                        continue;
                    }

                    let entry = hooks.entry(pid).or_default();
                    // Drop bookkeeping for threads that have since exited, so the
                    // map can't grow without bound over long uptime and we don't
                    // keep posting to dead queues.
                    let live: HashSet<u32> = threads.iter().copied().collect();
                    entry.retain(|tid, hook| {
                        if live.contains(tid) || is_thread_alive(*tid) {
                            true
                        } else {
                            unsafe {
                                if let Err(e) = UnhookWindowsHookEx(*hook) {
                                    log_unhook_failure(pid, *tid, &e);
                                }
                            }
                            false
                        }
                    });

                    let mut installed = 0usize;
                    let mut failed = 0usize;
                    let mut kind: Option<FailKind> = None;

                    for tid in threads {
                        if !entry.contains_key(&tid) {
                            match unsafe { SetWindowsHookExW(WH_GETMESSAGE, pfn, hmod, tid) } {
                                Ok(hook) => {
                                    entry.insert(tid, hook);
                                }
                                Err(_) => {
                                    // Capture *why*: swallowing this is what turned a
                                    // recoverable error into a silent "protected" lie.
                                    let err = unsafe { GetLastError() }.0;
                                    failed += 1;
                                    kind.get_or_insert(FailKind::classify(pid, err));
                                    // Never signal a thread we failed to hook — the
                                    // helper isn't mapped there, so "protect" would
                                    // be a message nobody acts on, and the host would
                                    // carry on as though it had worked.
                                    continue;
                                }
                            }
                        }
                        if send_control(tid, ctrl, true) {
                            installed += 1;
                        } else {
                            // The hook exists but the thread has no queue / has gone:
                            // the order never arrived, so don't count it as protected.
                            failed += 1;
                        }
                    }

                    record_health(pid, installed, failed, kind);
                }
                Cmd::Unprotect(pid) => {
                    if let Some(entry) = hooks.get(&pid) {
                        for &tid in entry.keys() {
                            send_control(tid, ctrl, false);
                        }
                    }
                    // Not a failure state — the user asked for this.
                    record_health(pid, 0, 0, None);
                }
                Cmd::Prune(alive) => {
                    hooks.retain(|pid, threads| {
                        if alive.contains(pid) {
                            true
                        } else {
                            for (tid, hook) in threads.iter() {
                                unsafe {
                                    if let Err(e) = UnhookWindowsHookEx(*hook) {
                                        log_unhook_failure(*pid, *tid, &e);
                                    }
                                }
                            }
                            false
                        }
                    });
                    retain_health(&alive);
                }
                Cmd::UnhookAll(ack) => {
                    // SetWindowsHookEx explicitly documents that the installing
                    // process must UnhookWindowsHookEx before it terminates —
                    // an abrupt process::exit() while hooks are still mapped
                    // into another process (e.g. Cursor, via the ElectronPatch
                    // belt-and-suspenders hook below) can destabilize that
                    // process if it's mid-dispatch through the hook chain.
                    for (pid, threads) in hooks.iter() {
                        for (tid, hook) in threads.iter() {
                            unsafe {
                                if let Err(e) = UnhookWindowsHookEx(*hook) {
                                    log_unhook_failure(*pid, *tid, &e);
                                }
                            }
                        }
                    }
                    hooks.clear();
                    retain_health(&HashSet::new());
                    let _ = ack.send(());
                }
            }
        }
    });

    // `INIT_LOCK` above serializes callers, so this always wins; the fallback
    // just drops our sender, letting the redundant owner thread's `rx.recv()`
    // return Err so it exits instead of lingering.
    let _ = TX.set(tx);
    Ok(())
}

/// Post the protect/clear order to a hooked thread. Returns whether the message
/// was actually queued — `PostThreadMessage` fails if the thread has exited or
/// has no message queue, and treating that as success is how a lost order became
/// an invisible "protected" state.
fn send_control(tid: u32, ctrl: u32, protect: bool) -> bool {
    unsafe {
        // Wakes the thread's message loop AND carries the protect/clear order to
        // the injected hook proc, which reads it and (un)excludes the process.
        PostThreadMessageW(tid, ctrl, WPARAM(protect as usize), LPARAM(0)).is_ok()
    }
}

/// A thread we hold a hook for is still around if we can post it a benign
/// no-op message (WM_NULL). Cheap, and doesn't require a thread handle.
fn is_thread_alive(tid: u32) -> bool {
    unsafe { PostThreadMessageW(tid, 0, WPARAM(0), LPARAM(0)).is_ok() }
}

fn log_unhook_failure(pid: u32, tid: u32, e: &windows::core::Error) {
    eprintln!("[hook] UnhookWindowsHookEx failed for pid {pid} tid {tid}: {e}");
}

/// Record a Protect attempt's outcome for `pid` and advance/clear its backoff.
fn record_health(pid: u32, installed: usize, failed: usize, kind: Option<FailKind>) {
    let Ok(mut guard) = HEALTH.lock() else { return };
    let map = guard.get_or_insert_with(HashMap::new);
    let h = map.entry(pid).or_default();

    h.installed = installed;
    h.failed = failed;

    if installed > 0 {
        // Any working hook means the target is covered — partial success is
        // normal (GUI threads come and go), so clear the failure state.
        h.kind = None;
        h.retry_after = None;
        h.backoff = BACKOFF_MIN;
    } else if failed > 0 {
        h.kind = kind;
        h.retry_after = Some(Instant::now() + h.backoff);
        h.backoff = (h.backoff * 2).min(BACKOFF_MAX);
    }
}

/// True while `pid` is in a post-failure backoff window.
fn in_backoff(pid: u32) -> bool {
    let Ok(guard) = HEALTH.lock() else { return false };
    let Some(map) = guard.as_ref() else { return false };
    match map.get(&pid).and_then(|h| h.retry_after) {
        Some(t) => Instant::now() < t,
        None => false,
    }
}

/// Forget health for pids that are gone, so the map tracks live targets only.
fn retain_health(alive: &HashSet<u32>) {
    if let Ok(mut guard) = HEALTH.lock() {
        if let Some(map) = guard.as_mut() {
            map.retain(|pid, _| alive.contains(pid));
        }
    }
}

/// Whether the protection engine actually came up (helper prepared, loaded, and
/// the owner thread running).
///
/// Callers that report success to the user MUST check this first: when the
/// engine never initialised, `protect_process` silently no-ops, so reporting
/// "protection turned ON" would be a lie the user has no way to detect. Since a
/// failed `init()` used to be permanent for the session, that lie would repeat
/// every time they toggled, all day, from a dead engine.
pub fn is_ready() -> bool {
    TX.get().is_some()
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

/// Cleanly `UnhookWindowsHookEx` every hook we've installed in every target
/// process, and wait (briefly) for confirmation. MUST be called before this
/// process exits — see the note on `Cmd::UnhookAll`. Bounded wait so a stuck
/// owner thread can't hang shutdown indefinitely.
pub fn shutdown() {
    let Some(tx) = TX.get() else { return };
    let (ack_tx, ack_rx) = mpsc::channel();
    if tx.send(Cmd::UnhookAll(ack_tx)).is_ok() {
        let _ = ack_rx.recv_timeout(std::time::Duration::from_millis(1500));
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

    // Compare CONTENT, not just length. A same-size-but-different helper (an
    // update that happens to keep the size) would otherwise never be rewritten,
    // leaving a stale helper running silently — a bug that only ever shows up
    // after a release, on a user's machine, invisibly.
    let need_write = match std::fs::read(&path) {
        Ok(existing) => existing != HOOK_DLL,
        Err(_) => true,
    };
    if need_write {
        match std::fs::File::create(&path) {
            Ok(mut f) => f.write_all(HOOK_DLL).map_err(|e| e.to_string())?,
            Err(e) => {
                // Typically the old copy is still mapped into a running target,
                // so the file is locked. We fall back to the existing on-disk
                // helper, but this is NOT silently fine: if it differs from what
                // we embed, the engine is running stale code.
                if std::fs::metadata(&path).is_err() {
                    return Err(format!("cannot write helper to {}: {e}", path.display()));
                }
                eprintln!(
                    "[hook] helper at {} is stale and could not be replaced ({e}); \
                     it is likely locked by a running protected app. Restart those \
                     apps to pick up the updated helper.",
                    path.display()
                );
            }
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

    // A failed grant is not fatal (only AppContainer targets need it), but it
    // must not be silent: without it a sandboxed Store app such as WhatsApp
    // simply cannot load the helper, and the host would report it protected.
    match cmd.output() {
        Ok(out) if !out.status.success() => eprintln!(
            "[hook] icacls grant failed for {} ({}): {}",
            p.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => eprintln!("[hook] could not run icacls for {}: {e}", p.display()),
        _ => {}
    }
}
