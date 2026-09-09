//! Native, cheap read of live capture-protection state.
//!
//! Windows lets ANY process READ a window's display-affinity flag (only SETTING
//! it cross-process is blocked). So the monitor can poll status natively here and
//! only shell out to the injection engine when a window is actually unprotected.

use serde::Serialize;
use std::collections::HashMap;

use windows::Win32::Foundation::{BOOL, CloseHandle, HWND, LPARAM, RECT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, EnumWindows, GetClassNameW, GetForegroundWindow, GetWindow,
    GetWindowDisplayAffinity, GetWindowLongW, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindowVisible, SetForegroundWindow, SetWindowPos,
    ShowWindow, GWL_EXSTYLE, GW_OWNER, HWND_NOTOPMOST, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, SW_RESTORE, SW_SHOW, WS_EX_TOOLWINDOW,
};
use windows::core::PWSTR;
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentThreadId, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// WDA_EXCLUDEFROMCAPTURE — window is visible on screen but absent from capture.
const WDA_EXCLUDE: u32 = 0x11;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureStatus {
    /// The app isn't running at all (no process by that name).
    NotRunning,
    /// The process IS running, but no window of it is countable — minimized to
    /// tray (benign), or we cannot see its windows at all: different session,
    /// elevation/UIPI mismatch, or the exe was renamed by an update. The last
    /// two mean the user is exposed, so this must never be shown as reassuring.
    NoWindows,
    /// Every matching window is excluded from capture.
    Protected,
    /// Some matching windows are protected, some are not.
    Partial,
    /// Matching windows exist but none are protected (capturable).
    Unprotected,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct TargetProbe {
    pub status: CaptureStatus,
    pub windows_total: usize,
    pub windows_protected: usize,
}

/// A window that matched a target's filters.
#[derive(Clone, Copy)]
pub struct MatchedWindow {
    pub hwnd: HWND,
}

/// The screen rect (left, top, right, bottom) of a window, if it can be read.
pub fn window_rect(h: HWND) -> Option<(i32, i32, i32, i32)> {
    let mut r = RECT::default();
    unsafe { GetWindowRect(h, &mut r).ok()? };
    Some((r.left, r.top, r.right, r.bottom))
}

/// Find all top-level windows that match a target's process/class/title/pool rules.
/// This mirrors the injection engine's window-selection so status and actions agree.
pub fn matched_windows(
    process: &str,
    class: &str,
    title: &str,
    all_windows: bool,
) -> Vec<MatchedWindow> {
    matched_windows_in(process, class, title, all_windows, &process_map())
}

/// `matched_windows` against an already-taken process snapshot. Snapshotting the
/// process table costs ~9ms (vs ~0.1ms for EnumWindows), so a caller probing
/// several targets in one pass should take the map ONCE and reuse it here rather
/// than paying that cost per target. See `monitor.rs`.
pub fn matched_windows_in(
    process: &str,
    class: &str,
    title: &str,
    all_windows: bool,
    pids: &HashMap<u32, String>,
) -> Vec<MatchedWindow> {
    let want_proc = strip_exe(process);
    let title_lc = title.to_ascii_lowercase();
    let mut out = Vec::new();

    for h in candidate_windows() {
        let visible = unsafe { IsWindowVisible(h).as_bool() };
        let has_title = unsafe { GetWindowTextLengthW(h) } > 0;

        let in_pool = if all_windows {
            visible
        } else if !class.is_empty() || !title.is_empty() {
            true // a class/title filter lets us safely scan hidden/untitled windows too
        } else {
            visible && has_title
        };
        if !in_pool {
            continue;
        }

        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(h, Some(&mut pid as *mut u32)) };
        match pids.get(&pid) {
            Some(name) if *name == want_proc => {}
            _ => continue,
        }
        if !class.is_empty() && !class_name(h).eq_ignore_ascii_case(class) {
            continue;
        }
        if !title.is_empty() && !window_title(h).to_ascii_lowercase().contains(&title_lc) {
            continue;
        }

        out.push(MatchedWindow { hwnd: h });
    }
    out
}

/// True when an exclusive full-screen (D3D) app is running — WDA_EXCLUDEFROMCAPTURE
/// is enforced by the desktop compositor, which such apps bypass, so protection
/// silently does nothing there. Used to surface a "run borderless" hint.
pub fn exclusive_fullscreen_active() -> bool {
    use windows::Win32::UI::Shell::{SHQueryUserNotificationState, QUNS_RUNNING_D3D_FULL_SCREEN};
    unsafe {
        matches!(
            SHQueryUserNotificationState(),
            Ok(state) if state == QUNS_RUNNING_D3D_FULL_SCREEN
        )
    }
}

/// A window worth reacting to when it appears: one the probe would also count
/// (see `candidate_windows`), and big enough to be a real window rather than a
/// tiny message-only helper. The size floor is deliberately low so thin floating
/// toolbars (e.g. a 160x28 tracker widget) are still covered.
///
/// This deliberately shares `is_top_level`/`is_user_dialog` with the probe: the
/// event path and the status path must agree about what a window IS, or we react
/// to windows we never count (or worse, count windows we never react to).
pub fn is_substantial_window(h: HWND) -> bool {
    unsafe {
        if !IsWindowVisible(h).as_bool() {
            return false;
        }
        if !(is_top_level(h) || is_user_dialog(h)) {
            return false;
        }
        let mut r = RECT::default();
        if GetWindowRect(h, &mut r).is_err() {
            return false;
        }
        // A window shown at 0x0 and sized a moment later (common for Chromium /
        // Electron surfaces) still counts — rejecting it here would hand it to
        // the slow backstop poll instead of the instant path.
        let (w, hgt) = (r.right - r.left, r.bottom - r.top);
        (w == 0 && hgt == 0) || (w >= 40 && hgt >= 16)
    }
}

/// Inspect the live windows of a target and report protection state.
pub fn probe(process: &str, class: &str, title: &str, all_windows: bool) -> TargetProbe {
    probe_in(process, class, title, all_windows, &process_map())
}

/// `probe` against an already-taken process snapshot — see `matched_windows_in`.
pub fn probe_in(
    process: &str,
    class: &str,
    title: &str,
    all_windows: bool,
    pids: &HashMap<u32, String>,
) -> TargetProbe {
    let wins = matched_windows_in(process, class, title, all_windows, pids);
    let total = wins.len();
    let protected = wins.iter().filter(|w| affinity(w.hwnd) == WDA_EXCLUDE).count();

    let status = if total == 0 {
        // No countable window. Two very different situations hide here, and
        // conflating them is how a privacy tool goes quiet while you are
        // exposed: the app may genuinely not be running (fine), or it may be
        // running and we simply cannot see its windows — a different session,
        // an elevation/UIPI mismatch, or a process rename after an update.
        // The caller must be able to tell those apart, so say which it is.
        if pids.values().any(|n| *n == strip_exe(process)) {
            CaptureStatus::NoWindows
        } else {
            CaptureStatus::NotRunning
        }
    } else if protected == total {
        CaptureStatus::Protected
    } else if protected == 0 {
        CaptureStatus::Unprotected
    } else {
        CaptureStatus::Partial
    };

    TargetProbe {
        status,
        windows_total: total,
        windows_protected: protected,
    }
}

// --- window enumeration -------------------------------------------------------

unsafe extern "system" fn collect_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out = &mut *(lparam.0 as *mut Vec<HWND>);
    out.push(hwnd);
    BOOL(1)
}

/// Every window eligible to be counted for a target: all unowned top-levels,
/// PLUS owned windows that are real user-facing dialogs (see `is_user_dialog`).
///
/// Owned windows used to be dropped wholesale, which meant a modal dialog or
/// popup could sit on screen unprotected while the target still reported
/// "Protected N/N" — the dialog was never in N. It is counted now.
fn candidate_windows() -> Vec<HWND> {
    let mut all: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(collect_cb), LPARAM(&mut all as *mut _ as isize));
    }
    all.into_iter()
        .filter(|&h| is_top_level(h) || is_user_dialog(h))
        .collect()
}

/// Top-level == has no owner window (GetWindow(GW_OWNER) is null).
fn is_top_level(h: HWND) -> bool {
    unsafe {
        match GetWindow(h, GW_OWNER) {
            Ok(owner) => owner == HWND::default(),
            Err(_) => true,
        }
    }
}

/// Is this OWNED window a real dialog the user can see, rather than one of the
/// many invisible helper windows every process carries?
///
/// Measured on a live desktop: of 539 windows, 245 were owned and NOT ONE of
/// them was visible — 142 `IME`, 80 `tooltips_class32`, 30 `MSCTFIME UI`, plus a
/// few Qt/Xaml popup site-bridges. Counting all owned windows would therefore
/// have added 245 permanently-unprotected windows and pinned every target to
/// "Partial" forever — a false RED, which destroys trust just as surely as a
/// false green.
///
/// So the test is "is it on screen and does it name itself", not a denylist of
/// known helper classes (such a list rots as Windows adds classes, and every
/// miss is a false red):
///   * visible          — excludes all 245 helpers observed
///   * not DWM-cloaked  — excludes suspended/off-screen UWP surfaces, which
///                        report visible while not actually being on screen
///   * not a tool window— excludes palettes/tooltips by their declared intent
///   * has a title      — a real dialog names itself (note IME/MSCTFIME DO have
///                        titles, so this alone would NOT have separated them)
fn is_user_dialog(h: HWND) -> bool {
    unsafe {
        if !IsWindowVisible(h).as_bool() {
            return false;
        }
        if is_cloaked(h) {
            return false;
        }
        let ex = GetWindowLongW(h, GWL_EXSTYLE) as u32;
        if ex & WS_EX_TOOLWINDOW.0 != 0 {
            return false;
        }
        GetWindowTextLengthW(h) > 0
    }
}

/// DWM "cloaked" — the window is composed but deliberately not shown (a
/// suspended UWP surface, another virtual desktop). `IsWindowVisible` still
/// reports true for these, so it has to be asked separately.
fn is_cloaked(h: HWND) -> bool {
    // Declared here rather than pulled from `windows::Win32::Graphics::Dwm`,
    // which would mean enabling another crate feature for a single call.
    #[link(name = "dwmapi")]
    unsafe extern "system" {
        fn DwmGetWindowAttribute(
            hwnd: HWND,
            attr: u32,
            value: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    const DWMWA_CLOAKED: u32 = 14;

    let mut cloaked: u32 = 0;
    unsafe {
        let hr = DwmGetWindowAttribute(
            h,
            DWMWA_CLOAKED,
            &mut cloaked as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
        hr == 0 && cloaked != 0
    }
}

// --- per-window reads ---------------------------------------------------------

fn affinity(h: HWND) -> u32 {
    let mut aff: u32 = 0;
    match unsafe { GetWindowDisplayAffinity(h, &mut aff) } {
        Ok(_) => aff,
        Err(_) => 0,
    }
}

fn class_name(h: HWND) -> String {
    let mut buf = [0u16; 256];
    let n = unsafe { GetClassNameW(h, &mut buf) };
    if n <= 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

fn window_title(h: HWND) -> String {
    let len = unsafe { GetWindowTextLengthW(h) };
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let n = unsafe { GetWindowTextW(h, &mut buf) };
    String::from_utf16_lossy(&buf[..n as usize])
}

// --- process table ------------------------------------------------------------

/// Map every running pid to its lowercase base process name (no .exe).
fn process_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return map,
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = wstr_to_string(&entry.szExeFile);
                map.insert(entry.th32ProcessID, strip_exe(&name));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    map
}

fn strip_exe(name: &str) -> String {
    let lc = name.to_ascii_lowercase();
    lc.strip_suffix(".exe").unwrap_or(&lc).to_string()
}

/// Every running pid whose base name matches `process` (no .exe). Used by the
/// hook engine to map the helper DLL into each instance of a target.
pub fn pids_for_process(process: &str) -> Vec<u32> {
    pids_for_process_in(process, &process_map())
}

/// `pids_for_process` against an already-taken snapshot — see `matched_windows_in`.
pub fn pids_for_process_in(process: &str, pids: &HashMap<u32, String>) -> Vec<u32> {
    let want = strip_exe(process);
    pids.iter()
        .filter(|(_, n)| **n == want)
        .map(|(pid, _)| *pid)
        .collect()
}

/// Take one process-table snapshot for a caller that is about to probe several
/// targets. See `matched_windows_in` for why this matters.
pub fn process_snapshot() -> HashMap<u32, String> {
    process_map()
}

/// Scan running processes for the first one matching any name in `names`
/// (case-insensitive, ".exe" optional). Returns the matched name (as given in
/// `names`, for display) and its pid. Used by the tracker-software detector.
pub fn find_any_process(names: &[String]) -> Option<(String, u32)> {
    let map = process_map();
    for want in names {
        let key = strip_exe(want);
        if let Some((&pid, _)) = map.iter().find(|(_, n)| **n == key) {
            return Some((want.clone(), pid));
        }
    }
    None
}

// --- app-type detection -------------------------------------------------------

/// What we learned about an app and which protection method suits it best.
#[derive(Debug, Clone, Serialize)]
pub struct AppTypeInfo {
    /// "electron-unpacked" | "electron-packed" | "native" | "not-running"
    pub kind: String,
    /// "electron-patch" | "inject"
    pub recommended_method: String,
    pub exe_path: Option<String>,
    pub note: String,
    pub running: bool,
}

/// Classify a process by inspecting a running instance: Electron apps can protect
/// themselves (best), everything else uses injection.
pub fn detect(process: &str) -> AppTypeInfo {
    let pid = find_pid(process);
    let running = pid.is_some();
    let exe = pid.and_then(exe_path);

    if let Some(path) = &exe {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let res = dir.join("resources");
            if res.join("app").join("package.json").exists() {
                return AppTypeInfo {
                    kind: "electron-unpacked".into(),
                    recommended_method: "electron-patch".into(),
                    exe_path: exe.clone(),
                    note: "Electron app — it can protect itself (permanent, no injection, no AV risk).".into(),
                    running,
                };
            }
            if res.join("app.asar").exists() {
                return AppTypeInfo {
                    kind: "electron-packed".into(),
                    recommended_method: "inject".into(),
                    exe_path: exe.clone(),
                    note: "Electron app but asar-packed — self-patch isn't possible, using injection.".into(),
                    running,
                };
            }
        }
        return AppTypeInfo {
            kind: "native".into(),
            recommended_method: "inject".into(),
            exe_path: exe.clone(),
            note: "Native app — injection show-through is the best available method.".into(),
            running,
        };
    }

    AppTypeInfo {
        kind: "not-running".into(),
        recommended_method: "inject".into(),
        exe_path: None,
        note: "App isn't running — start it, then Detect. Defaulting to injection.".into(),
        running,
    }
}

fn find_pid(process: &str) -> Option<u32> {
    let want = strip_exe(process);
    process_map().into_iter().find(|(_, n)| *n == want).map(|(pid, _)| pid)
}

/// Lowercase base process name (no .exe) for a single pid — cheap enough to call
/// per window-event without snapshotting every process.
pub fn process_base_name(pid: u32) -> Option<String> {
    let path = exe_path(pid)?;
    let file = std::path::Path::new(&path)
        .file_name()?
        .to_string_lossy()
        .to_string();
    Some(strip_exe(&file))
}

/// The directory holding a running process's exe — used to locate an Electron
/// app's install root from a live instance.
pub fn process_exe_dir(pid: u32) -> Option<std::path::PathBuf> {
    let path = exe_path(pid)?;
    std::path::Path::new(&path).parent().map(|p| p.to_path_buf())
}

fn exe_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let res = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        match res {
            Ok(_) => Some(String::from_utf16_lossy(&buf[..len as usize])),
            Err(_) => None,
        }
    }
}

fn wstr_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ---------------------------------------------------------------------------
// Forcing our OWN window to the foreground
// ---------------------------------------------------------------------------
//
// Windows refuses SetForegroundWindow from a process that doesn't own the
// foreground (the foreground-lock rules). We hit that constantly: the tray
// click is delivered by explorer.exe, and when Windows Guard runs elevated
// while explorer is not, UIPI blocks the activation hand-off outright. So a
// plain `show() + set_focus()` can leave the window hidden or buried with no
// error anyone can see.
//
// These helpers are the OS-level ground truth (`is_window_visible`) and the
// escalating workaround (`force_foreground`) used by `show_main`.

/// True when the window has WS_VISIBLE set — the real state as the OS sees it,
/// not what an async Tauri call claimed. This is what we verify against.
pub fn is_window_visible(h: HWND) -> bool {
    unsafe { IsWindowVisible(h).as_bool() }
}

/// Adopt a window handle that came from Tauri.
///
/// Tauri links its own (newer) build of the `windows` crate, so the `HWND` it
/// returns is a distinct Rust type from ours even though both are the same
/// pointer-sized OS handle. Convert through the raw pointer at the boundary.
pub fn hwnd_from_raw(raw: isize) -> HWND {
    HWND(raw as *mut core::ffi::c_void)
}

/// True when the window is minimized (iconic).
pub fn is_window_minimized(h: HWND) -> bool {
    unsafe { IsIconic(h).as_bool() }
}

/// Native show + restore, bypassing Tauri's async path entirely.
///
/// `ShowWindow` is a direct, synchronous user32 call on our own window, so it
/// isn't subject to the IPC round-trip whose error Tauri drops. Restores first
/// when iconic so a hidden-AND-minimized window comes back at its old size
/// rather than staying collapsed.
pub fn show_window_native(h: HWND) {
    unsafe {
        if IsIconic(h).as_bool() {
            let _ = ShowWindow(h, SW_RESTORE);
        } else {
            let _ = ShowWindow(h, SW_SHOW);
        }
    }
}

/// Drag a window to the foreground despite the foreground-activation rules.
///
/// Escalating sequence, cheapest first:
///   1. plain `SetForegroundWindow` — works when we already own the foreground;
///   2. `AttachThreadInput` to the current foreground thread, which puts us in
///      the same input queue and makes the activation legal, then retry;
///   3. the topmost flip — briefly mark the window HWND_TOPMOST and undo it,
///      which raises the window even when activation itself stays refused.
///
/// Step 3 is the one that saves us under UIPI (elevated app, unelevated
/// explorer): we may not be allowed to *focus*, but we can still be *seen*.
/// Returns true once the window is actually the foreground window.
pub fn force_foreground(h: HWND) -> bool {
    unsafe {
        if SetForegroundWindow(h).as_bool() && GetForegroundWindow() == h {
            return true;
        }

        let fg = GetForegroundWindow();
        if !fg.is_invalid() && fg != h {
            let fg_thread = GetWindowThreadProcessId(fg, None);
            let our_thread = GetCurrentThreadId();
            if fg_thread != 0 && fg_thread != our_thread {
                let attached = AttachThreadInput(our_thread, fg_thread, true).as_bool();
                let _ = SetForegroundWindow(h);
                let _ = BringWindowToTop(h);
                if attached {
                    let _ = AttachThreadInput(our_thread, fg_thread, false);
                }
                if GetForegroundWindow() == h {
                    return true;
                }
            }
        }

        // Last resort: raise it visually even if activation stays refused.
        let flags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;
        let _ = SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, flags);
        let _ = SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, flags);
        let _ = BringWindowToTop(h);

        GetForegroundWindow() == h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C2 predicate must not sweep in the OS helper windows every process
    /// carries. Measured on a live desktop: 245 of 539 windows were owned and
    /// NONE were visible, so a correct rule adds none of them.
    #[test]
    fn user_dialog_rule_excludes_invisible_helpers() {
        let mut owned = 0usize;
        let mut owned_counted = 0usize;
        for h in {
            let mut all: Vec<HWND> = Vec::new();
            unsafe {
                let _ = EnumWindows(Some(collect_cb), LPARAM(&mut all as *mut _ as isize));
            }
            all
        } {
            if is_top_level(h) {
                continue;
            }
            owned += 1;
            if is_user_dialog(h) {
                owned_counted += 1;
                // Anything we DO count must be visible and titled.
                assert!(unsafe { IsWindowVisible(h).as_bool() });
                assert!(unsafe { GetWindowTextLengthW(h) } > 0);
            }
        }
        eprintln!("owned={owned} counted_as_dialog={owned_counted}");
    }

    /// `is_substantial_window` and the probe must agree about what a window is.
    #[test]
    fn event_path_agrees_with_probe_pool() {
        let mut all: Vec<HWND> = Vec::new();
        unsafe {
            let _ = EnumWindows(Some(collect_cb), LPARAM(&mut all as *mut _ as isize));
        }
        for h in all {
            if is_substantial_window(h) {
                assert!(
                    is_top_level(h) || is_user_dialog(h),
                    "event path accepted a window the probe would never count"
                );
            }
        }
    }
}
