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
    EnumWindows, GetClassNameW, GetWindow, GetWindowDisplayAffinity, GetWindowRect,
    GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, GW_OWNER,
};
use windows::core::PWSTR;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// WDA_EXCLUDEFROMCAPTURE — window is visible on screen but absent from capture.
const WDA_EXCLUDE: u32 = 0x11;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureStatus {
    /// No matching window is currently open (app closed or minimized to tray).
    NotRunning,
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
    let want_proc = strip_exe(process);
    let pids = process_map();
    let title_lc = title.to_ascii_lowercase();
    let mut out = Vec::new();

    for h in top_level_windows() {
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

/// A visible window big enough to be a real window (main/widget/dialog), while
/// skipping tiny message-only/helper windows. The floor is deliberately low so
/// thin floating toolbars (e.g. a 160x28 tracker widget) are still covered.
pub fn is_substantial_window(h: HWND) -> bool {
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

/// Inspect the live windows of a target and report protection state.
pub fn probe(process: &str, class: &str, title: &str, all_windows: bool) -> TargetProbe {
    let wins = matched_windows(process, class, title, all_windows);
    let total = wins.len();
    let protected = wins.iter().filter(|w| affinity(w.hwnd) == WDA_EXCLUDE).count();

    let status = if total == 0 {
        CaptureStatus::NotRunning
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

fn top_level_windows() -> Vec<HWND> {
    let mut all: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(collect_cb), LPARAM(&mut all as *mut _ as isize));
    }
    all.into_iter().filter(|&h| is_top_level(h)).collect()
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
    let want = strip_exe(process);
    process_map()
        .into_iter()
        .filter(|(_, n)| *n == want)
        .map(|(pid, _)| pid)
        .collect()
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
