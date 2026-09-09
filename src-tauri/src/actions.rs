//! Protection actions.
//!
//! The default apps are excluded from capture by the signed hook DLL (see
//! `hook.rs`) — the documented `SetWindowsHookEx` injection path, not
//! remote-thread shellcode. Electron apps additionally get a permanent self-patch
//! so they stay protected even when Windows Guard isn't running. The remaining
//! PowerShell scripts are non-injection helpers (Electron patch, app listing,
//! icons). Cheap status reads are done natively in `winapi.rs`.

use crate::config::{Method, Target};
use crate::hook;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The marker the Electron self-patch writes into the app's main bundle. Must
/// match `$marker` in Enable-ElectronContentProtection.ps1.
const ELECTRON_MARKER: &str = "capture-guard-content-protection";

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// State of an Electron app's permanent self-patch, tracked separately from the
/// observed capture status.
///
/// These are orthogonal on purpose. `CaptureStatus` says what the windows are
/// doing RIGHT NOW; `PatchState` says whether the on-disk patch that keeps them
/// that way still exists. An app update silently reverts the patch, so a target
/// can read "Protected" (the stale running process still has protection applied)
/// while the patch is gone and the NEXT launch will be fully capturable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatchState {
    /// This target isn't patched at all (not the electron-patch method).
    NotApplicable,
    /// The marker is missing from the app's main bundle — never applied, or an
    /// app update overwrote it. Needs re-applying.
    Absent,
    /// The patch IS on disk, but the running app predates it, so its windows
    /// are not protected yet. Honest amber: a full quit-and-relaunch activates
    /// it. Never reported as protected.
    PendingRestart,
    /// Patch on disk AND the live windows are excluded from capture.
    Active,
}

/// Is the Electron self-patch currently present in `process`'s main bundle?
///
/// Read straight from disk, deliberately INDEPENDENTLY of what the probe says.
/// The old code only re-applied the patch when the probe already reported
/// failure, which is circular: a still-running instance keeps reporting
/// "Protected" from a patch that has already been deleted from disk by an
/// update, so the condition that would trigger the fix never becomes true.
/// Returns `None` when the app can't be located (not installed / not the
/// unpacked layout the patch needs).
pub fn electron_patch_present(process: &str) -> Option<bool> {
    let main_js = electron_main_js(process)?;
    let text = fs::read_to_string(&main_js).ok()?;
    Some(text.contains(ELECTRON_MARKER))
}

/// Locate an Electron app's main bundle entry point, mirroring the search order
/// in Enable-ElectronContentProtection.ps1 (running instance first, then the
/// usual per-user/machine install roots).
fn electron_main_js(process: &str) -> Option<PathBuf> {
    let base = process.trim_end_matches(".exe");

    let mut roots: Vec<PathBuf> = Vec::new();
    // 1) from a running instance — authoritative for side-by-side installs.
    for pid in crate::winapi::pids_for_process(base) {
        if let Some(dir) = crate::winapi::process_exe_dir(pid) {
            roots.push(dir);
        }
    }
    // 2) the common install roots.
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        roots.push(Path::new(&local).join("Programs").join(base));
        roots.push(Path::new(&local).join("Programs").join(base.to_lowercase()));
    }
    if let Ok(pf) = std::env::var("PROGRAMFILES") {
        roots.push(Path::new(&pf).join(base));
    }

    for root in roots {
        let app_dir = root.join("resources").join("app");
        let pkg = app_dir.join("package.json");
        let Ok(text) = fs::read_to_string(&pkg) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let main_rel = json
            .get("main")
            .and_then(|m| m.as_str())
            .unwrap_or("main.js")
            .trim_start_matches("./");
        let main_js = app_dir.join(main_rel.replace('/', "\\"));
        if main_js.exists() {
            return Some(main_js);
        }
    }
    None
}

/// Paths to the (non-injection) helper scripts once written to the app data dir.
#[derive(Clone)]
pub struct Engine {
    pub electron_ps: PathBuf,
    pub hide_ps: PathBuf,
    pub apps_ps: PathBuf,
    pub icons_ps: PathBuf,
}

impl Engine {
    /// Write the embedded scripts into `dir` (refreshed each launch so an app
    /// update ships new engine code). Returns the resolved paths.
    pub fn install(dir: &Path) -> std::io::Result<Engine> {
        fs::create_dir_all(dir)?;
        let electron_ps = dir.join("Enable-ElectronContentProtection.ps1");
        let hide_ps = dir.join("Protect-WhatsAppCapture.ps1");
        let apps_ps = dir.join("List-InstalledApps.ps1");
        let icons_ps = dir.join("Get-AppIcons.ps1");
        fs::write(
            &electron_ps,
            include_str!("../scripts/Enable-ElectronContentProtection.ps1"),
        )?;
        fs::write(
            &hide_ps,
            include_str!("../scripts/Protect-WhatsAppCapture.ps1"),
        )?;
        fs::write(
            &apps_ps,
            include_str!("../scripts/List-InstalledApps.ps1"),
        )?;
        fs::write(&icons_ps, include_str!("../scripts/Get-AppIcons.ps1"))?;
        Ok(Engine {
            electron_ps,
            hide_ps,
            apps_ps,
            icons_ps,
        })
    }

    /// Fetch icons (PNG data URIs) for the given process names (JSON object on stdout).
    pub fn app_icons(&self, processes: &str) -> Result<String, String> {
        let mut cmd = Command::new("powershell.exe");
        cmd.arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&self.icons_ps)
            .arg("-Processes")
            .arg(processes);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd
            .output()
            .map_err(|e| format!("failed to launch PowerShell: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Enumerate installed apps (JSON on stdout) for the app picker.
    pub fn list_installed_apps(&self) -> Result<String, String> {
        let mut cmd = Command::new("powershell.exe");
        cmd.arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&self.apps_ps);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd
            .output()
            .map_err(|e| format!("failed to launch PowerShell: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Turn protection ON for a target, using its method.
    pub fn apply(&self, t: &Target) -> Result<String, String> {
        match t.method {
            // Signed hook-DLL: excludes the target's own windows from capture,
            // in-process, no remote-thread injection.
            Method::Inject => {
                // The engine has to actually be up. `protect_target` is a
                // fire-and-forget channel send, so without this check apply()
                // returns Ok — and the UI logs "protection turned ON" — against
                // an engine that never started and can protect nothing.
                //
                // Read this fresh on every call, never cached: a failed init is
                // retryable, so `false` means "not right now", not "never", and
                // a user toggling during a recovery window deserves the honest
                // answer for that moment.
                if !hook::is_ready() {
                    return Err("Protection engine is not running — it failed to start. \
                                Windows Guard cannot protect this app."
                        .into());
                }
                // Without this the call returns Ok — and the UI logs
                // "protection turned ON" — even when the target isn't running
                // and protect_target had nothing to hook. Report what actually
                // happened instead of asserting success.
                if crate::winapi::pids_for_process(&t.process).is_empty() {
                    return Ok(format!(
                        "{} isn't running — it will be protected when it starts.",
                        t.name
                    ));
                }
                hook::protect_target(&t.process);
                Ok(format!("Protecting {}", t.name))
            }
            // Electron: keep the permanent self-patch (survives with Windows Guard
            // closed) AND hook the process so its native OS dialogs are covered too.
            Method::ElectronPatch => {
                // Deliberately NOT gated on hook::is_ready(): unlike Inject, the
                // self-patch is the primary mechanism here and works entirely
                // without the engine. The hook is only a belt-and-suspenders pass
                // for the app's native OS dialogs, so a dead engine degrades this
                // method rather than defeating it — and we say which happened.
                let engine_up = hook::is_ready();
                if engine_up {
                    hook::protect_target(&t.process);
                }
                let out = run_ps(&self.electron_ps, &electron_args(t, false))?;
                // The script only writes files; the running app loaded its code
                // long ago. Reporting plain success here is what let a wiped
                // patch look "re-applied and fine" while the live app stayed
                // capturable. Say plainly that a restart is required.
                let caveat = if engine_up {
                    ""
                } else {
                    " (protection engine is down, so this app's native OS dialogs \
                      aren't covered until it recovers)"
                };
                Ok(format!(
                    "{} patched — fully quit and relaunch {} to activate.{}\n{}",
                    t.name, t.name, caveat, out
                ))
            }
            Method::HideDuringCapture => {
                Ok("Hide-during-capture protects per-capture; nothing to keep applied.".into())
            }
        }
    }

    /// Current patch state for a target — the on-disk truth, combined with
    /// whether the live windows actually show it taking effect.
    pub fn patch_state(&self, t: &Target, observed: crate::winapi::CaptureStatus) -> PatchState {
        if t.method != Method::ElectronPatch {
            return PatchState::NotApplicable;
        }
        match electron_patch_present(&t.process) {
            Some(true) => {
                // Present on disk. Only call it Active when the windows agree —
                // otherwise the running instance predates the patch. Deriving
                // this (rather than assuming) is what stops "pending restart"
                // from becoming a permanent excuse for a patch that is simply
                // not working.
                if observed == crate::winapi::CaptureStatus::Protected {
                    PatchState::Active
                } else {
                    PatchState::PendingRestart
                }
            }
            Some(false) => PatchState::Absent,
            // Can't find the app's bundle at all — nothing to claim.
            None => PatchState::NotApplicable,
        }
    }

    /// Turn protection OFF for a target.
    pub fn remove(&self, t: &Target) -> Result<String, String> {
        match t.method {
            Method::Inject => {
                // Mirror of the check in apply(). Claiming "Unprotected X" with
                // the engine down is the inverse lie: nothing was cleared, and
                // any exclusion already applied by a live helper stays in force.
                if !hook::is_ready() {
                    return Err("Protection engine is not running — protection state \
                                for this app is unchanged."
                        .into());
                }
                hook::unprotect_target(&t.process);
                Ok(format!("Unprotected {}", t.name))
            }
            Method::ElectronPatch => {
                // Same shape as the apply() twin: not gated (removing the
                // on-disk patch is the primary effect and works with the engine
                // down), one read used for both the skip and the caveat so the
                // two can't disagree mid-call.
                let engine_up = hook::is_ready();
                if engine_up {
                    hook::unprotect_target(&t.process);
                }
                let out = run_ps(&self.electron_ps, &electron_args(t, true))?;
                // Removing the patch, like applying it, only edits files — the
                // running app keeps the protection it already loaded. Saying
                // "removed" flat would imply the app is capturable again now.
                let caveat = if engine_up {
                    ""
                } else {
                    " (protection engine is down, so any exclusion already applied \
                      to this app's dialogs stays until it restarts)"
                };
                Ok(format!(
                    "{} patch removed — fully quit and relaunch {} to take effect.{}\n{}",
                    t.name, t.name, caveat, out
                ))
            }
            Method::HideDuringCapture => Ok("Nothing to remove.".into()),
        }
    }
}

fn electron_args(t: &Target, disable: bool) -> Vec<String> {
    let mut a = vec!["-Process".into(), t.process.clone()];
    if disable {
        a.push("-Disable".into());
    }
    a
}

fn run_ps(script: &Path, args: &[String]) -> Result<String, String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-WindowStyle")
        .arg("Hidden")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script);
    for a in args {
        cmd.arg(a);
    }
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let out = cmd
        .output()
        .map_err(|e| format!("failed to launch PowerShell: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    let combined = combined.trim().to_string();
    if out.status.success() {
        Ok(combined)
    } else {
        Err(if combined.is_empty() {
            "PowerShell exited with an error".into()
        } else {
            combined
        })
    }
}
