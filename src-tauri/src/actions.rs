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
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
                hook::protect_target(&t.process);
                Ok(format!("Protecting {}", t.name))
            }
            // Electron: keep the permanent self-patch (survives with Windows Guard
            // closed) AND hook the process so its native OS dialogs are covered too.
            Method::ElectronPatch => {
                hook::protect_target(&t.process);
                run_ps(&self.electron_ps, &electron_args(t, false))
            }
            Method::HideDuringCapture => {
                Ok("Hide-during-capture protects per-capture; nothing to keep applied.".into())
            }
        }
    }

    /// Turn protection OFF for a target.
    pub fn remove(&self, t: &Target) -> Result<String, String> {
        match t.method {
            Method::Inject => {
                hook::unprotect_target(&t.process);
                Ok(format!("Unprotected {}", t.name))
            }
            Method::ElectronPatch => {
                hook::unprotect_target(&t.process);
                run_ps(&self.electron_ps, &electron_args(t, true))
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
