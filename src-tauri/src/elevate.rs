//! Elevated auto-start at logon via a Task Scheduler task with highest
//! privileges. Creating/removing the task needs a one-time admin approval (UAC);
//! after that it launches elevated at each logon with NO recurring UAC prompt.

use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const TASK_NAME: &str = "Windows Guard";
/// Prior product names' task, cleaned up automatically on an already-elevated
/// run so a rename never leaves an orphaned scheduled task behind.
const RETIRED_TASK_NAMES: &[&str] = &["CaptureGuard"];

/// Is the scheduled task currently registered?
pub fn task_installed() -> bool {
    task_named_exists(TASK_NAME)
}

fn task_named_exists(name: &str) -> bool {
    let mut cmd = Command::new("schtasks.exe");
    cmd.args(["/Query", "/TN", name]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

/// Register the logon task. Prompts once for admin — unless we're already
/// elevated, in which case it's registered directly with no prompt at all.
pub fn install_task(exe: &Path) -> Result<(), String> {
    let user = current_user();
    let xml = task_xml(&user, exe);
    let path = std::env::temp_dir().join("windows-guard-task.xml");
    write_utf16(&path, &xml).map_err(|e| e.to_string())?;
    run_schtasks(&[
        "/Create".into(),
        "/TN".into(),
        TASK_NAME.into(),
        "/XML".into(),
        path.display().to_string(),
        "/F".into(),
    ])
}

/// Remove the logon task (prompts once for admin, unless already elevated).
pub fn remove_task() -> Result<(), String> {
    run_schtasks(&["/Delete".into(), "/TN".into(), TASK_NAME.into(), "/F".into()])
}

/// Best-effort cleanup of scheduled tasks left behind by a prior product name.
/// Only actually does anything when the caller is already elevated (deleting a
/// task needs admin rights) — otherwise a silent no-op, never prompts. Safe to
/// call unconditionally on every start.
pub fn cleanup_retired_tasks() {
    if !crate::privilege::is_elevated() {
        return;
    }
    for name in RETIRED_TASK_NAMES {
        if task_named_exists(name) {
            let mut cmd = Command::new("schtasks.exe");
            cmd.args(["/Delete", "/TN", name, "/F"]);
            #[cfg(windows)]
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd.output();
        }
    }
}

/// Start the already-registered logon task RIGHT NOW. No UAC prompt: Task
/// Scheduler lets any process — even unelevated — trigger a task that was
/// already granted `RunLevel=HighestAvailable` at creation time (that consent
/// was captured once, in `install_task`). This is what lets Windows Guard
/// relaunch itself elevated silently, on demand, as often as it needs to.
pub fn run_task_now() -> Result<(), String> {
    let mut cmd = Command::new("schtasks.exe");
    cmd.args(["/Run", "/TN", TASK_NAME]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    // ERROR_TASK_ALREADY_RUNNING (0x800710E0). At logon the task's own
    // LogonTrigger is firing at the same moment we ask for an on-demand run,
    // so `schtasks /Run` loses the race and reports the task as already
    // started. That is a SUCCESSFUL hand-off, not a failure: an elevated
    // instance is already coming up and `MultipleInstancesPolicy=IgnoreNew`
    // is doing exactly what it should. Treating it as an error is what used
    // to leave the unelevated caller alive alongside the elevated copy.
    if is_already_running() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if msg.is_empty() {
        format!("schtasks /Run failed (exit {:?})", out.status.code())
    } else {
        msg
    })
}

/// Does this `schtasks /Run` failure actually mean "an instance is already
/// starting"?
///
/// Deliberately does NOT try to read the answer out of `schtasks`: measured on
/// Windows 11, `schtasks /Run` against a task it cannot start exits with a plain
/// `1` and prints localized prose containing no error code at all, so neither
/// the exit code nor the message text can be matched reliably. (The 0x800710E0
/// ERROR_TASK_ALREADY_RUNNING that identifies this case shows up on the task's
/// stored Last Result, not on the `/Run` invocation.) So we ask the Schedule
/// Service for the task's state instead.
///
/// Anything we cannot positively confirm is treated as NOT already running, so
/// an ambiguous failure falls through to the caller's verification step rather
/// than being optimistically reported as a successful hand-off.
fn is_already_running() -> bool {
    task_state_is_running().unwrap_or(false)
}

/// Ask the Schedule Service whether our task is in the Running state.
/// `Some(false)` = definitely not running, `None` = couldn't tell.
///
/// Uses PowerShell's `Get-ScheduledTask` because its `State` is a typed enum
/// whose names are invariant, unlike `schtasks /Query`, whose "Status: Running"
/// line is localized and would silently stop matching on a non-English Windows.
fn task_state_is_running() -> Option<bool> {
    let script = format!(
        "(Get-ScheduledTask -TaskName '{}' -ErrorAction Stop).State",
        TASK_NAME.replace('\'', "''")
    );
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .eq_ignore_ascii_case("Running"),
    )
}

/// Wait (briefly) for an elevated instance of `exe` other than ourselves to
/// exist. `schtasks /Run` returns as soon as the request is QUEUED, not when
/// the process has started, so a caller that exits on its return alone can
/// leave zero instances running. Polls until `timeout`, returning true as soon
/// as another instance of our own image is observed.
pub fn wait_for_other_instance(exe: &Path, timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if other_instance_running(exe) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    other_instance_running(exe)
}

/// Is another process running the same image as `exe` (ignoring ourselves)?
#[cfg(windows)]
fn other_instance_running(exe: &Path) -> bool {
    let Some(name) = exe.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let me = std::process::id();
    // `tasklist` is used rather than a toolhelp snapshot because an unelevated
    // caller can enumerate image names of elevated processes this way without
    // needing to OPEN them (OpenProcess against an elevated PID from a normal
    // token fails with access-denied, which is the very situation we're in).
    let mut cmd = Command::new("tasklist.exe");
    cmd.args(["/FI", &format!("IMAGENAME eq {name}"), "/NH", "/FO", "CSV"]);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let Ok(out) = cmd.output() else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).lines().any(|line| {
        // CSV: "image","pid","session","session#","mem"
        let mut fields = line.split("\",\"");
        let matches_image = fields
            .next()
            .map(|f| f.trim_start_matches('"').eq_ignore_ascii_case(name))
            .unwrap_or(false);
        let pid: Option<u32> = fields.next().and_then(|f| f.trim().parse().ok());
        matches_image && pid.map(|p| p != me).unwrap_or(false)
    })
}

#[cfg(not(windows))]
fn other_instance_running(_exe: &Path) -> bool {
    false
}

/// Name of the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value that
/// `tauri-plugin-autostart` writes. Must match the app's product name.
const RUN_KEY_VALUE: &str = "Windows Guard";

/// Delete our `HKCU\...\Run` autostart value, if present.
///
/// When elevated mode is on the scheduled task is the ONLY thing allowed to
/// start us at logon. The Run key launches an UNELEVATED copy (that hive always
/// uses the plain user token) at the same moment, and an unelevated instance
/// cannot install its hooks — so leaving both registered is what made every
/// target silently capturable after a reboot.
///
/// Uses `reg.exe` rather than the autostart plugin because this has to run
/// before the Tauri app (and its AppHandle) exists. Deleting a value under HKCU
/// needs no elevation. A missing value is not an error.
pub fn remove_run_key() {
    let mut cmd = Command::new("reg.exe");
    cmd.args([
        "delete",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "/V",
        RUN_KEY_VALUE,
        "/F",
    ]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let _ = cmd.output();
}

/// Relaunch the app elevated now. Tries the silent, no-prompt task trigger
/// first (works whenever the logon task is registered); only falls back to a
/// UAC-prompted relaunch if that task is missing or fails for some reason.
/// Caller should exit the current (unelevated) process once this returns Ok.
pub fn restart_elevated(exe: &Path) -> Result<(), String> {
    if task_installed() && run_task_now().is_ok() {
        return Ok(());
    }
    // No forced `--minimized` here either — see the note on `task_xml` for why.
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ Start-Process -FilePath \"{}\" -Verb RunAs; exit 0 }} catch {{ exit 1223 }}",
        exe.display()
    );
    run_powershell(&script)
}

/// Run a `schtasks` create/delete call. If we're already elevated, run it
/// directly (our own process token already has the rights this needs, so no
/// prompt is shown at all); otherwise elevate just this one call via UAC.
/// Args are passed as a real argument array the whole way through — never
/// concatenated into one string — so task names/paths containing spaces
/// (e.g. "Windows Guard") can't be mis-split by an intermediate shell.
fn run_schtasks(args: &[String]) -> Result<(), String> {
    if crate::privilege::is_elevated() {
        let mut cmd = Command::new("schtasks.exe");
        cmd.args(args);
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd.output().map_err(|e| e.to_string())?;
        return if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        };
    }
    run_elevated(args)
}

fn run_elevated(schtasks_args: &[String]) -> Result<(), String> {
    // Elevate just the schtasks call via UAC; wait and surface its exit code.
    // Build a PowerShell array literal so each argument is quoted and passed
    // through independently — no single-string concatenation anywhere.
    let ps_array = schtasks_args
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ $p = Start-Process -FilePath schtasks.exe -ArgumentList @({ps_array}) -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode }} catch {{ exit 1223 }}"
    );
    run_powershell(&script)
}

fn run_powershell(script: &str) -> Result<(), String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        // A declined/dismissed UAC prompt has been observed to surface as
        // different exit codes depending on Windows version (the documented
        // ERROR_CANCELLED 1223, but also a generic E_FAIL-shaped -2147467259
        // from the underlying .NET exception) — since our script's only path
        // to a non-1223 failure IS an elevation that didn't happen, treat any
        // failure here the same way rather than showing a cryptic exit code.
        Err("Admin permission wasn't granted.".into())
    }
}

fn current_user() -> String {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    if domain.is_empty() {
        user
    } else {
        format!("{}\\{}", domain, user)
    }
}

/// This task is the SOLE logon-start mechanism whenever elevated mode is on —
/// the HKCU\Run autostart key is deliberately removed in that case (see
/// `setup()` in lib.rs). Two independent logon launches of the same exe used to
/// race: the Run key's unelevated copy would call `run_task_now()` at the exact
/// moment the LogonTrigger fired, collide with `MultipleInstancesPolicy`
/// =IgnoreNew, read the resulting ERROR_TASK_ALREADY_RUNNING as a failed
/// hand-off, and therefore NOT exit — leaving an unelevated instance running
/// that can never install its hooks (no SeDebugPrivilege) while the UI happily
/// reported everything as protected.
///
/// No `--minimized` argument here deliberately: this same task also fires for
/// the non-elevated->elevated hand-off on every manual launch (see `setup()`
/// in lib.rs), not just the logon trigger. Hardcoding `--minimized` used to
/// mean ANY manual launch got silently redirected through this task and came
/// up hidden, regardless of the user's actual "start minimized" setting.
/// Whether to hide now comes solely from the persisted `start_minimized`
/// config, which both launch paths already read.
fn task_xml(user: &str, exe: &Path) -> String {
    let u = xml_escape(user);
    let cmd = xml_escape(&exe.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Windows Guard elevated auto-start at logon</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{u}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{u}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author"><Exec><Command>{cmd}</Command></Exec></Actions>
</Task>"#
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_utf16(path: &Path, s: &str) -> std::io::Result<()> {
    let mut bytes = vec![0xFFu8, 0xFE]; // UTF-16 LE BOM
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(path, bytes)
}
