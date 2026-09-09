//! WhatsApp privacy blur: injects a control panel into WhatsApp's own WebView2
//! via the Chrome DevTools Protocol (CDP), blurring chats/messages/header until
//! hovered. Separate from capture-hiding (WhatsApp is already excluded from
//! screen capture) — this is for shoulder-surfing.
//!
//! Mechanism: WhatsApp Desktop renders its whole UI inside a WebView2. Setting
//! WhatsApp's own `AdditionalBrowserArguments` policy value — scoped to
//! `WhatsApp.Root.exe` ONLY, never machine-wide — enables
//! `--remote-debugging-port`, which lets us connect over CDP and inject a
//! persistent stylesheet + control panel (see `scripts/whatsapp-blur-panel.js`).
//!
//! This opens a real local exposure while active (any local process could reach
//! WhatsApp's authenticated session over that loopback port), so by design it is
//! only enabled while the user has this feature turned ON: the registry value
//! and any live debug port are removed the moment it's turned off or the app
//! exits. Applying the registry value needs administrator rights (this app's
//! elevated mode).

use crate::winapi::pids_for_process;
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    REG_SZ,
};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const WHATSAPP_PROCESS: &str = "whatsapp.root";
/// WhatsApp Desktop's Store package family name — assigned once by the
/// publisher, stable across app updates/locales.
const WHATSAPP_AUMID: &str = "5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App";
const POLICY_SUBKEY: &str = "Software\\Policies\\Microsoft\\Edge\\WebView2\\AdditionalBrowserArguments";
const VALUE_NAME: &str = "WhatsApp.Root.exe";

/// The injected control panel (blur CSS + hover reveal + settings UI). Embedded
/// so the feature ships as part of the (signed) exe, no external file needed.
const PANEL_JS: &str = include_str!("../scripts/whatsapp-blur-panel.js");

static ENABLED: AtomicBool = AtomicBool::new(false);
static PORT: AtomicU16 = AtomicU16::new(0);
static WS_ACTIVE: AtomicBool = AtomicBool::new(false);
static GEN: AtomicU16 = AtomicU16::new(0); // bumped on enable/disable to stop stale ws loops

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WaBlurState {
    Off,
    WaitingForWhatsApp,
    Active,
    ElevationNeeded,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WaBlurStatus {
    pub enabled: bool,
    pub state: WaBlurState,
}

static LAST_STATUS: Mutex<WaBlurStatus> = Mutex::new(WaBlurStatus {
    enabled: false,
    state: WaBlurState::Off,
});

pub fn status() -> WaBlurStatus {
    LAST_STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_state(app: &AppHandle, enabled: bool, state: WaBlurState) {
    let new = WaBlurStatus { enabled, state };
    let mut cur = LAST_STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let changed = *cur != new;
    *cur = new.clone();
    drop(cur);
    if changed {
        let _ = app.emit("wablur-status", &new);
    }
}

/// Turn the feature on/off. The background supervisor (see `spawn`) does the
/// actual registry/relaunch/injection work on its next tick.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    GEN.fetch_add(1, Ordering::Relaxed);
}

// --- registry: WhatsApp-only WebView2 debug-port policy value ----------------

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn set_policy_value(root: HKEY, port: u16) -> windows::core::Result<()> {
    unsafe {
        let subkey = wide(POLICY_SUBKEY);
        let mut hkey = HKEY::default();
        RegCreateKeyExW(
            root,
            PCWSTR(subkey.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .ok()?;
        let value = wide(&format!(
            "--remote-debugging-port={port} --remote-allow-origins=*"
        ));
        let bytes: &[u8] =
            std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
        let name = wide(VALUE_NAME);
        let res = RegSetValueExW(hkey, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(bytes));
        let _ = RegCloseKey(hkey);
        res.ok()?;
    }
    Ok(())
}

fn remove_policy_value(root: HKEY) {
    unsafe {
        let subkey = wide(POLICY_SUBKEY);
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(root, PCWSTR(subkey.as_ptr()), 0, KEY_SET_VALUE, &mut hkey).is_ok() {
            let name = wide(VALUE_NAME);
            let _ = RegDeleteValueW(hkey, PCWSTR(name.as_ptr()));
            let _ = RegCloseKey(hkey);
        }
    }
}

fn dbg(msg: &str) {
    if std::env::var("CG_WABLUR_DEBUG").as_deref() == Ok("1") {
        if let Ok(dir) = std::env::var("TEMP") {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{dir}\\cg-wablur-debug.log"))
            {
                let _ = writeln!(f, "{msg}");
            }
        }
    }
}

/// Try the no-elevation HKCU location first (works on machines where it isn't
/// policy-locked), then HKLM (needs this app's elevated mode).
fn ensure_policy_set(port: u16) -> Result<(), ()> {
    match set_policy_value(HKEY_CURRENT_USER, port) {
        Ok(()) => {
            dbg(&format!("HKCU set OK port={port}"));
            return Ok(());
        }
        Err(e) => dbg(&format!("HKCU set failed: {e:?}")),
    }
    match set_policy_value(HKEY_LOCAL_MACHINE, port) {
        Ok(()) => {
            dbg(&format!("HKLM set OK port={port}"));
            return Ok(());
        }
        Err(e) => dbg(&format!("HKLM set failed: {e:?}")),
    }
    Err(())
}

fn remove_policy_everywhere() {
    remove_policy_value(HKEY_CURRENT_USER);
    remove_policy_value(HKEY_LOCAL_MACHINE);
}

// --- process control ----------------------------------------------------------

fn kill_whatsapp() {
    for pid in pids_for_process(WHATSAPP_PROCESS) {
        unsafe {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
                let _ = TerminateProcess(h, 0);
                let _ = CloseHandle(h);
            }
        }
    }
}

fn launch_whatsapp() {
    unsafe {
        let op = wide("open");
        let path = wide(&format!("shell:AppsFolder\\{WHATSAPP_AUMID}"));
        let _ = ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// A high, process-specific port — avoids the well-known 9222 default and
/// collisions between multiple machines' fixed ports (defense-in-depth; the
/// port is loopback-only regardless).
fn pick_port() -> u16 {
    20000 + (std::process::id() % 20000) as u16
}

// --- CDP client (native; no external runtime needed) --------------------------

fn fetch_json_list(port: u16) -> Option<Vec<serde_json::Value>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
    let req = format!(
        "GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf); // may time out after Connection:close; that's fine
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

fn find_ws_url(list: &[serde_json::Value]) -> Option<String> {
    list.iter()
        .find(|t| {
            t["type"] == "page" && t["url"].as_str().is_some_and(|u| u.contains("whatsapp"))
        })
        .or_else(|| list.iter().find(|t| t["type"] == "page" && t["webSocketDebuggerUrl"].is_string()))
        .and_then(|t| t["webSocketDebuggerUrl"].as_str().map(|s| s.to_string()))
}

/// Connect, inject (persistent across reloads via addScriptToEvaluateOnNewDocument
/// + an immediate Runtime.evaluate), then keep the socket alive and periodically
/// re-assert (idempotent — the panel version-guards its own rebuild) so soft SPA
/// navigations stay covered. Returns when the socket closes/errors or `gen`
/// (this enable/disable cycle's generation) goes stale.
fn run_ws_loop(ws_url: &str, gen: u16) {
    let (mut socket, _resp) = match tungstenite::connect(ws_url) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let tungstenite::stream::MaybeTlsStream::Plain(tcp) = socket.get_ref() {
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(400)));
    }

    let mut id = 1u32;
    let mut send = |socket: &mut tungstenite::WebSocket<_>, method: &str, params: serde_json::Value| {
        id += 1;
        let msg = serde_json::json!({ "id": id, "method": method, "params": params });
        let _ = socket.send(tungstenite::Message::Text(msg.to_string().into()));
    };
    send(&mut socket, "Page.enable", serde_json::json!({}));
    send(
        &mut socket,
        "Page.addScriptToEvaluateOnNewDocument",
        serde_json::json!({ "source": PANEL_JS }),
    );
    send(
        &mut socket,
        "Runtime.evaluate",
        serde_json::json!({ "expression": PANEL_JS }),
    );

    WS_ACTIVE.store(true, Ordering::Relaxed);
    let mut last_reassert = Instant::now();
    loop {
        if GEN.load(Ordering::Relaxed) != gen {
            break; // enable/disable happened; let the supervisor take over
        }
        match socket.read() {
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break, // socket closed (WhatsApp restarted / navigated away hard)
        }
        if last_reassert.elapsed() >= Duration::from_secs(5) {
            send(
                &mut socket,
                "Runtime.evaluate",
                serde_json::json!({ "expression": PANEL_JS }),
            );
            last_reassert = Instant::now();
        }
    }
    WS_ACTIVE.store(false, Ordering::Relaxed);
}

// --- supervisor ----------------------------------------------------------------

/// One background thread drives the whole lifecycle: apply/remove the
/// registry value, relaunch WhatsApp when needed, connect + inject, and report
/// status. Mirrors the pattern used by `hook`, `events`, `monitor`, `veil`.
pub fn spawn(app: AppHandle) {
    std::thread::spawn(move || {
        let mut applied_to_running_instance = false;

        loop {
            let enabled = ENABLED.load(Ordering::Relaxed);
            let running = !pids_for_process(WHATSAPP_PROCESS).is_empty();
            let gen = GEN.load(Ordering::Relaxed);
            dbg(&format!(
                "tick enabled={enabled} running={running} port={} ws_active={}",
                PORT.load(Ordering::Relaxed),
                WS_ACTIVE.load(Ordering::Relaxed)
            ));

            if enabled {
                if PORT.load(Ordering::Relaxed) == 0 {
                    let port = pick_port();
                    match ensure_policy_set(port) {
                        Ok(()) => {
                            PORT.store(port, Ordering::Relaxed);
                            if running {
                                // This running instance predates the flag — restart it
                                // once so its WebView2 picks up the debug port.
                                kill_whatsapp();
                                std::thread::sleep(Duration::from_millis(800));
                                launch_whatsapp();
                                applied_to_running_instance = true;
                            }
                            set_state(&app, true, WaBlurState::WaitingForWhatsApp);
                        }
                        Err(()) => {
                            set_state(&app, true, WaBlurState::ElevationNeeded);
                            std::thread::sleep(Duration::from_secs(3));
                            continue;
                        }
                    }
                }

                let port = PORT.load(Ordering::Relaxed);
                if !WS_ACTIVE.load(Ordering::Relaxed) {
                    if let Some(list) = fetch_json_list(port) {
                        if let Some(ws_url) = find_ws_url(&list) {
                            let app2 = app.clone();
                            let gen2 = gen;
                            std::thread::spawn(move || run_ws_loop(&ws_url, gen2));
                            // give the fresh connection a moment before we re-check
                            std::thread::sleep(Duration::from_millis(300));
                            set_state(
                                &app2,
                                true,
                                if WS_ACTIVE.load(Ordering::Relaxed) {
                                    WaBlurState::Active
                                } else {
                                    WaBlurState::WaitingForWhatsApp
                                },
                            );
                        } else {
                            set_state(&app, true, WaBlurState::WaitingForWhatsApp);
                        }
                    } else {
                        set_state(&app, true, WaBlurState::WaitingForWhatsApp);
                    }
                } else {
                    set_state(&app, true, WaBlurState::Active);
                }
            } else {
                if PORT.load(Ordering::Relaxed) != 0 {
                    remove_policy_everywhere();
                    PORT.store(0, Ordering::Relaxed);
                    if applied_to_running_instance && running {
                        kill_whatsapp();
                        std::thread::sleep(Duration::from_millis(800));
                        launch_whatsapp();
                    }
                    applied_to_running_instance = false;
                }
                set_state(&app, false, WaBlurState::Off);
            }

            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

/// Best-effort cleanup so a crashed/killed Windows Guard doesn't leave the
/// debug port open. Call from the app's exit path.
pub fn shutdown() {
    if PORT.swap(0, Ordering::Relaxed) != 0 {
        remove_policy_everywhere();
    }
}
