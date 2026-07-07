# Windows Guard

A lightweight Windows tray app (Tauri + Rust) that keeps your private apps —
WhatsApp, Brave, Cursor, and anything you add — **out of screen recordings and
screenshots**, while they stay fully visible to you ("show-through"). It starts
at logon, protects on startup, and **self-heals**: when a protected app is closed
and reopened, protection is re-applied automatically within a few seconds.

It also includes **Sync Monitor** (detects employee-monitoring/tracker software
taking a screenshot and alerts you), a **WhatsApp privacy blur**, an **activity
simulator** (keeps idle-detectors satisfied without typing anything), and a
per-app **defender status badge**.

## What it does

- **Per-app protection with the best method for each app type** (see below).
- **Master switch** to pause/resume everything, plus an individual toggle per app.
- **Live status** for every app: Protected / Capturable / Partly protected / Not running.
- **Self-healing monitor**: re-applies protection whenever a window loses it
  (e.g. after the app restarts or a new window/widget appears).
- **Start on Windows login** (no admin) and optional **start minimized to tray**.
- **Add your own apps/games**, with automatic app-type detection to pick the best method.
- **WhatsApp privacy veil** (anti shoulder-surfing): blurs WhatsApp on screen and
  reveals only the message you hover — see below. Toggle in Settings.
- **Activity log** of everything the guardian does.

## Protection methods (best -> fallback), chosen by app type

| Method | Best for | How it works |
|---|---|---|
| **Electron self-patch** | Electron apps (Cursor, VS Code, VSCodium, Windsurf, Signal...) | Patches the app so *it* calls `BrowserWindow.setContentProtection(true)`. Permanent across restarts, no injection, no AV risk. Needs an unpacked bundle (`resources\app`); asar-packed apps fall back to the signed hook DLL. |
| **Signed hook DLL** | Non-Electron apps (WhatsApp's WinUI app, Brave/Chrome/Edge, native apps, windowed games) | Maps a **signed helper DLL** into the target via `SetWindowsHookEx(WH_GETMESSAGE)` — the documented Windows path used by IMEs and accessibility tools — so it can call `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` on the target's *own* windows from the inside. Re-applied on restart (see below). |
| **Hide during capture** | AV-safe last resort | Briefly hides the window only during a capture, then restores it. |

The **Add app** dialog auto-detects whether an app is Electron and recommends the
right method; you can override it.

## In-process protection via a signed helper DLL

`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` only works on a window owned by
the **calling** process — the OS blocks it cross-process. To exclude another app's
windows you have to run code *inside* that app. CaptureGuard does this the
documented, non-flaggable way instead of remote-thread shellcode:

- **A signed helper DLL** (crate `captureguard-hook`, in `hook-dll/`) is the only
  thing that runs inside the target. It is embedded into the (signed) CaptureGuard
  exe and extracted at runtime to
  `%LOCALAPPDATA%\CaptureGuard\captureguard_hook.dll`. The on-disk bytes are
  identical to the file we sign, so it stays a verified-publisher binary.
- **It is mapped in via `SetWindowsHookEx(WH_GETMESSAGE)`** — the same documented
  injection path IMEs and accessibility tools use, not `CreateRemoteThread` — so AV
  and Defender don't treat it as shellcode injection. Once mapped, the DLL calls
  `SetWindowDisplayAffinity` on the target's own top-level windows and installs an
  in-process `SetWinEventHook` so any window the target opens *later* (dialogs,
  popups, floating widgets) is excluded the instant it appears.
- **It works for sandboxed Store/UWP apps** (e.g. WhatsApp): the extracted DLL is
  `icacls`-granted read+execute to *ALL APPLICATION PACKAGES* and *ALL RESTRICTED
  APPLICATION PACKAGES*, so AppContainer processes are allowed to load it. No admin
  needed — CaptureGuard owns the file.
- **It survives cold starts.** CaptureGuard hooks *every* GUI thread of a target
  (not just the first) and re-scans threads on each protect pass, so an app that is
  still spinning up — whose first UI thread isn't pumping messages yet — still gets
  the DLL mapped via whichever thread pumps first; newly-created UI threads are
  picked up on the next monitor tick. Protection is toggled by posting a registered
  control message to the hooked thread, so enabling/clearing is instant and the hook
  stays installed until the process exits.

## WhatsApp privacy veil (anti shoulder-surfing)

Separate from capture-hiding — WhatsApp is already excluded from screen capture, so
this is purely against someone physically glancing at your screen:

- A **click-through, layered overlay** (which CaptureGuard owns) is inserted
  immediately above the WhatsApp window in the Z-order and applies an **acrylic
  blur**, so chats and messages aren't readable at a glance.
- A single **reveal "hole"** — shaped to the **UI-Automation element under the
  cursor** (the message bubble / chat-list row) — is cut out of the veil, so only
  what you're pointing at is crisp.
- It is active **whenever the WhatsApp window is visible** (not only when focused).
  Because the overlay sits just above WhatsApp rather than always-on-top, any window
  in front of WhatsApp still occludes the veil, so it never bleeds onto other apps.
- **The overlay is itself excluded from capture**, so the veil never shows up in a
  screenshot or recording.

Toggle it in **Settings → Privacy veil (WhatsApp)**.

## Architecture

- **Rust backend** (`src-tauri/src/`)
  - `winapi.rs` — native, cheap reads of live capture state (enumerate windows,
    read display-affinity) + app-type detection. No PowerShell needed just to check.
  - `hook.rs` — the in-process protection engine: extracts + `icacls`-grants the
    signed helper DLL, then loads it into each target via `SetWindowsHookEx` from a
    single dedicated owner thread (so hook handles are never orphaned).
  - `veil.rs` — the WhatsApp privacy veil: the click-through acrylic-blur overlay
    with a UI-Automation-shaped reveal hole under the cursor.
  - `actions.rs` — turns protection on/off per target: drives `hook.rs` for the
    signed-DLL method, plus the remaining (non-injection) PowerShell helpers for the
    Electron self-patch, app listing, and icons.
  - `monitor.rs` — the self-healing loop: probes each app every few seconds and
    re-applies protection when needed, with per-method cooldowns.
  - `config.rs` — the persisted config (apps, methods, settings, privacy veil).
  - `lib.rs` — Tauri commands, tray icon, autostart, window-to-tray behavior.
- **Signed helper DLL** (`hook-dll/`, crate `captureguard-hook`) — the tiny in-process
  library that is mapped into targets via `SetWindowsHookEx` and calls
  `SetWindowDisplayAffinity` on their own windows. Built as a `cdylib`, signed, and
  embedded into the exe.
- **Frontend** (`src/`) — a vanilla-TS + Vite single-page UI.
- **Engine scripts** (`src-tauri/scripts/`) — the remaining (non-injection) PowerShell
  helpers, bundled into the binary and written to the app data dir on launch:
  - `Enable-ElectronContentProtection.ps1` — generic Electron self-patcher.
  - `Protect-WhatsAppCapture.ps1` — hide-during-capture fallback.
  - `List-InstalledApps.ps1` / `Get-AppIcons.ps1` — data for the Add-app picker.

## Build & run

Requires: Rust (MSVC toolchain), Node.js, the MSVC C++ Build Tools + Windows SDK,
and Smart App Control **off** (it blocks unsigned build scripts).

```powershell
npm install
npm run tauri dev      # run in dev
npm run tauri build    # produce an installer + .exe in the build target dir
```

Rust build artifacts are redirected out of OneDrive via
`src-tauri/.cargo/config.toml` (`target-dir`), so OneDrive doesn't sync gigabytes.

## Caveats

- The signed hook DLL uses the **documented** `SetWindowsHookEx` path, so it isn't
  the remote-thread shellcode pattern AV flags — but AV can still object to *any*
  cross-process load. The Electron self-patch avoids loading anything into the
  target at all, which is why it stays preferred for Electron apps.
- The helper DLL is a **single architecture**; `SetWindowsHookEx` silently skips a
  target of the other bitness (nearly everything on modern Windows is 64-bit).
- The affinity flag lives on a specific window handle; closing/reopening an app
  recreates the window and drops it — that's why the monitor re-hooks and re-applies
  it, including for cold-starting apps.
- App updates can wipe the Electron patch or change a window class; just re-enable.
- **Exclusive-fullscreen** games bypass the desktop compositor and can't be
  protected — run them **windowed/borderless**.

### Code signing — what it does and doesn't buy you

CaptureGuard self-signs its exe and helper DLL, and `scripts/trust-captureguard.ps1`
can trust that certificate on your own machine so binaries show **"CaptureGuard"** as
a verified publisher. Be honest about the limits:

- **Self-signing does NOT clear SmartScreen or Smart App Control (SAC).** Those
  reputation gates trust only certificates with established reputation — in practice
  an **EV (Extended Validation) code-signing certificate**. A self-signed cert, even
  once locally trusted, won't satisfy them.
- **SAC must be OFF to build and run** the unsigned build scripts. Re-enabling SAC
  afterward is **lossy**: Windows only lets SAC go back to *on* via a **system
  reset**, so treat turning it off as a one-way door for that install.
- `scripts/allow-captureguard.ps1` can additionally add a Defender exclusion for
  CaptureGuard's own paths so its in-process loading isn't second-guessed. That
  stops Defender scanning those paths — only do it because it's your own tool.
