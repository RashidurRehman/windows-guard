#requires -Version 5.1
<#
.SYNOPSIS
    Keep WhatsApp Desktop out of screen captures by hiding it for the moment of
    capture, then restoring it exactly as it was.

.DESCRIPTION
    WhatsApp Desktop is the native WinUI Store app (WhatsApp.Root.exe, window class
    WinUIDesktopWin32WindowClass). It is NOT Electron, so the Cursor trick
    (patching the app to call setContentProtection on itself) does not apply, and
    Windows refuses to let an outside script set WDA_EXCLUDEFROMCAPTURE on a window
    it does not own (SetWindowDisplayAffinity returns ACCESS_DENIED / err 5). That
    "show-through" mode is therefore impossible from outside WhatsApp.

    The reliable alternative: ShowWindow IS allowed cross-process, so we hide the
    WhatsApp window (SW_HIDE - gone from screen AND capture), let your capture run,
    then restore the window to its previous state (normal / maximized / minimized).

    Only the real WhatsApp window (class WinUIDesktopWin32WindowClass) is touched.
    The process's tiny helper windows (GDI+ hook, NotifyIcon, .NET broadcast) are
    left alone.

.PARAMETER Run
    Hide WhatsApp, run this command/line, then ALWAYS restore (even if it errors).
    This is the safest integration for an automated capture:
        .\Protect-WhatsAppCapture.ps1 -Run "nircmd.exe savescreenshot shot.png"

.PARAMETER Hide
    Just hide WhatsApp now (call this right before your capture step).

.PARAMETER Show
    Restore WhatsApp (call this right after your capture step).

.PARAMETER Status
    Report whether WhatsApp is currently visible or hidden.

.PARAMETER SettleMs
    Milliseconds to wait after hiding before the capture, so the compositor has
    dropped the window. Default 250.

.NOTES
    * No admin needed. WhatsApp keeps running the whole time; only its window is
      hidden for a fraction of a second.
    * State (which window was hidden + its placement) is saved next to this script
      as wa-hidden-state.json so -Show restores precisely. If that file is lost,
      -Show falls back to un-hiding any hidden WhatsApp main window as "normal".

.EXAMPLE
    # Wrap your capture (recommended - atomic, auto-restores on failure):
    powershell -ExecutionPolicy Bypass -File .\Protect-WhatsAppCapture.ps1 -Run "your-capture.exe args"

.EXAMPLE
    # Or bracket your capture step manually:
    powershell -ExecutionPolicy Bypass -File .\Protect-WhatsAppCapture.ps1 -Hide
    #   ... your screen capture happens here ...
    powershell -ExecutionPolicy Bypass -File .\Protect-WhatsAppCapture.ps1 -Show
#>
[CmdletBinding(DefaultParameterSetName='Status')]
param(
    [Parameter(ParameterSetName='Run', Mandatory)][string]$Run,
    [Parameter(ParameterSetName='Hide', Mandatory)][switch]$Hide,
    [Parameter(ParameterSetName='Show', Mandatory)][switch]$Show,
    [Parameter(ParameterSetName='Status')][switch]$Status,
    [int]$SettleMs = 250
)
$ErrorActionPreference = 'Stop'

$TargetProcess = 'WhatsApp.Root'
$TargetClass   = 'WinUIDesktopWin32WindowClass'
$StateFile     = Join-Path $PSScriptRoot 'wa-hidden-state.json'

Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class WaWin {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint c);
    [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int m);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
    [DllImport("user32.dll", SetLastError=true)] public static extern bool ShowWindow(IntPtr h, int c);

    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] public struct RECT  { public int L, T, R, B; }
    [StructLayout(LayoutKind.Sequential)] public struct WP {
        public int length; public int flags; public int showCmd;
        public POINT ptMin; public POINT ptMax; public RECT rcNormal;
    }
    [DllImport("user32.dll")] public static extern bool GetWindowPlacement(IntPtr h, ref WP p);

    public static List<IntPtr> TopLevel() {
        var l = new List<IntPtr>();
        EnumWindows((h, x) => { if (GetWindow(h,4)==IntPtr.Zero && GetWindowTextLength(h)>0) l.Add(h); return true; }, IntPtr.Zero);
        return l;
    }
    public static int Pid(IntPtr h){ uint p; GetWindowThreadProcessId(h, out p); return (int)p; }
    public static string Cls(IntPtr h){ var s=new StringBuilder(256); GetClassName(h,s,256); return s.ToString(); }
    public static int ShowCmd(IntPtr h){ WP p = new WP(); p.length = Marshal.SizeOf(p); return GetWindowPlacement(h, ref p) ? p.showCmd : 1; }
    public static bool Vis(IntPtr h){ return IsWindowVisible(h); }
    public static bool Alive(IntPtr h){ return IsWindow(h); }
}
'@

# --- helpers -------------------------------------------------------------
function Get-WaMainWindows {
    # Only the real WhatsApp window(s): correct process AND WinUI class.
    $out = @()
    foreach ($h in [WaWin]::TopLevel()) {
        $name = try { (Get-Process -Id ([WaWin]::Pid($h)) -ErrorAction Stop).ProcessName } catch { '' }
        if ($name -ne $TargetProcess) { continue }
        if ([WaWin]::Cls($h) -ne $TargetClass) { continue }
        $out += $h
    }
    return $out
}

function Invoke-Hide {
    $wins = Get-WaMainWindows
    if (-not $wins) {
        Write-Host "WhatsApp has no open window (closed or in tray) - nothing to hide." -ForegroundColor Yellow
        return $false
    }
    $state = @()
    foreach ($h in $wins) {
        $showCmd = [WaWin]::ShowCmd($h)
        if ($showCmd -le 0) { $showCmd = 1 }          # never store "hidden(0)"; treat as normal
        [WaWin]::ShowWindow($h, 0) | Out-Null          # SW_HIDE
        $state += [pscustomobject]@{ Hwnd = [int64]$h; ShowCmd = $showCmd }
        Write-Host ("Hidden WhatsApp window 0x{0:X} (will restore as showCmd={1})." -f [int64]$h, $showCmd) -ForegroundColor Cyan
    }
    $state | ConvertTo-Json -Compress | Set-Content -Path $StateFile -Encoding UTF8
    return $true
}

function Invoke-Show {
    $restored = 0
    if (Test-Path $StateFile) {
        $state = Get-Content $StateFile -Raw | ConvertFrom-Json
        foreach ($e in @($state)) {
            $h = [IntPtr][int64]$e.Hwnd
            if (-not [WaWin]::Alive($h)) { continue }
            $cmd = [int]$e.ShowCmd; if ($cmd -le 0) { $cmd = 1 }
            [WaWin]::ShowWindow($h, $cmd) | Out-Null
            $restored++
        }
        Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    }
    if ($restored -eq 0) {
        # Fallback: no state file - un-hide any hidden WhatsApp main window as normal.
        foreach ($h in Get-WaMainWindows) {
            if (-not [WaWin]::Vis($h)) { [WaWin]::ShowWindow($h, 1) | Out-Null; $restored++ }  # SW_SHOWNORMAL
        }
    }
    if ($restored -gt 0) { Write-Host ("Restored {0} WhatsApp window(s)." -f $restored) -ForegroundColor Green }
    else { Write-Host "No hidden WhatsApp window to restore." -ForegroundColor Yellow }
}

function Show-Status {
    $wins = Get-WaMainWindows
    if (-not $wins) { Write-Host "WhatsApp: no open window (closed or minimized to tray)." -ForegroundColor Yellow; return }
    foreach ($h in $wins) {
        if ([WaWin]::Vis($h)) { Write-Host ("WhatsApp window 0x{0:X}: VISIBLE (capturable)." -f [int64]$h) -ForegroundColor Red }
        else                  { Write-Host ("WhatsApp window 0x{0:X}: HIDDEN (safe from capture)." -f [int64]$h) -ForegroundColor Green }
    }
}

# --- dispatch ------------------------------------------------------------
switch ($PSCmdlet.ParameterSetName) {
    'Hide'   { [void](Invoke-Hide) }
    'Show'   { Invoke-Show }
    'Status' { Show-Status }
    'Run'    {
        $hid = Invoke-Hide
        if ($hid -and $SettleMs -gt 0) { Start-Sleep -Milliseconds $SettleMs }
        try {
            Write-Host ("Running capture: {0}" -f $Run) -ForegroundColor DarkGray
            & $env:ComSpec /c $Run
            Write-Host ("Capture command exit code: {0}" -f $LASTEXITCODE) -ForegroundColor DarkGray
        }
        finally {
            Invoke-Show
        }
    }
}
