#requires -Version 5.1
<#
.SYNOPSIS
    Make the Cursor editor exclude itself from screen capture (recorders/screenshots).

.DESCRIPTION
    Windows only lets a process hide its OWN windows from capture
    (SetWindowDisplayAffinity is cross-process ACCESS_DENIED). Cursor is an Electron
    app, so the correct place to do this is from inside Cursor: Electron's
    BrowserWindow.setContentProtection(true), which applies WDA_EXCLUDEFROMCAPTURE.

    This script drops a tiny hook file next to Cursor's main bundle and makes the
    main process load it. The hook calls setContentProtection(true) on every Cursor
    window as it is created. Result when anything records/screenshots the screen:
    everything else is captured normally, and where Cursor is the capture shows the
    apps BEHIND it (not black) - because WDA_EXCLUDEFROMCAPTURE removes the window
    from the capture rather than blanking it.

    You still see Cursor completely normally.

.PARAMETER Disable
    Undo the patch and restore Cursor's original main bundle.

.NOTES
    * No admin needed (Cursor is a per-user install).
    * You MUST fully quit Cursor (including any tray icon) and relaunch for it to
      take effect - the running instance already loaded the old code.
    * A Cursor update overwrites its install folder and removes this patch; just
      run this script again after updating.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Enable-CursorContentProtection.ps1
    powershell -ExecutionPolicy Bypass -File .\Enable-CursorContentProtection.ps1 -Disable
#>
[CmdletBinding()]
param([switch]$Disable)

$ErrorActionPreference = 'Stop'
$marker = 'cursor-content-protection'

function Find-CursorApp {
    $roots = @(
        "$env:LOCALAPPDATA\Programs\cursor",
        "$env:LOCALAPPDATA\Programs\Cursor",
        "$env:PROGRAMFILES\Cursor",
        "${env:ProgramFiles(x86)}\Cursor"
    )
    foreach ($r in $roots) { if (Test-Path (Join-Path $r 'resources\app\package.json')) { return $r } }
    $p = Get-Process -Name Cursor -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
    if ($p) { return (Split-Path $p.Path -Parent) }
    return $null
}

$root = Find-CursorApp
if (-not $root) { throw "Could not locate the Cursor install. Is Cursor installed for this user?" }

$appDir  = Join-Path $root 'resources\app'
$pkg     = Get-Content (Join-Path $appDir 'package.json') -Raw | ConvertFrom-Json
$mainRel = $pkg.main -replace '^\./',''
$mainJs  = Join-Path $appDir $mainRel
if (-not (Test-Path $mainJs)) { throw "Main entry not found: $mainJs" }

$outDir    = Split-Path $mainJs -Parent
$hookPath  = Join-Path $outDir 'cp-hook.cjs'          # .cjs = always CommonJS, so require() works inside it
$oldHookJs = Join-Path $outDir 'cp-hook.js'           # legacy name from an earlier version, clean it up
$preBak    = "$mainJs.prebak"
# Cursor's main can be an ES module ("type":"module") where require() is undefined.
$isEsm     = ($pkg.type -eq 'module') -or ($mainRel -match '\.mjs$')

Write-Host ''
Write-Host ("Cursor:  {0}  (v{1})" -f $root, $pkg.version) -ForegroundColor Cyan
Write-Host ("Main:    {0}" -f $mainJs) -ForegroundColor DarkGray

if ($Disable) {
    if (Test-Path $preBak) {
        Copy-Item $preBak $mainJs -Force
        Remove-Item $preBak -Force
        Write-Host "Restored original main.js from backup." -ForegroundColor Green
    }
    else {
        # Fallback: strip the injected line if the backup is gone (e.g., after an update)
        $lines = Get-Content $mainJs
        $kept  = $lines | Where-Object { $_ -notmatch [regex]::Escape($marker) }
        if ($kept.Count -ne $lines.Count) {
            Set-Content -Path $mainJs -Value $kept -Encoding UTF8
            Write-Host "Removed injected loader line from main.js." -ForegroundColor Green
        } else {
            Write-Host "No injected line found in main.js (already clean)." -ForegroundColor Yellow
        }
    }
    foreach ($hp in @($hookPath, $oldHookJs)) { if (Test-Path $hp) { Remove-Item $hp -Force; Write-Host "Deleted hook file: $hp" -ForegroundColor Green } }
    Write-Host ''
    Write-Host "Disabled. Fully quit and relaunch Cursor to apply." -ForegroundColor Yellow
    Write-Host ''
    return
}

# ---- Enable ----
$hook = @'
// Content-protection hook for Cursor - hides its windows from screen capture.
// Added by Enable-CursorContentProtection.ps1 (marker: cursor-content-protection).
// Delete this file (and the loader line in main.js) or run the script with
// -Disable to turn it off.
try {
    var electron = require('electron');
    var app = electron.app;
    var protect = function (win) {
        try { win.setContentProtection(true); } catch (e) {}
    };
    if (app && app.on) {
        app.on('browser-window-created', function (_e, win) { protect(win); });
    }
    try {
        if (electron.BrowserWindow && electron.BrowserWindow.getAllWindows) {
            electron.BrowserWindow.getAllWindows().forEach(protect);
        }
    } catch (e) {}
} catch (e) {}
'@
Set-Content -Path $hookPath -Value $hook -Encoding ASCII
Write-Host "Wrote hook: $hookPath" -ForegroundColor Green

$already = Select-String -Path $mainJs -Pattern $marker -SimpleMatch -Quiet
if ($already) {
    Write-Host "main.js already loads the hook (marker present)." -ForegroundColor Yellow
} else {
    if (-not (Test-Path $preBak)) { Copy-Item $mainJs $preBak; Write-Host "Backed up original -> $preBak" -ForegroundColor DarkGray }
    if ($isEsm) {
        $loader = "import('./cp-hook.cjs').catch(function(){{}}); // {0}" -f $marker
    } else {
        $loader = "try{{require('./cp-hook.cjs')}}catch(e){{}} // {0}" -f $marker
    }
    Add-Content -Path $mainJs -Value ("`n" + $loader) -Encoding UTF8
    $mode = if ($isEsm) { 'ESM import()' } else { 'CJS require()' }
    Write-Host ("Injected loader line into main.js ({0})." -f $mode) -ForegroundColor Green
}

Write-Host ''
Write-Host "  ENABLED." -ForegroundColor Green
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "   1. Fully QUIT Cursor - close all windows AND right-click the tray icon > Quit,"
Write-Host "      or run:  Get-Process Cursor | Stop-Process -Force"
Write-Host "   2. Relaunch Cursor."
Write-Host "   3. Verify:  run Check-CursorCaptureState.ps1  (should say HIDDEN),"
Write-Host "      or take a screenshot with Win+Shift+S - Cursor won't be in it."
Write-Host ''
