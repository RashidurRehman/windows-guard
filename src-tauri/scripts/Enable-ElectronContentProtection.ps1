#requires -Version 5.1
<#
.SYNOPSIS
    Make ANY Electron app exclude itself from screen capture, by patching it to call
    BrowserWindow.setContentProtection(true) on its own windows.

.DESCRIPTION
    Windows only lets a process hide its OWN windows from capture. Electron apps
    (Cursor, VS Code, VSCodium, Windsurf, Signal, ...) expose
    BrowserWindow.setContentProtection(true), which applies WDA_EXCLUDEFROMCAPTURE
    from inside the app - the correct, permanent, injection-free way.

    This drops a tiny hook next to the app's main bundle and makes the main process
    load it. The hook calls setContentProtection(true) on every window as it is
    created. You still see the app normally; recorders/screenshots show the apps
    BEHIND it (show-through), not a black box.

    Works for Electron apps that ship an UNPACKED main bundle (resources\app\
    package.json + main.js) - the VS Code family (Cursor included) does. If the app
    is asar-PACKED (only resources\app.asar), this reports that and you should use
    injection show-through instead.

.PARAMETER Process  Process name without .exe (e.g. Cursor, Code, Windsurf).
.PARAMETER Path     Optional explicit install root OR path to the app's .exe.
.PARAMETER Disable  Undo the patch and restore the original main bundle.

.NOTES
    * No admin needed for per-user installs.
    * You MUST fully quit and relaunch the app for it to take effect.
    * An app update overwrites its folder and removes the patch - just run again.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Process,
    [string]$Path = '',
    [switch]$Disable
)

$ErrorActionPreference = 'Stop'
$marker = 'capture-guard-content-protection'
$Process = $Process -replace '\.exe$', ''

function Find-ElectronRoot {
    # 1) explicit path (exe or folder)
    if ($Path) {
        if (Test-Path $Path -PathType Leaf) { return (Split-Path $Path -Parent) }
        if (Test-Path $Path -PathType Container) { return $Path }
    }
    # 2) from a running instance
    $p = Get-Process -Name $Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path } | Select-Object -First 1
    if ($p) { return (Split-Path $p.Path -Parent) }
    # 3) common per-user / machine install roots
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\$Process",
        "$env:LOCALAPPDATA\Programs\$($Process.ToLower())",
        "$env:PROGRAMFILES\$Process",
        "${env:ProgramFiles(x86)}\$Process"
    )
    foreach ($r in $candidates) {
        if (Test-Path (Join-Path $r 'resources\app\package.json')) { return $r }
        if (Test-Path (Join-Path $r 'resources\app.asar')) { return $r }
    }
    return $null
}

$root = Find-ElectronRoot
if (-not $root) { throw "Could not locate an Electron install for '$Process'. Start the app once, or pass -Path." }

$appDir  = Join-Path $root 'resources\app'
$pkgPath = Join-Path $appDir 'package.json'

if (-not (Test-Path $pkgPath)) {
    if (Test-Path (Join-Path $root 'resources\app.asar')) {
        throw "'$Process' is an asar-packed Electron app (resources\app.asar). The self-patch needs an unpacked bundle; use injection show-through for this app instead."
    }
    throw "'$Process' does not look like a patchable Electron app (no resources\app\package.json under $root)."
}

$pkg     = Get-Content $pkgPath -Raw | ConvertFrom-Json
$mainRel = $pkg.main -replace '^\./', ''
$mainJs  = Join-Path $appDir $mainRel
if (-not (Test-Path $mainJs)) { throw "Main entry not found: $mainJs" }

$outDir   = Split-Path $mainJs -Parent
$hookPath = Join-Path $outDir 'cg-cp-hook.cjs'
$preBak   = "$mainJs.cgbak"
$isEsm    = ($pkg.type -eq 'module') -or ($mainRel -match '\.mjs$')

Write-Host ("Electron app: {0}  (v{1})" -f $root, $pkg.version) -ForegroundColor Cyan
Write-Host ("Main:         {0}" -f $mainJs) -ForegroundColor DarkGray

if ($Disable) {
    if (Test-Path $preBak) {
        Copy-Item $preBak $mainJs -Force
        Remove-Item $preBak -Force
        Write-Host "Restored original main from backup." -ForegroundColor Green
    } else {
        $lines = Get-Content $mainJs
        $kept  = $lines | Where-Object { $_ -notmatch [regex]::Escape($marker) }
        if ($kept.Count -ne $lines.Count) {
            Set-Content -Path $mainJs -Value $kept -Encoding UTF8
            Write-Host "Removed injected loader line." -ForegroundColor Green
        } else {
            Write-Host "No injected line found (already clean)." -ForegroundColor Yellow
        }
    }
    if (Test-Path $hookPath) { Remove-Item $hookPath -Force }
    Write-Host "Disabled. Fully quit and relaunch $Process to apply." -ForegroundColor Yellow
    return
}

# ---- Enable ----
$hook = @'
// CaptureGuard content-protection hook - hides this Electron app's windows from
// screen capture via BrowserWindow.setContentProtection(true).
// marker: capture-guard-content-protection
try {
    var electron = require('electron');
    var app = electron.app;
    var protect = function (win) { try { win.setContentProtection(true); } catch (e) {} };
    if (app && app.on) { app.on('browser-window-created', function (_e, win) { protect(win); }); }
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
    # The marker being present is NOT proof the patch works: an app update can
    # leave the loader line while deleting the hook file it points at. Verify the
    # hook file too, and repair it rather than reporting a false success.
    if (-not (Test-Path $hookPath)) {
        Write-Host "Loader present but hook file was missing - rewritten." -ForegroundColor Yellow
    } else {
        Write-Host "main already loads the hook (marker present)." -ForegroundColor Yellow
    }
} else {
    if (-not (Test-Path $preBak)) { Copy-Item $mainJs $preBak; Write-Host "Backed up original -> $preBak" -ForegroundColor DarkGray }
    if ($isEsm) { $loader = "import('./cg-cp-hook.cjs').catch(function(){{}}); // {0}" -f $marker }
    else        { $loader = "try{{require('./cg-cp-hook.cjs')}}catch(e){{}} // {0}" -f $marker }
    Add-Content -Path $mainJs -Value ("`n" + $loader) -Encoding UTF8
    Write-Host ("Injected loader into main ({0})." -f $(if ($isEsm) { 'ESM' } else { 'CJS' })) -ForegroundColor Green
}

Write-Host "ENABLED. Fully quit and relaunch $Process to apply." -ForegroundColor Green
