#requires -Version 5.1
<#
    Return icons (PNG data URIs) for a set of process names, keyed by lowercase
    process name. For Store/UWP apps (e.g. WhatsApp) the real logo lives in the
    package assets, so we read that; for classic apps we extract the exe icon;
    otherwise we fall back to a Start Menu shortcut target.
    Usage: -Processes "whatsapp.root,brave,cursor"
#>
param([string]$Processes = '')
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing | Out-Null

function Get-IconDataUri([string]$path) {
    try {
        $ico = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
        if (-not $ico) { return $null }
        $bmp = $ico.ToBitmap()
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $b64 = [Convert]::ToBase64String($ms.ToArray())
        $ms.Dispose(); $bmp.Dispose(); $ico.Dispose()
        return "data:image/png;base64,$b64"
    } catch { return $null }
}

function Get-PngDataUri([string]$path) {
    try { return "data:image/png;base64," + [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
    catch { return $null }
}

# For a Store/UWP exe path, find the package's best square logo asset.
function Get-UwpLogo([string]$exePath) {
    if (-not $exePath) { return $null }
    $pkg = Get-AppxPackage -ErrorAction SilentlyContinue |
        Where-Object { $_.InstallLocation -and $exePath.StartsWith($_.InstallLocation, [StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
    if (-not $pkg) { return $null }
    $pngs = Get-ChildItem $pkg.InstallLocation -Recurse -Filter '*.png' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Square44x44Logo|StoreLogo|Square71x71Logo|Square150x150Logo' -and $_.Name -notmatch 'contrast' }
    if (-not $pngs) { return $null }
    # Prefer a crisp ~44px square logo, then the store logo, then larger squares.
    $order = @(
        'Square44x44Logo\.scale-200', 'Square44x44Logo\.targetsize-32', 'Square44x44Logo\.targetsize-44',
        'Square44x44Logo\.targetsize-24', 'Square44x44Logo\.scale-100', 'Square44x44Logo',
        'StoreLogo\.scale-200', 'StoreLogo', 'Square71x71Logo', 'Square150x150Logo'
    )
    foreach ($pat in $order) {
        $m = $pngs | Where-Object { $_.Name -match $pat } | Sort-Object Length -Descending | Select-Object -First 1
        if ($m) { return (Get-PngDataUri $m.FullName) }
    }
    return (Get-PngDataUri (($pngs | Sort-Object Length -Descending | Select-Object -First 1).FullName))
}

$names = @($Processes -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
$result = @{}

# 1) running processes (Store logo for UWP apps, else the exe icon)
foreach ($n in $names) {
    $p = Get-Process -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
    if ($p) {
        $uri = $null
        if ($p.Path -match '\\WindowsApps\\') { $uri = Get-UwpLogo $p.Path }
        if (-not $uri) { $uri = Get-IconDataUri $p.Path }
        if ($uri) { $result[$n] = $uri }
    }
}

# 2) fall back to Start Menu shortcuts for any still missing
$missing = @($names | Where-Object { -not $result.ContainsKey($_) })
if ($missing.Count -gt 0) {
    $sh = New-Object -ComObject WScript.Shell
    $dirs = @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'),
        (Join-Path $env:APPDATA    'Microsoft\Windows\Start Menu\Programs')
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { continue }
        Get-ChildItem $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $t = $null
            try { $t = $sh.CreateShortcut($_.FullName).TargetPath } catch { return }
            if (-not $t -or $t -notmatch '\.exe$' -or -not (Test-Path $t)) { return }
            $b = [System.IO.Path]::GetFileNameWithoutExtension($t).ToLower()
            if (($missing -contains $b) -and -not $result.ContainsKey($b)) {
                $uri = Get-IconDataUri $t
                if ($uri) { $result[$b] = $uri }
            }
        }
    }
}

if ($result.Count -eq 0) { '{}' }
else { ConvertTo-Json -InputObject $result -Compress }
