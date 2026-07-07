#requires -Version 5.1
<#
    Enumerate installed desktop apps for the "Add app" picker:
    resolve Start Menu shortcuts -> target .exe, grab a display name, the process
    name, an icon (PNG data URI), and a best-guess protection method (Electron
    self-patch vs injection). Emits a JSON array on stdout.
#>
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

$sh = New-Object -ComObject WScript.Shell
$dirs = @(
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'),
    (Join-Path $env:APPDATA    'Microsoft\Windows\Start Menu\Programs')
)

$skip = '^(unins|uninstall|setup|update|updater|installer|readme|help|website|homepage|documentation|repair|modify|remove)'
$apps = @{}

foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { continue }
    Get-ChildItem $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        $lnkName = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
        $target = $null
        try { $target = $sh.CreateShortcut($_.FullName).TargetPath } catch { return }
        if (-not $target) { return }
        if ($target -notmatch '\.exe$') { return }
        if (-not (Test-Path $target)) { return }

        $base = [System.IO.Path]::GetFileNameWithoutExtension($target)
        if ($base -match $skip -or $lnkName -match $skip) { return }
        # skip obvious Windows/system utilities living under System32
        if ($target -match '\\Windows\\System32\\' -or $target -match '\\Windows\\SysWOW64\\') { return }

        $key = $target.ToLower()
        if ($apps.ContainsKey($key)) { return }

        $dir = Split-Path $target -Parent
        $method = 'inject'
        if (Test-Path (Join-Path $dir 'resources\app\package.json')) { $method = 'electron-patch' }
        elseif (Test-Path (Join-Path $dir 'resources\app.asar'))     { $method = 'inject' }

        $apps[$key] = [pscustomobject]@{
            name    = $lnkName
            exe     = $target
            process = $base
            method  = $method
            icon    = (Get-IconDataUri $target)
        }
    }
}

# Always emit a JSON array (even for 0/1 items).
$list = @($apps.Values | Sort-Object name)
if ($list.Count -eq 0) { '[]' }
else { ConvertTo-Json -InputObject $list -Depth 4 -Compress }
