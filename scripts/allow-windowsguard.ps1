<#
  allow-windowsguard.ps1

  Makes this machine treat Windows Guard as a safe, verified app:
    1. Adds a Windows Defender exclusion for Windows Guard (process + its
       folders) so its injection behaviour is not flagged.
    2. Trusts Windows Guard's code-signing certificate system-wide, so signed
       Windows Guard binaries show "Windows Guard" as a verified publisher.

  TRADE-OFF: the Defender exclusion means Defender stops scanning those paths.
  Only do this because Windows Guard is your own tool.

  Requires administrator rights (it will prompt). Note: if Tamper Protection
  is on, the Defender-exclusion step may be silently skipped — add it manually
  via Windows Security -> Virus & threat protection -> Manage settings ->
  Exclusions in that case. Reverse this script with:
    - Remove-MpPreference -ExclusionProcess "windows-guard.exe"
    - Remove-MpPreference -ExclusionPath "<the paths below>"
    - scripts\untrust-windowsguard.ps1
#>

$ErrorActionPreference = "Stop"

# Re-launch elevated if not already admin.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "Requesting administrator rights..." -ForegroundColor Yellow
  Start-Process powershell -Verb RunAs `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}

$cer = Join-Path $PSScriptRoot "..\signing\WindowsGuard.cer"

# 1) Defender exclusions -----------------------------------------------------
$paths = @(
  "$env:LOCALAPPDATA\capture-guard-release",
  "$env:LOCALAPPDATA\capture-guard-build",
  "$env:LOCALAPPDATA\Windows Guard"
)
try {
  Add-MpPreference -ExclusionProcess "windows-guard.exe" -ErrorAction Stop
  foreach ($p in $paths) { Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue }
  Write-Host "  Defender: Windows Guard added to exclusions." -ForegroundColor Green
} catch {
  Write-Host "  Defender exclusion skipped: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 2) Trust the code-signing certificate --------------------------------------
if (Test-Path $cer) {
  Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
  Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
  Write-Host "  Certificate: 'Windows Guard' is now a trusted, verified publisher." -ForegroundColor Green
} else {
  Write-Host "  Certificate not found at $cer" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Done. Windows Guard is now treated as a safe, verified app on this PC." -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to close"
