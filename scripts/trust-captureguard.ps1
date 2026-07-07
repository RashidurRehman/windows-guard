<#
  trust-captureguard.ps1

  Installs CaptureGuard's code-signing certificate into this machine's trust
  stores, so Windows treats CaptureGuard-signed binaries as coming from a known,
  verified publisher ("CaptureGuard") instead of an unknown one.

  Run this once. It requires administrator rights and will prompt for them.
#>

$ErrorActionPreference = "Stop"

# Re-launch elevated if we are not already running as administrator.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "Requesting administrator rights..." -ForegroundColor Yellow
  Start-Process powershell -Verb RunAs `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}

$cer = Join-Path $PSScriptRoot "..\signing\CaptureGuard.cer"
if (-not (Test-Path $cer)) {
  Write-Error "Certificate not found: $cer"
  exit 1
}

Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

Write-Host ""
Write-Host "  CaptureGuard's certificate is now trusted on this machine." -ForegroundColor Green
Write-Host "  Signed CaptureGuard binaries will show 'CaptureGuard' as a verified" -ForegroundColor Green
Write-Host "  publisher and will no longer be flagged as an unknown publisher." -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to close"
