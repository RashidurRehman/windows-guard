<#
  untrust-windowsguard.ps1

  Removes Windows Guard's code-signing certificate from this machine's trust
  stores — the reverse of trust-windowsguard.ps1. Requires administrator rights.
#>

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
  Write-Host "Requesting administrator rights..." -ForegroundColor Yellow
  Start-Process powershell -Verb RunAs `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit
}

$removed = 0
foreach ($store in @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher")) {
  Get-ChildItem $store | Where-Object { $_.Subject -eq "CN=Windows Guard" } | ForEach-Object {
    Remove-Item $_.PSPath -Force
    $removed++
  }
}

Write-Host ""
Write-Host "  Removed $removed Windows Guard certificate entr(ies) from the trust stores." -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to close"
