#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    PhishRonin Expansion Pack — Dependency Installer & Setup
    Run once to install Python tools and configure API keys.

.EXAMPLE
    pwsh -File Setup-PhishRoninExpansion.ps1
    pwsh -File Setup-PhishRoninExpansion.ps1 -ConfigureApiKeys
    pwsh -File Setup-PhishRoninExpansion.ps1 -VerifyOnly
#>
param(
  [switch]$ConfigureApiKeys,
  [switch]$SkipPython,
  [switch]$VerifyOnly
)

$ErrorActionPreference = 'Continue'

Write-Host @"
  ┌──────────────────────────────────────────────────┐
  │  PhishRonin Expansion Pack — Setup               │
  │  HoneyBadger Vanguard 2.0 | THINKPOL Integration │
  └──────────────────────────────────────────────────┘
"@ -ForegroundColor Cyan

# 1. PowerShell version
Write-Host "`n[1/6] PowerShell version..." -ForegroundColor White
if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Error "PS 7.5+ required"; exit 1 }
Write-Host "  OK  PS $($PSVersionTable.PSVersion)" -ForegroundColor Green

# 2. Python
Write-Host "`n[2/6] Python check..." -ForegroundColor White
$python = (Get-Command python3 -ErrorAction SilentlyContinue) ?? (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) { Write-Error "Python 3.x not found. Install from https://python.org"; exit 1 }
$pyVer = & $python.Source --version 2>&1
Write-Host "  OK  $pyVer at $($python.Source)" -ForegroundColor Green

# 3. Python packages
if (-not $SkipPython -and -not $VerifyOnly) {
  Write-Host "`n[3/6] Installing Python packages..." -ForegroundColor White
  @(
    @{ Name='h8mail';           Pip='h8mail';           Phase='Phase 1' },
    @{ Name='holehe';           Pip='holehe';           Phase='Phase 1' },
    @{ Name='sherlock-project'; Pip='sherlock-project'; Phase='Phase 3' },
    @{ Name='maigret';          Pip='maigret';          Phase='Phase 3' }
  ) | ForEach-Object {
    Write-Host "  Installing $($_.Name) ($($_.Phase))..." -NoNewline
    & $python.Source -m pip install $_.Pip --break-system-packages --quiet 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " FAILED — run manually: pip install $($_.Pip) --break-system-packages" -ForegroundColor Red }
  }
} else {
  Write-Host "`n[3/6] Skipping Python install" -ForegroundColor DarkGray
}

# 4. Verify packages
Write-Host "`n[4/6] Verifying packages..." -ForegroundColor White
@('h8mail','holehe','sherlock-project') | ForEach-Object {
  $ver = & $python.Source -m pip show $_ 2>&1 | Select-String 'Version'
  if ($ver) { Write-Host "  OK  $_ : $ver" -ForegroundColor Green }
  else       { Write-Host "  --  $_ : not found" -ForegroundColor Red }
}

# 5. WhatsMyName database
Write-Host "`n[5/6] WhatsMyName database..." -ForegroundColor White
$wmnPath = "$env:APPDATA\PhishRonin\wmn-data.json"
$wmnDir  = Split-Path $wmnPath -Parent
if (-not (Test-Path $wmnDir)) { New-Item -ItemType Directory $wmnDir -Force | Out-Null }
if (-not (Test-Path $wmnPath) -or $VerifyOnly) {
  Write-Host "  Downloading..." -NoNewline
  try {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json' `
      -OutFile $wmnPath -UseBasicParsing
    $cnt = ((Get-Content $wmnPath | ConvertFrom-Json).websites.Count)
    Write-Host " OK ($cnt sites)" -ForegroundColor Green
  } catch { Write-Host " FAILED: $_" -ForegroundColor Red }
} else {
  $cnt = ((Get-Content $wmnPath | ConvertFrom-Json).websites.Count)
  Write-Host "  OK  Cached ($cnt sites) — use -VerifyOnly to re-download" -ForegroundColor Green
}

# 6. API keys
Write-Host "`n[6/6] API key status..." -ForegroundColor White
$apiKeys = @(
  @{ Name='EMAILREP_API_KEY';   Desc='EmailRep.io (optional)';             Url='https://emailrep.io/key';                         Required=$false },
  @{ Name='OTX_API_KEY';        Desc='AlienVault OTX (free)';              Url='https://otx.alienvault.com/accounts/signup';      Required=$true  },
  @{ Name='XFORCE_API_KEY';     Desc='IBM X-Force API Key (optional)';     Url='https://exchange.xforce.ibmcloud.com/settings/api';Required=$false },
  @{ Name='XFORCE_API_PASS';    Desc='IBM X-Force API Pass (optional)';    Url='https://exchange.xforce.ibmcloud.com/settings/api';Required=$false },
  @{ Name='LEAKSAPI_KEY';       Desc='LeaksAPI.io (optional)';             Url='https://leaks-api.io';                            Required=$false },
  @{ Name='HUDSONROCK_API_KEY'; Desc='Hudson Rock (optional)';             Url='https://cavalier.hudsonrock.com';                 Required=$false },
  @{ Name='INTELOWL_API_KEY';   Desc='IntelOwl — generate after deploy';   Url='https://ihbv-ai:4443';                            Required=$false },
  @{ Name='INTELOWL_URL';       Desc='IntelOwl URL (default ihbv-ai:4443)';Url='https://ihbv-ai:4443';                            Required=$false }
)

foreach ($k in $apiKeys) {
  $val    = [System.Environment]::GetEnvironmentVariable($k.Name, 'User')
  $status = if ($val) { 'SET' } elseif ($k.Required) { 'NOT SET (required)' } else { 'not set (optional)' }
  $color  = if ($val) { 'Green' } elseif ($k.Required) { 'Red' } else { 'DarkGray' }
  Write-Host "  $($k.Name) : $status" -ForegroundColor $color

  if ($ConfigureApiKeys -and -not $val) {
    Write-Host "    $($k.Desc) — $($k.Url)" -ForegroundColor DarkCyan
    $newVal = Read-Host "    Enter value (Enter to skip)"
    if ($newVal) {
      [System.Environment]::SetEnvironmentVariable($k.Name, $newVal, 'User')
      Write-Host "    Saved to User environment" -ForegroundColor Green
    }
  }
}

# IntelOwl reminder
Write-Host @"

  ── IntelOwl on iHBV-AI ─────────────────────────────────────
  1. Copy IntelOwl\intelowl-docker-compose.yml to iHBV-AI
  2. docker compose -f intelowl-docker-compose.yml up -d
  3. Create superuser: docker exec -it intelowl_uwsgi python manage.py createsuperuser
  4. Login https://ihbv-ai:4443 -> Profile -> copy API key
  5. [System.Environment]::SetEnvironmentVariable('INTELOWL_API_KEY','KEY','User')

  ── Module test ──────────────────────────────────────────────
"@ -ForegroundColor Yellow

try {
  Import-Module "$PSScriptRoot\modules\RoninTriage-Enrichment.psm1" -Force
  Import-Module "$PSScriptRoot\modules\RoninHunt.psm1"              -Force
  Import-Module "$PSScriptRoot\modules\RoninOsint.psm1"             -Force
  Import-Module "$PSScriptRoot\PhishRonin-Pipeline.psm1"            -Force
  Write-Host "  All modules loaded OK" -ForegroundColor Green

  $test = Invoke-EmailRep -Email "test@gmail.com" -ErrorAction Stop
  Write-Host "  EmailRep test: reputation=$($test.Reputation)" -ForegroundColor Green
} catch {
  Write-Host "  Module error: $_" -ForegroundColor Red
}

Write-Host @"

  ── Ready ────────────────────────────────────────────────────
  Import-Module .\PhishRonin-Pipeline.psm1

  # Quick (Phase 1 only)
  Invoke-PhishRonin -Email "suspicious@example.com" -SkipPhase 2,3

  # Full pipeline
  Invoke-PhishRonin -Email "suspicious@example.com" -FullPipeline

  # CyberShield 2026 demo
  Invoke-PhishRonin -Email "target@evil.ru" -FullPipeline -DemoMode

"@ -ForegroundColor White
