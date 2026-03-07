#Requires -Version 7.0
<#
.SYNOPSIS
    PhishRonin Full Pipeline — THINKPOL Expansion Pack v2.0
    Phases 1-3 unified orchestrator with HTML report output

.DESCRIPTION
    Integrates all THINKPOL expansion phases with existing PhishRonin:

    Phase 1  RoninTriage-Enrichment  EmailRep + h8mail + holehe
    Phase 2  RoninHunt               IntelOwl + OTX + X-Force + BreachCorrelate
    Phase 3  RoninOsint              Sherlock + WhatsMyName + THINKPOL Reddit

.EXAMPLE
    # Quick triage (Phase 1 only, no Python needed)
    Invoke-PhishRonin -Email "suspicious@evil.ru" -SkipPhase 2,3

    # Full pipeline
    Invoke-PhishRonin -Email "phisher@protonmail.com" -FullPipeline

    # CyberShield 2026 live demo mode
    Invoke-PhishRonin -Email "demo@target.com" -FullPipeline -DemoMode

    # Wire into existing PhishRonin workflow
    $evidence | Invoke-PhishRonin -EmailOverride $evidence.Message.From

.NOTES
    Author      : HoneyBadger (HoneyBadger Vanguard, LLC)
    Version     : 2.0.0 (THINKPOL Expansion)
    CyberShield : 2026 — Little Rock, AR
    Attribution : THINKPOL (think-pol.com) @101R00M, Sherlock, WhatsMyName
                  (WebBreacher), h8mail (khast3x), holehe (megadose),
                  IntelOwl (intelowlproject), AlienVault OTX, IBM X-Force,
                  LeaksAPI, Hudson Rock
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Auto-import expansion modules relative to this file ──────────────────────
$ModuleDir = Join-Path $PSScriptRoot 'modules'
foreach ($mod in @('RoninTriage-Enrichment','RoninHunt','RoninOsint')) {
  $modPath = Join-Path $ModuleDir "$mod.psm1"
  if (Test-Path $modPath) {
    Import-Module $modPath -Force -ErrorAction SilentlyContinue
  } else {
    Write-Warning "PhishRonin-Pipeline: module not found — $modPath"
  }
}

function Invoke-PhishRonin {
  <#
  .SYNOPSIS
      Full PhishRonin enrichment pipeline — Phases 1 through 3.
  .PARAMETER Email
      Target email address (sender from phishing investigation).
  .PARAMETER FullPipeline
      Enable slower tools: h8mail, holehe, Sherlock, WhatsMyName.
  .PARAMETER SkipPhase
      Skip specific phases by number, e.g. -SkipPhase 2,3
  .PARAMETER DemoMode
      CyberShield demo mode — verbose console output, all stages, dramatic flair.
  .PARAMETER OutputDir
      Directory to save HTML reports.
  .PARAMETER NoReport
      Skip HTML report generation (return object only).
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Email,
    [Parameter()][switch]$FullPipeline,
    [Parameter()][int[]]$SkipPhase = @(),
    [Parameter()][switch]$DemoMode,
    [Parameter()][string]$OutputDir = "$env:USERPROFILE\PhishRonin\Reports",
    [Parameter()][switch]$NoReport
  )
  process {
    $startTime = Get-Date
    if ($DemoMode) {
      Write-Host @"

  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗  ██████╗ ███╗   ██╗██╗███╗   ██╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗██╔═══██╗████╗  ██║██║████╗  ██║
  ██████╔╝███████║██║███████╗███████║    ██████╔╝██║   ██║██╔██╗ ██║██║██╔██╗ ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██╗██║   ██║██║╚██╗██║██║██║╚██╗██║
  ██║     ██║  ██║██║███████║██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║██║██║ ╚████║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝
  HoneyBadger Vanguard 2.0 | THINKPOL Expansion Pack v2.0.0
  TARGET: $Email | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC
"@ -ForegroundColor Cyan
    }

    $p1 = $null; $p2 = $null; $p3 = $null

    # Phase 1
    if (1 -notin $SkipPhase) {
      Write-Host "`n[PHASE 1] Email Enrichment" -ForegroundColor Cyan
      $p1Params = @{ Email = $Email }
      if (-not $FullPipeline) { $p1Params.SkipH8Mail = $true; $p1Params.SkipHolehe = $true }
      $p1 = Invoke-RoninTriageEnrich @p1Params
      if ($DemoMode) { Start-Sleep -Milliseconds 600 }
    }

    # Phase 2
    if (2 -notin $SkipPhase) {
      Write-Host "`n[PHASE 2] Threat Intelligence" -ForegroundColor Yellow
      $p2Params = @{ Email = $Email }
      if (-not $env:INTELOWL_API_KEY) { $p2Params.SkipIntelOwl = $true }
      $p2 = Invoke-RoninHuntEnrich @p2Params
      if ($DemoMode) { Start-Sleep -Milliseconds 600 }
    }

    # Phase 3
    if (3 -notin $SkipPhase) {
      Write-Host "`n[PHASE 3] Identity Pivot" -ForegroundColor Magenta
      $p3Params = @{ Email = $Email }
      if (-not $FullPipeline) { $p3Params.SkipSherlock = $true; $p3Params.SkipWhatsMyName = $true }
      $p3 = Invoke-RoninIdentityPivot @p3Params
      if ($DemoMode) { Start-Sleep -Milliseconds 600 }
    }

    $finalScore = [Math]::Min((($p1?.ThreatScore ?? 0) + ($p2?.ThreatScore ?? 0) + ($p3?.ThreatScore ?? 0)), 100)
    $allFlags   = @(@($p1?.Flags),@($p2?.Flags),@($p3?.ThreatKeywords | ForEach-Object {"KW:$_"})) |
                  ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique
    $verdict = switch ($finalScore) {
      { $_ -ge 80 } { 'CRITICAL — Confirmed Threat Actor'   }
      { $_ -ge 60 } { 'HIGH — Strong Malicious Indicators'  }
      { $_ -ge 40 } { 'MEDIUM — Suspicious Activity'        }
      { $_ -ge 20 } { 'LOW — Minor Indicators'              }
      default       { 'CLEAN — No Significant Findings'     }
    }
    $elapsed = (Get-Date) - $startTime

    Write-Host "`n$('─' * 65)" -ForegroundColor DarkGray
    Write-Host "  VERDICT  : $verdict" -ForegroundColor $(if($finalScore -ge 60){'Red'}elseif($finalScore -ge 30){'Yellow'}else{'Green'})
    Write-Host "  SCORE    : $finalScore / 100" -ForegroundColor White
    Write-Host "  EMAIL    : $Email" -ForegroundColor White
    if ($allFlags) { Write-Host "  FLAGS    : $($allFlags -join ' | ')" -ForegroundColor Yellow }
    if ($p3?.TopCommunities) { Write-Host "  REDDIT   : $($p3.TopCommunities)" -ForegroundColor Magenta }
    Write-Host "  ELAPSED  : $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor DarkGray
    Write-Host "$('─' * 65)`n" -ForegroundColor DarkGray

    $result = [PSCustomObject]@{
      PSTypeName      = 'PhishRonin.FinalResult'
      Email           = $Email
      FinalScore      = $finalScore
      Verdict         = $verdict
      Flags           = @($allFlags)
      Phase1          = $p1
      Phase2          = $p2
      Phase3          = $p3
      RedditProfile   = $p3?.RedditProfile
      TopCommunities  = $p3?.TopCommunities
      ThreatKeywords  = $p3?.ThreatKeywords ?? @()
      AccountsFound   = $p3?.TotalAccountsFound ?? 0
      ElapsedSeconds  = [int]$elapsed.TotalSeconds
      Attribution     = @{
        THINKPOL    = 'https://think-pol.com (@101R00M)'
        Sherlock    = 'https://github.com/sherlock-project/sherlock'
        WhatsMyName = 'https://github.com/WebBreacher/WhatsMyName'
        h8mail      = 'https://github.com/khast3x/h8mail'
        holehe      = 'https://github.com/megadose/holehe'
        IntelOwl    = 'https://github.com/intelowlproject/IntelOwl'
      }
      Timestamp       = Get-Date -Format 'o'
    }

    if (-not $NoReport) {
      if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
      $ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
      $reportPath = Join-Path $OutputDir "PhishRonin_$($Email -replace '[^a-zA-Z0-9]','_')_$ts.html"
      $result | Export-PhishRoninEnrichReport -OutputPath $reportPath
      Write-Host "  Report: $reportPath" -ForegroundColor Cyan
    }
    return $result
  }
}

function Export-PhishRoninEnrichReport {
  <#
  .SYNOPSIS
      Generate HTML enrichment report from PhishRonin pipeline results.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)][PSCustomObject]$Result,
    [Parameter(Mandatory)][string]$OutputPath
  )
  $sc = switch ($Result.FinalScore) {
    { $_ -ge 80 } { '#d32f2f' } { $_ -ge 60 } { '#f57c00' }
    { $_ -ge 40 } { '#fbc02d' } default { '#388e3c' }
  }
  $flagsHtml    = ($Result.Flags | ForEach-Object { "<span class='flag'>$_</span>" }) -join ' '
  $accountsHtml = if ($Result.Phase3?.AllAccounts) {
    ($Result.Phase3.AllAccounts | ForEach-Object { "<tr><td>$($_.Site)</td><td><a href='$($_.URL)' target='_blank'>$($_.URL)</a></td></tr>" }) -join ''
  } else { '<tr><td colspan="2" style="color:#8b949e">No accounts discovered</td></tr>' }
  $redditHtml = if ($Result.RedditProfile?.Exists) {
    $r = $Result.RedditProfile.PersonaProfile ?? $Result.RedditProfile
    "<table class='dt'><tr><th>Username</th><td>u/$($r.Username)</td></tr>" +
    "<tr><th>Age</th><td>$($r.AccountAgeDays) days</td></tr>" +
    "<tr><th>Karma</th><td>$($r.TotalKarma)</td></tr>" +
    "<tr><th>Communities</th><td>$($Result.TopCommunities)</td></tr>" +
    "<tr><th>Activity</th><td>$($r.InferredTimezone)</td></tr>" +
    "<tr><th>Threat KW</th><td>$(if($r.ThreatKeywordHits -gt 0){"<span class='flag'>$($r.ThreatKeywords -join ', ')</span>"}else{'None'})</td></tr>" +
    "</table><p style='font-size:.75rem;color:#8b949e'>Methodology: <a href='https://think-pol.com'>THINKPOL</a> (@101R00M)</p>"
  } else { '<p style="color:#8b949e">No Reddit profile found or analysis skipped</p>' }

  $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>PhishRonin Enrichment — $($Result.Email)</title>
<style>
* { box-sizing:border-box; margin:0; padding:0 }
body { font-family:'Segoe UI',sans-serif; background:#0d1117; color:#c9d1d9 }
header { background:#161b22; padding:20px 36px; border-bottom:1px solid #30363d }
header h1 { color:#58a6ff; font-size:1.4rem; letter-spacing:2px }
header .sub { color:#8b949e; font-size:.8rem; margin-top:4px }
.sbar { background:#161b22; padding:16px 36px; display:flex; align-items:center; gap:20px; border-bottom:1px solid #30363d }
.sc { width:72px; height:72px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:1.6rem; font-weight:bold; background:$sc; color:#fff }
.verdict { font-size:1.1rem; font-weight:bold; color:$sc }
.content { padding:28px 36px; max-width:1100px }
section { margin-bottom:28px; background:#161b22; border:1px solid #30363d; border-radius:8px; padding:18px }
h2 { color:#58a6ff; font-size:.9rem; text-transform:uppercase; letter-spacing:1px; margin-bottom:14px; border-bottom:1px solid #30363d; padding-bottom:7px; display:flex; justify-content:space-between }
.badge { background:#0d1117; border:1px solid #30363d; border-radius:10px; padding:1px 9px; font-size:.75rem; color:#8b949e }
.flag { background:#3d1f00; color:#f0883e; border:1px solid #f0883e; border-radius:3px; padding:1px 7px; font-size:.75rem; margin:2px; display:inline-block; font-family:monospace }
.dt { width:100%; border-collapse:collapse; font-size:.83rem }
.dt th { color:#8b949e; text-align:left; padding:5px 10px; width:150px }
.dt td { padding:5px 10px; border-bottom:1px solid #21262d }
.dt a { color:#58a6ff; text-decoration:none }
footer { padding:16px 36px; border-top:1px solid #30363d; color:#484f58; font-size:.75rem; text-align:center }
footer a { color:#58a6ff; text-decoration:none }
</style></head><body>
<header><h1>⚔ PHISHRONIN — ENRICHMENT REPORT</h1>
<div class="sub">HoneyBadger Vanguard 2.0 | THINKPOL Expansion | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC</div></header>
<div class="sbar">
  <div class="sc">$($Result.FinalScore)</div>
  <div><div class="verdict">$($Result.Verdict)</div>
  <div style="color:#8b949e;font-size:.85rem;margin-top:4px">$($Result.Email)</div>
  <div style="margin-top:8px">$flagsHtml</div></div>
</div>
<div class="content">
<section>
  <h2>Phase 1 — Email Enrichment <span class="badge">+$($Result.Phase1?.ThreatScore ?? 0) pts</span></h2>
  <table class="dt">
    <tr><th>EmailRep</th><td>$($Result.Phase1?.Reputation ?? 'N/A')</td></tr>
    <tr><th>Suspicious</th><td>$($Result.Phase1?.EmailRepResult?.Suspicious)</td></tr>
    <tr><th>Disposable</th><td>$($Result.Phase1?.EmailRepResult?.Disposable)</td></tr>
    <tr><th>Recent Abuse</th><td>$($Result.Phase1?.EmailRepResult?.RecentAbuse)</td></tr>
    <tr><th>Breaches (h8mail)</th><td>$($Result.Phase1?.BreachCount)</td></tr>
    <tr><th>Accounts (holehe)</th><td>$($Result.Phase1?.AccountsFound) — $($Result.Phase1?.RegisteredSites -join ', ')</td></tr>
  </table>
</section>
<section>
  <h2>Phase 2 — Threat Intelligence <span class="badge">+$($Result.Phase2?.ThreatScore ?? 0) pts</span></h2>
  <table class="dt">
    <tr><th>OTX Pulses</th><td>$($Result.Phase2?.OTXResult?.PulseCount ?? 0)</td></tr>
    <tr><th>X-Force Score</th><td>$($Result.Phase2?.XForceResult?.RiskScore ?? 'N/A')</td></tr>
    <tr><th>LeaksAPI</th><td>$($Result.Phase2?.BreachResult?.LeaksAPITotal ?? 0) records</td></tr>
    <tr><th>Infostealer Hits</th><td>$($Result.Phase2?.BreachResult?.InfostealerHits ?? 0)</td></tr>
    <tr><th>Stealer Families</th><td>$($Result.Phase2?.BreachResult?.StealerFamilies -join ', ')</td></tr>
    <tr><th>IntelOwl</th><td>$($Result.Phase2?.IntelOwlResult?.JobStatus ?? 'Not deployed')</td></tr>
  </table>
</section>
<section>
  <h2>Phase 3 — Identity Pivot <span class="badge">+$($Result.Phase3?.ThreatScore ?? 0) pts</span></h2>
  <table class="dt" style="margin-bottom:14px">
    <tr><th>Variants</th><td>$($Result.Phase3?.UsernameVariants -join ', ')</td></tr>
    <tr><th>Accounts Found</th><td>$($Result.AccountsFound)</td></tr>
  </table>
  <h3 style="color:#79c0ff;font-size:.85rem;margin-bottom:8px">Reddit Behavioral Profile</h3>
  $redditHtml
  <h3 style="color:#79c0ff;font-size:.85rem;margin:12px 0 8px">Discovered Accounts</h3>
  <table class="dt"><tr><th>Site</th><th>URL</th></tr>$accountsHtml</table>
</section>
</div>
<footer>PhishRonin v2.0 | HoneyBadger Vanguard, LLC | CyberShield 2026<br>
Attribution: <a href="https://think-pol.com">THINKPOL</a> (@101R00M) &bull;
<a href="https://github.com/sherlock-project/sherlock">Sherlock</a> &bull;
<a href="https://github.com/WebBreacher/WhatsMyName">WhatsMyName</a> &bull;
<a href="https://github.com/khast3x/h8mail">h8mail</a> &bull;
<a href="https://github.com/megadose/holehe">holehe</a> &bull;
<a href="https://github.com/intelowlproject/IntelOwl">IntelOwl</a></footer>
</body></html>
"@
  $html | Set-Content -Path $OutputPath -Encoding UTF8
}

Export-ModuleMember -Function Invoke-PhishRonin, Export-PhishRoninEnrichReport
