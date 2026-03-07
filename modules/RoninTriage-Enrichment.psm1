#Requires -Version 7.0
<#
.SYNOPSIS
    RoninTriage Enrichment Module - THINKPOL Expansion Phase 1
    EmailRep + h8mail + holehe integration for PhishRonin pipeline

.DESCRIPTION
    Adds three new enrichment stages callable standalone or wired into the
    PhishRonin Evidence pipeline alongside the existing RoninTriage.psm1:

      Invoke-EmailRep    - Reputation + threat scoring via emailrep.io
      Invoke-H8Mail      - Breach/password hunting via h8mail (Python subprocess)
      Invoke-Holehe      - Email-to-account pivot (250+ sites) via holehe
      Invoke-RoninTriageEnrich - Unified Phase 1 orchestrator

    Install Python deps:
      pip install h8mail holehe --break-system-packages

.NOTES
    Author      : HoneyBadger (HoneyBadger Vanguard, LLC)
    Module      : RoninTriage-Enrichment
    Version     : 1.0.0
    Attribution : emailrep.io, h8mail (github.com/khast3x/h8mail),
                  holehe (github.com/megadose/holehe)
    CyberShield : 2026 Demo Ready
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:TriageEnrichConfig = @{
  EmailRep = @{
    BaseUrl    = 'https://emailrep.io'
    ApiKey     = $env:EMAILREP_API_KEY
    UserAgent  = 'PhishRonin/2.0 (HoneyBadgerVanguard)'
    TimeoutSec = 15
  }
  H8Mail = @{
    PythonExe  = 'python3'
    OutputDir  = "$env:TEMP\ronin_h8mail"
    TimeoutSec = 120
  }
  Holehe = @{
    PythonExe  = 'python3'
    TimeoutSec = 90
  }
  Scoring = @{
    BreachFound      = 25
    SuspiciousRep    = 20
    MaliciousRep     = 40
    AccountsFound    = 10   # per 5 accounts
    DisposableEmail  = 15
    RecentAbuse      = 20
    FreeProvider     = 5
    Spam             = 10
  }
}

function Invoke-EmailRep {
  <#
  .SYNOPSIS
      Query emailrep.io for email reputation and threat intelligence.
  .DESCRIPTION
      Returns reputation score, suspicious/malicious flags, deliverability,
      breach history, domain age, and a PhishRonin score contribution.
  .PARAMETER Email
      Email address to investigate.
  .PARAMETER ApiKey
      Optional EmailRep API key for higher rate limits.
  .EXAMPLE
      Invoke-EmailRep -Email "suspicious@tempmail.com"
  .EXAMPLE
      Get-Content emails.txt | Invoke-EmailRep
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$Email,
    [Parameter()][string]$ApiKey = $script:TriageEnrichConfig.EmailRep.ApiKey,
    [Parameter()][switch]$Raw
  )
  process {
    $headers = @{
      'User-Agent' = $script:TriageEnrichConfig.EmailRep.UserAgent
      'Accept'     = 'application/json'
    }
    if ($ApiKey) { $headers['Key'] = $ApiKey }
    try {
      $resp = Invoke-RestMethod -Uri "$($script:TriageEnrichConfig.EmailRep.BaseUrl)/$([Uri]::EscapeDataString($Email))" `
                -Headers $headers -TimeoutSec $script:TriageEnrichConfig.EmailRep.TimeoutSec -Method GET
      if ($Raw) { return $resp }

      $scoreAdd = 0; $flags = [System.Collections.Generic.List[string]]::new()
      if ($resp.suspicious)                 { $scoreAdd += $script:TriageEnrichConfig.Scoring.SuspiciousRep; $flags.Add('SUSPICIOUS')    }
      if ($resp.details.malicious_activity) { $scoreAdd += $script:TriageEnrichConfig.Scoring.MaliciousRep;  $flags.Add('MALICIOUS')     }
      if ($resp.details.credentials_leaked) { $scoreAdd += $script:TriageEnrichConfig.Scoring.BreachFound;   $flags.Add('BREACH')        }
      if ($resp.details.disposable)         { $scoreAdd += $script:TriageEnrichConfig.Scoring.DisposableEmail; $flags.Add('DISPOSABLE')  }
      if ($resp.details.recent_abuse)       { $scoreAdd += $script:TriageEnrichConfig.Scoring.RecentAbuse;   $flags.Add('RECENT_ABUSE')  }
      if ($resp.details.free_provider)      { $scoreAdd += $script:TriageEnrichConfig.Scoring.FreeProvider;  $flags.Add('FREE_PROVIDER') }
      if ($resp.details.spam)               { $scoreAdd += $script:TriageEnrichConfig.Scoring.Spam;          $flags.Add('SPAM')          }

      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.EmailRepResult'
        Email             = $Email
        Reputation        = $resp.reputation
        Suspicious        = [bool]$resp.suspicious
        References        = [int]$resp.references
        Deliverable       = [bool]$resp.details.deliverable
        DomainExists      = [bool]$resp.details.domain_exists
        DomainReputation  = $resp.details.domain_reputation
        NewDomain         = [bool]$resp.details.new_domain
        Blacklisted       = [bool]$resp.details.blacklisted
        MaliciousActivity = [bool]$resp.details.malicious_activity
        CredentialsLeaked = [bool]$resp.details.credentials_leaked
        Disposable        = [bool]$resp.details.disposable
        RecentAbuse       = [bool]$resp.details.recent_abuse
        FreeMail          = [bool]$resp.details.free_provider
        Spam              = [bool]$resp.details.spam
        Flags             = $flags.ToArray()
        ScoreContribution = $scoreAdd
        Source            = 'emailrep.io'
        Timestamp         = Get-Date -Format 'o'
      }
    } catch {
      Write-Warning "EmailRep error for $Email : $_"
      return [PSCustomObject]@{
        PSTypeName = 'PhishRonin.EmailRepResult'; Email = $Email
        Error = $_.Exception.Message; ScoreContribution = 0; Source = 'emailrep.io'
        Timestamp = Get-Date -Format 'o'
      }
    }
  }
}

function Invoke-H8Mail {
  <#
  .SYNOPSIS
      Hunt breached credentials via h8mail (Python subprocess wrapper).
  .DESCRIPTION
      Searches multiple breach sources: HaveIBeenPwned, scylla.sh,
      leak-lookup.com, intelx.io, and optional local breach files.
      Install: pip install h8mail --break-system-packages
      Credit: h8mail — https://github.com/khast3x/h8mail
  .PARAMETER Email
      Target email address(es).
  .PARAMETER LocalBreachFile
      Path to local breach file/directory for offline searching.
  .EXAMPLE
      Invoke-H8Mail -Email "target@example.com"
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string[]]$Email,
    [Parameter()][string]$LocalBreachFile,
    [Parameter()][string]$PythonExe = $script:TriageEnrichConfig.H8Mail.PythonExe
  )
  begin {
    $allEmails = [System.Collections.Generic.List[string]]::new()
    $outputDir = $script:TriageEnrichConfig.H8Mail.OutputDir
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
  }
  process { $allEmails.AddRange([string[]]$Email) }
  end {
    $sid        = [System.Guid]::NewGuid().ToString('N').Substring(0,8)
    $outFile    = Join-Path $outputDir "h8mail_$sid.json"
    $targFile   = Join-Path $outputDir "targets_$sid.txt"
    $allEmails | Set-Content -Path $targFile -Encoding UTF8
    $args = @('-m','h8mail','-t',$targFile,'--json',$outFile)
    if ($LocalBreachFile) { $args += '--local-breach',$LocalBreachFile }
    try {
      Start-Process -FilePath $PythonExe -ArgumentList $args -Wait -NoNewWindow `
        -RedirectStandardOutput "$outputDir\stdout_$sid.txt" `
        -RedirectStandardError  "$outputDir\stderr_$sid.txt" | Out-Null
      if (-not (Test-Path $outFile)) {
        Write-Warning "h8mail produced no output. Check stderr: $outputDir\stderr_$sid.txt"
        return
      }
      foreach ($entry in (Get-Content $outFile -Raw | ConvertFrom-Json)) {
        $breaches = @($entry.results | Where-Object { $_.type -eq 'breach' } | ForEach-Object { $_.source })
        $pwCount  = ($entry.results | Where-Object { $_.data -match 'password|passwd' }).Count
        [PSCustomObject]@{
          PSTypeName        = 'PhishRonin.H8MailResult'
          Email             = $entry.target
          BreachCount       = $breaches.Count
          BreachSources     = $breaches
          PasswordsFound    = ($pwCount -gt 0)
          PasswordCount     = $pwCount
          ScoreContribution = if ($breaches.Count -gt 0) { $script:TriageEnrichConfig.Scoring.BreachFound } else { 0 }
          Source            = 'h8mail'
          Timestamp         = Get-Date -Format 'o'
        }
      }
    } finally {
      Remove-Item $targFile,"$outputDir\stdout_$sid.txt","$outputDir\stderr_$sid.txt" -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-Holehe {
  <#
  .SYNOPSIS
      Pivot email address to registered accounts across 250+ sites via holehe.
  .DESCRIPTION
      Uses holehe's "forgot password" flow to discover registrations without
      attempting login. Pure passive enumeration.
      Install: pip install holehe --break-system-packages
      Credit: holehe — https://github.com/megadose/holehe
  .PARAMETER Email
      Target email address.
  .PARAMETER OnlyRegistered
      Return only confirmed registrations (filter out rate-limited results).
  .EXAMPLE
      Invoke-Holehe -Email "target@gmail.com" -OnlyRegistered
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[^@]+@[^@]+\.[^@]+$')]
    [string]$Email,
    [Parameter()][switch]$OnlyRegistered,
    [Parameter()][string]$PythonExe = $script:TriageEnrichConfig.Holehe.PythonExe
  )
  process {
    Write-Verbose "Holehe pivot: $Email"
    try {
      $cliResult  = & $PythonExe -m holehe $Email --only-used 2>&1
      $registered = $cliResult | Where-Object { $_ -match '\[.*\+.*\]|\[✔\]' } |
                    ForEach-Object { ($_ -split '\s+' | Where-Object { $_ })[1] }
      $scoreAdd = [Math]::Min(($registered.Count / 5) * $script:TriageEnrichConfig.Scoring.AccountsFound, 50)
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.HoleheResult'
        Email             = $Email
        AccountsFound     = $registered.Count
        RegisteredSites   = @($registered)
        ScoreContribution = $scoreAdd
        Source            = 'holehe'
        Timestamp         = Get-Date -Format 'o'
      }
    } catch {
      Write-Warning "Holehe error for $Email : $_"
      return [PSCustomObject]@{
        PSTypeName = 'PhishRonin.HoleheResult'; Email = $Email
        Error = $_.Exception.Message; ScoreContribution = 0; Source = 'holehe'
        Timestamp = Get-Date -Format 'o'
      }
    }
  }
}

function Invoke-RoninTriageEnrich {
  <#
  .SYNOPSIS
      Run all Phase 1 enrichment tools against an email address.
  .DESCRIPTION
      Orchestrates EmailRep + h8mail + holehe, aggregates results,
      and returns a unified enrichment object ready for the PhishRonin
      Evidence pipeline and HTML report.
  .PARAMETER Email
      Target email address.
  .PARAMETER SkipH8Mail
      Skip h8mail (useful if Python deps not yet installed).
  .PARAMETER SkipHolehe
      Skip holehe (useful for quick triage).
  .EXAMPLE
      Invoke-RoninTriageEnrich -Email "attacker@protonmail.com"
  .EXAMPLE
      "evil@tempmail.com" | Invoke-RoninTriageEnrich
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Email,
    [Parameter()][switch]$SkipH8Mail,
    [Parameter()][switch]$SkipHolehe
  )
  process {
    Write-Host "  [*] Triage Enrichment: $Email" -ForegroundColor Cyan

    Write-Host "  [->] EmailRep.io..." -ForegroundColor DarkCyan
    $emailRep = Invoke-EmailRep -Email $Email -ErrorAction SilentlyContinue

    $h8mail = $null
    if (-not $SkipH8Mail) {
      Write-Host "  [->] h8mail breach hunt..." -ForegroundColor DarkCyan
      try { $h8mail = Invoke-H8Mail -Email $Email -ErrorAction Stop }
      catch { Write-Warning "h8mail skipped: $_" }
    }

    $holehe = $null
    if (-not $SkipHolehe) {
      Write-Host "  [->] holehe account pivot..." -ForegroundColor DarkCyan
      try { $holehe = Invoke-Holehe -Email $Email -OnlyRegistered -ErrorAction Stop }
      catch { Write-Warning "holehe skipped: $_" }
    }

    $totalScore = ($emailRep?.ScoreContribution ?? 0) + ($h8mail?.ScoreContribution ?? 0) + ($holehe?.ScoreContribution ?? 0)
    $allFlags   = [System.Collections.Generic.List[string]]::new()
    if ($emailRep?.Flags) { $allFlags.AddRange([string[]]$emailRep.Flags) }
    if ($h8mail?.BreachCount -gt 0) { $allFlags.Add("BREACH:$($h8mail.BreachCount)") }
    if ($holehe?.AccountsFound -gt 0) { $allFlags.Add("ACCOUNTS:$($holehe.AccountsFound)") }

    $riskLevel = switch ($totalScore) {
      { $_ -ge 75 } { 'CRITICAL' } { $_ -ge 50 } { 'HIGH' }
      { $_ -ge 25 } { 'MEDIUM'  } { $_ -ge 10 } { 'LOW'  } default { 'CLEAN' }
    }
    Write-Host "  [+] Score: $totalScore | Risk: $riskLevel | Flags: $($allFlags -join ', ')" -ForegroundColor $(
      switch ($riskLevel) { 'CRITICAL'{'Red'} 'HIGH'{'Yellow'} 'MEDIUM'{'Magenta'} default{'Green'} }
    )

    return [PSCustomObject]@{
      PSTypeName        = 'PhishRonin.TriageEnrichResult'
      Email             = $Email
      ThreatScore       = [Math]::Min($totalScore, 100)
      RiskLevel         = $riskLevel
      Flags             = $allFlags.ToArray()
      EmailRepResult    = $emailRep
      H8MailResult      = $h8mail
      HoleheResult      = $holehe
      BreachCount       = ($h8mail?.BreachCount ?? 0)
      AccountsFound     = ($holehe?.AccountsFound ?? 0)
      RegisteredSites   = ($holehe?.RegisteredSites ?? @())
      Reputation        = $emailRep?.Reputation
      Timestamp         = Get-Date -Format 'o'
    }
  }
}

Export-ModuleMember -Function Invoke-EmailRep, Invoke-H8Mail, Invoke-Holehe, Invoke-RoninTriageEnrich
