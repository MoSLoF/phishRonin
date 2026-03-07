Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Export-RoninIocs {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][string]$OutDir
  )
  if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

  $iocs = [PSCustomObject]@{
    ips     = ($Evidence.Iocs.Ips | Select-Object -Unique)
    urls    = ($Evidence.Iocs.Urls | Select-Object -Unique)
    domains = ($Evidence.Iocs.Domains | Select-Object -Unique)
    hashes  = ($Evidence.Iocs.Hashes | Select-Object -Unique)
  }

  $path = Join-Path $OutDir "ronin-iocs.json"
  $iocs | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
  return [PSCustomObject]@{ path=$path; iocs=$iocs }
}

function New-RoninHuntQueries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$IocBundle,
    [Parameter(Mandatory=$true)][ValidateSet('MDE','Defender','Sentinel','Splunk','Generic')][string]$Provider
  )

  $i = $IocBundle.iocs
  $queries = [ordered]@{ Provider=$Provider; Notes=@() }

  switch ($Provider) {
    'MDE' {
      $queries.Email = @"
// Microsoft Defender XDR / Advanced Hunting (example)
EmailEvents
| where SenderFromAddress has_any (${(Format-RoninKqlList $i.domains)})
   or RecipientEmailAddress has_any (${(Format-RoninKqlList $i.domains)})
   or Subject has_any (${(Format-RoninKqlList @('layoff','termination','hr'))})
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject
"@
      $queries.Url = @"
// URL clicks / URL artifacts
UrlClickEvents
| where Url has_any (${(Format-RoninKqlList $i.urls)})
"@
      $queries.File = @"
// File hashes
DeviceFileEvents
| where SHA256 in (${(Format-RoninKqlList $i.hashes)})
"@
    }
    'Sentinel' {
      $queries.Kql = @"
// Azure Sentinel / Log Analytics (example)
SecurityAlert
| where Entities has_any (${(Format-RoninKqlList $i.domains)})
"@
    }
    'Splunk' {
      $queries.Spl = "index=* ( " + (Format-RoninSplunkOr $i.domains "domain") + " )"
    }
    default {
      $queries.Generic = [PSCustomObject]@{
        Domains = $i.domains
        Urls    = $i.urls
        Hashes  = $i.hashes
        Ips     = $i.ips
      }
      $queries.Notes += "Use these IOCs in your preferred SIEM/EDR."
    }
  }

  return [PSCustomObject]$queries
}

function Format-RoninKqlList {
  param([object[]]$Items)
  $safe = @()
  foreach ($x in $Items) {
    if (-not $x) { continue }
    $safe += "'" + ($x.ToString().Replace("'","''")) + "'"
  }
  return ($safe -join ", ")
}

function Format-RoninSplunkOr {
  param([object[]]$Items, [string]$Field)
  $parts = @()
  foreach ($x in $Items) {
    if (-not $x) { continue }
    $parts += "$Field=`"$x`""
  }
  return ($parts -join " OR ")
}

# ═══════════════════════════════════════════════════════════════════════════════
# THINKPOL EXPANSION — Phase 2: Threat Intel Enrichment
# Added: IntelOwl, AlienVault OTX, IBM X-Force, LeaksAPI, Hudson Rock
# Author: HoneyBadger (HoneyBadger Vanguard, LLC) | Version: 2.0.0
# Attribution: IntelOwl (github.com/intelowlproject/IntelOwl),
#              AlienVault OTX (otx.alienvault.com),
#              IBM X-Force (exchange.xforce.ibmcloud.com),
#              LeaksAPI (leaks-api.io), Hudson Rock (hudsonrock.com)
# ═══════════════════════════════════════════════════════════════════════════════

$script:HuntConfig = @{
  IntelOwl = @{
    BaseUrl    = $env:INTELOWL_URL ?? 'http://ihbv-ai:4443'
    ApiKey     = $env:INTELOWL_API_KEY
    TimeoutSec = 120
    Analyzers  = @(
      'EmailRep_Get','HaveIBeenPwned_Get','Hunter_Get','MXToolbox_Get',
      'Emailformat_Get','VirusTotal_v3_Get','Shodan_Search',
      'AlienVault_OTX_Get','ThreatMiner_Domain','URLhaus_Query',
      'URLScan_Search','Phishtank_CheckURL','GoogleSafebrowsing'
    )
  }
  OTX = @{
    BaseUrl    = 'https://otx.alienvault.com/api/v1'
    ApiKey     = $env:OTX_API_KEY
    TimeoutSec = 30
  }
  XForce = @{
    BaseUrl    = 'https://api.xforce.ibmcloud.com'
    ApiKey     = $env:XFORCE_API_KEY
    ApiPass    = $env:XFORCE_API_PASS
    TimeoutSec = 30
  }
  LeaksAPI = @{
    BaseUrl    = 'https://leaks-api.io/api'
    ApiKey     = $env:LEAKSAPI_KEY
    TimeoutSec = 30
  }
  HudsonRock = @{
    BaseUrl    = 'https://cavalier.hudsonrock.com/api/json/v2'
    ApiKey     = $env:HUDSONROCK_API_KEY
    TimeoutSec = 30
  }
  Scoring = @{
    MaliciousIOC     = 35
    SuspiciousIOC    = 20
    BreachCorrelated = 30
    InfostealerHit   = 40
    PhishingURL      = 25
    KnownBadDomain   = 30
  }
}

function Invoke-IntelOwl {
  <#
  .SYNOPSIS
      Submit observable to self-hosted IntelOwl for multi-analyzer enrichment.
  .DESCRIPTION
      Submits an email, domain, IP, URL, or hash to IntelOwl on iHBV-AI.
      Polls for completion and returns aggregated analyzer results.
  .PARAMETER Observable
      Value to analyze (email, domain, IP, URL, file hash).
  .PARAMETER ObservableType
      Type: email, domain, ip, url, hash, generic (auto-detected if omitted).
  .PARAMETER WaitSeconds
      Max seconds to poll for completion (default 120).
  .EXAMPLE
      Invoke-IntelOwl -Observable "attacker@evil.com" -ObservableType email
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline)][string]$Observable,
    [Parameter()][ValidateSet('email','domain','ip','url','hash','generic')][string]$ObservableType = 'generic',
    [Parameter()][string[]]$Analyzers = $script:HuntConfig.IntelOwl.Analyzers,
    [Parameter()][int]$WaitSeconds = $script:HuntConfig.IntelOwl.TimeoutSec
  )
  process {
    if (-not $script:HuntConfig.IntelOwl.ApiKey) {
      throw "INTELOWL_API_KEY not set. Run: `$env:INTELOWL_API_KEY = 'your-key'"
    }
    if ($ObservableType -eq 'generic') {
      $ObservableType = switch -Regex ($Observable) {
        '^[^@]+@[^@]+\.[^@]+$'    { 'email'  }
        '^\d{1,3}(\.\d{1,3}){3}$' { 'ip'     }
        '^https?://'               { 'url'    }
        '^[a-f0-9]{32,64}$'        { 'hash'   }
        default                    { 'domain' }
      }
    }
    $headers = @{
      'Authorization' = "Token $($script:HuntConfig.IntelOwl.ApiKey)"
      'Content-Type'  = 'application/json'
    }
    $body = @{
      observable_name           = $Observable
      observable_classification = $ObservableType
      analyzers_requested       = $Analyzers
      tlp                       = 'WHITE'
    } | ConvertTo-Json
    try {
      $submit = Invoke-RestMethod -Uri "$($script:HuntConfig.IntelOwl.BaseUrl)/api/analyze_observable" `
                  -Method POST -Headers $headers -Body $body -TimeoutSec 30
      $jobId   = $submit.job_id
      $elapsed = 0; $interval = 5; $job = $null
      while ($elapsed -lt $WaitSeconds) {
        Start-Sleep -Seconds $interval; $elapsed += $interval
        $job = Invoke-RestMethod -Uri "$($script:HuntConfig.IntelOwl.BaseUrl)/api/jobs/$jobId" `
                 -Headers $headers -Method GET
        if ($job.status -in @('reported_without_fails','reported_with_fails','failed')) { break }
      }
      if (-not $job) { throw "IntelOwl job timeout after ${WaitSeconds}s" }
      $malicious = 0; $suspicious = 0; $scoreAdd = 0
      $flags = [System.Collections.Generic.List[string]]::new()
      $analyzerOut = [System.Collections.Generic.List[PSCustomObject]]::new()
      foreach ($a in $job.analyzer_reports) {
        $verdict = $a.report?.verdict ?? $a.report?.data?.verdict ?? 'unknown'
        switch -Wildcard ($verdict.ToString().ToLower()) {
          '*malicious*'  { $malicious++;  $flags.Add("MALICIOUS:$($a.name)")  }
          '*suspicious*' { $suspicious++; $flags.Add("SUSPICIOUS:$($a.name)") }
        }
        $analyzerOut.Add([PSCustomObject]@{ Analyzer=$a.name; Status=$a.status; Verdict=$verdict; Report=$a.report })
      }
      if ($malicious  -gt 0) { $scoreAdd += $script:HuntConfig.Scoring.MaliciousIOC  }
      if ($suspicious -gt 0) { $scoreAdd += $script:HuntConfig.Scoring.SuspiciousIOC }
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.IntelOwlResult'
        Observable        = $Observable
        ObservableType    = $ObservableType
        JobId             = $jobId
        JobStatus         = $job.status
        MaliciousCount    = $malicious
        SuspiciousCount   = $suspicious
        Flags             = $flags.ToArray()
        AnalyzerResults   = $analyzerOut.ToArray()
        ScoreContribution = $scoreAdd
        Source            = 'IntelOwl'
        Timestamp         = Get-Date -Format 'o'
      }
    }
    catch {
      Write-Warning "IntelOwl error for $Observable : $_"
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.IntelOwlResult'
        Observable        = $Observable
        Error             = $_.Exception.Message
        ScoreContribution = 0
        Source            = 'IntelOwl'
        Timestamp         = Get-Date -Format 'o'
      }
    }
  }
}

function Invoke-OTXLookup {
  <#
  .SYNOPSIS
      Query AlienVault OTX for threat intelligence on an IOC.
  .PARAMETER Observable
      IP, domain, URL, or hash.
  .PARAMETER Type
      IOC type: IPv4, domain, url, FileHash-MD5, FileHash-SHA1, FileHash-SHA256
  .EXAMPLE
      Invoke-OTXLookup -Observable "evil.ru" -Type domain
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline)][string]$Observable,
    [Parameter()][ValidateSet('IPv4','domain','url','FileHash-MD5','FileHash-SHA1','FileHash-SHA256')][string]$Type = 'domain'
  )
  process {
    $headers = @{ 'X-OTX-API-KEY' = ($script:HuntConfig.OTX.ApiKey ?? ''); 'Accept' = 'application/json' }
    $endpoint = switch ($Type) {
      'IPv4'   { "indicators/IPv4/$Observable/general"   }
      'domain' { "indicators/domain/$Observable/general" }
      'url'    { "indicators/url/$([Uri]::EscapeDataString($Observable))/general" }
      default  { "indicators/domain/$Observable/general" }
    }
    try {
      $result     = Invoke-RestMethod -Uri "$($script:HuntConfig.OTX.BaseUrl)/$endpoint" `
                      -Headers $headers -TimeoutSec $script:HuntConfig.OTX.TimeoutSec
      $pulseCount = $result.pulse_info?.count ?? 0
      $scoreAdd   = if ($pulseCount -gt 0) { $script:HuntConfig.Scoring.MaliciousIOC } else { 0 }
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.OTXResult'
        Observable        = $Observable
        Type              = $Type
        PulseCount        = $pulseCount
        Pulses            = $result.pulse_info?.pulses ?? @()
        Reputation        = $result.reputation ?? 0
        Country           = $result.country_name
        ASN               = $result.asn
        Malware           = $result.malware?.count ?? 0
        ScoreContribution = $scoreAdd
        Source            = 'AlienVault OTX'
        Timestamp         = Get-Date -Format 'o'
      }
    }
    catch {
      Write-Warning "OTX lookup failed for $Observable : $_"
      return [PSCustomObject]@{
        PSTypeName = 'PhishRonin.OTXResult'; Observable = $Observable
        Error = $_.Exception.Message; ScoreContribution = 0; Source = 'AlienVault OTX'
      }
    }
  }
}

function Invoke-XForceLookup {
  <#
  .SYNOPSIS
      Query IBM X-Force Exchange for threat intelligence.
  .PARAMETER Observable
      Domain, IP, or URL.
  .EXAMPLE
      Invoke-XForceLookup -Observable "phishing-domain.com"
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param([Parameter(Mandatory, ValueFromPipeline)][string]$Observable)
  process {
    $cred = [Convert]::ToBase64String(
      [Text.Encoding]::ASCII.GetBytes("$($script:HuntConfig.XForce.ApiKey):$($script:HuntConfig.XForce.ApiPass)")
    )
    $headers  = @{ 'Authorization' = "Basic $cred"; 'Accept' = 'application/json' }
    $endpoint = if ($Observable -match '^\d{1,3}(\.\d{1,3}){3}$') {
      "ipr/$Observable"
    } else { "url/$([Uri]::EscapeDataString($Observable))" }
    try {
      $result   = Invoke-RestMethod -Uri "$($script:HuntConfig.XForce.BaseUrl)/$endpoint" `
                    -Headers $headers -TimeoutSec $script:HuntConfig.XForce.TimeoutSec
      $score    = $result.result?.score ?? $result.score ?? 0
      $scoreAdd = if ($score -ge 7) { $script:HuntConfig.Scoring.MaliciousIOC } `
                  elseif ($score -ge 4) { $script:HuntConfig.Scoring.SuspiciousIOC } else { 0 }
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.XForceResult'
        Observable        = $Observable
        RiskScore         = $score
        Categories        = $result.result?.cats ?? $result.cats ?? @{}
        Country           = $result.geo?.country
        Malware           = $result.malware?.count ?? 0
        ScoreContribution = $scoreAdd
        Source            = 'IBM X-Force'
        Timestamp         = Get-Date -Format 'o'
      }
    }
    catch {
      Write-Warning "X-Force lookup failed for $Observable : $_"
      return [PSCustomObject]@{
        PSTypeName = 'PhishRonin.XForceResult'; Observable = $Observable
        Error = $_.Exception.Message; ScoreContribution = 0; Source = 'IBM X-Force'
      }
    }
  }
}

function Invoke-BreachCorrelate {
  <#
  .SYNOPSIS
      Check email/domain against LeaksAPI and Hudson Rock infostealer databases.
  .DESCRIPTION
      Queries LeaksAPI (1300+ leaked databases) and Hudson Rock (Raccoon/Redline/Vidar
      infostealer logs) for credential exposure and infostealer hits.
  .PARAMETER Email
      Email address to check.
  .PARAMETER Domain
      Domain to check for organizational exposure.
  .EXAMPLE
      Invoke-BreachCorrelate -Email "victim@company.com"
  #>
  [CmdletBinding()]
  param(
    [Parameter(ParameterSetName='Email', Mandatory)][string]$Email,
    [Parameter(ParameterSetName='Domain', Mandatory)][string]$Domain
  )
  $scoreAdd = 0
  $flags    = [System.Collections.Generic.List[string]]::new()
  $leaksResult = $null; $hrResult = $null

  # LeaksAPI
  if ($script:HuntConfig.LeaksAPI.ApiKey) {
    try {
      $query    = if ($Email) { $Email } else { $Domain }
      $leaksUri = "$($script:HuntConfig.LeaksAPI.BaseUrl)/search?query=$([Uri]::EscapeDataString($query))&type=email"
      $leaksResult = Invoke-RestMethod -Uri $leaksUri `
                       -Headers @{ 'X-API-Key' = $script:HuntConfig.LeaksAPI.ApiKey } `
                       -TimeoutSec $script:HuntConfig.LeaksAPI.TimeoutSec
      if ($leaksResult.total -gt 0) {
        $scoreAdd += $script:HuntConfig.Scoring.BreachCorrelated
        $flags.Add("LEAKSAPI:$($leaksResult.total)_records")
      }
    } catch { Write-Verbose "LeaksAPI error: $_" }
  }

  # Hudson Rock (free tier available)
  try {
    $hrQuery = if ($Email) {
      "$($script:HuntConfig.HudsonRock.BaseUrl)/osint-tools?email=$([Uri]::EscapeDataString($Email))"
    } else {
      "$($script:HuntConfig.HudsonRock.BaseUrl)/osint-tools?domain=$([Uri]::EscapeDataString($Domain))"
    }
    $hrHeaders = @{ 'Accept' = 'application/json' }
    if ($script:HuntConfig.HudsonRock.ApiKey) {
      $hrHeaders['Authorization'] = "Bearer $($script:HuntConfig.HudsonRock.ApiKey)"
    }
    $hrResult     = Invoke-RestMethod -Uri $hrQuery -Headers $hrHeaders `
                      -TimeoutSec $script:HuntConfig.HudsonRock.TimeoutSec
    $stealerCount = ($hrResult.stealers ?? @()).Count
    if ($stealerCount -gt 0) {
      $scoreAdd += $script:HuntConfig.Scoring.InfostealerHit
      $flags.Add("INFOSTEALER:$stealerCount hits")
    }
  } catch { Write-Verbose "Hudson Rock error: $_" }

  return [PSCustomObject]@{
    PSTypeName          = 'PhishRonin.BreachCorrelateResult'
    Query               = $Email ?? $Domain
    QueryType           = if ($Email) { 'email' } else { 'domain' }
    LeaksAPITotal       = $leaksResult?.total ?? 0
    LeaksAPIRecords     = $leaksResult?.data ?? @()
    InfostealerHits     = ($hrResult?.stealers ?? @()).Count
    StealerFamilies     = ($hrResult?.stealers | Select-Object -ExpandProperty malware_family -ErrorAction SilentlyContinue) ?? @()
    HudsonRockData      = $hrResult
    Flags               = $flags.ToArray()
    ScoreContribution   = $scoreAdd
    Source              = 'LeaksAPI + HudsonRock'
    Timestamp           = Get-Date -Format 'o'
  }
}

function Invoke-RoninHuntEnrich {
  <#
  .SYNOPSIS
      Run Phase 2 threat intel enrichment against an email/domain.
  .DESCRIPTION
      Orchestrates IntelOwl + OTX + X-Force + BreachCorrelate and returns
      a unified result compatible with the PhishRonin Evidence pipeline.
      Feeds score contribution back into RoninTriage scoring.
  .PARAMETER Email
      Sender email address from phishing investigation.
  .PARAMETER Domain
      Override sending domain (extracted from email if omitted).
  .PARAMETER SkipIntelOwl
      Skip IntelOwl (if not yet deployed on iHBV-AI).
  .EXAMPLE
      Invoke-RoninHuntEnrich -Email "phisher@evil-domain.ru"
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory, ValueFromPipeline)][string]$Email,
    [Parameter()][string]$Domain,
    [Parameter()][switch]$SkipIntelOwl
  )
  process {
    $domain = $Domain ?? ($Email -split '@')[1]
    Write-Host "  [*] RoninHunt Enrichment: $Email (domain: $domain)" -ForegroundColor Yellow

    $results = @{}

    if (-not $SkipIntelOwl -and $script:HuntConfig.IntelOwl.ApiKey) {
      Write-Host "  [->] IntelOwl multi-analyzer..." -ForegroundColor DarkYellow
      $results.IntelOwl       = Invoke-IntelOwl -Observable $Email   -ObservableType email  -ErrorAction SilentlyContinue
      $results.IntelOwlDomain = Invoke-IntelOwl -Observable $domain  -ObservableType domain -ErrorAction SilentlyContinue
    }

    Write-Host "  [->] AlienVault OTX..." -ForegroundColor DarkYellow
    $results.OTX = Invoke-OTXLookup -Observable $domain -Type domain -ErrorAction SilentlyContinue

    Write-Host "  [->] IBM X-Force..." -ForegroundColor DarkYellow
    $results.XForce = Invoke-XForceLookup -Observable $domain -ErrorAction SilentlyContinue

    Write-Host "  [->] Breach correlation (LeaksAPI + Hudson Rock)..." -ForegroundColor DarkYellow
    $results.Breach = Invoke-BreachCorrelate -Email $Email -ErrorAction SilentlyContinue

    $totalScore = ($results.Values | ForEach-Object { $_.ScoreContribution ?? 0 } | Measure-Object -Sum).Sum
    $allFlags   = $results.Values | ForEach-Object { $_.Flags ?? @() } | Select-Object -Unique
    $riskLevel  = switch ($totalScore) {
      { $_ -ge 75 } { 'CRITICAL' } { $_ -ge 50 } { 'HIGH' }
      { $_ -ge 25 } { 'MEDIUM'  } default { 'LOW' }
    }

    Write-Host "  [+] HuntEnrich Score: +$totalScore | Risk: $riskLevel" -ForegroundColor $(
      switch ($riskLevel) { 'CRITICAL'{'Red'} 'HIGH'{'Yellow'} 'MEDIUM'{'Magenta'} default{'Green'} }
    )

    return [PSCustomObject]@{
      PSTypeName        = 'PhishRonin.HuntEnrichResult'
      Email             = $Email
      Domain            = $domain
      ThreatScore       = [Math]::Min($totalScore, 100)
      RiskLevel         = $riskLevel
      Flags             = @($allFlags)
      IntelOwlResult    = $results.IntelOwl
      OTXResult         = $results.OTX
      XForceResult      = $results.XForce
      BreachResult      = $results.Breach
      Timestamp         = Get-Date -Format 'o'
    }
  }
}

Export-ModuleMember -Function `
  Export-RoninIocs, New-RoninHuntQueries, `
  Invoke-IntelOwl, Invoke-OTXLookup, Invoke-XForceLookup, `
  Invoke-BreachCorrelate, Invoke-RoninHuntEnrich
