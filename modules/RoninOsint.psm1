Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Force TLS 1.2 for PS 5.1 compatibility
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Private HTTP wrapper ─────────────────────────────────────────────────────

function Invoke-RoninSafeRest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Uri,
    [hashtable]$Headers = @{},
    [string]$Method = 'GET',
    [int]$TimeoutSec = 10,
    [object]$Evidence
  )
  try {
    $params = @{
      Uri             = $Uri
      Method          = $Method
      Headers         = $Headers
      TimeoutSec      = $TimeoutSec
      UseBasicParsing = $true
      ErrorAction     = 'Stop'
    }
    $resp = Invoke-RestMethod @params
    return $resp
  }
  catch {
    $msg = $_.Exception.Message
    if ($msg -match '429') {
      if ($Evidence) { $Evidence.Osint.Notes += "Rate limited: $Uri" }
    } elseif ($msg -match '401|403') {
      if ($Evidence) { $Evidence.Osint.Notes += "Auth failed: $Uri - check API key" }
    } elseif ($msg -match '404') {
      # Expected for Shodan/VT when IOC not indexed - silent
    } else {
      if ($Evidence) { $Evidence.Osint.Notes += "API error for ${Uri}: $msg" }
    }
    return $null
  }
}

# ── IP Profiling ─────────────────────────────────────────────────────────────

function Get-RoninIpProfile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Ip,
    [Parameter(Mandatory)][object]$Evidence,
    [switch]$Offline
  )

  $config = $Evidence.Config
  $osintCfg = $config.osint

  $profile = [PSCustomObject]@{
    Ip             = $Ip
    Geolocation    = @{ Country=""; CountryCode=""; Region=""; City=""; Lat=0; Lon=0; Timezone="" }
    Network        = @{ Isp=""; Org=""; Asn=""; AsName="" }
    Classification = @{ IsHosting=$false; IsProxy=$false; IsMobile=$false; InfraType="unknown" }
    ReverseDns     = ""
    AbuseIpDb      = @{ Score=0; Reports=0; LastReported="" }
    Shodan         = @{ Ports=@(); Vulns=@(); Os="" }
    Censys         = @{ Services=@(); TotalServices=0; LastUpdated="" }
    VirusTotal     = @{ Malicious=0; Suspicious=0; Harmless=0 }
  }

  # Skip private/loopback IPs
  if ($osintCfg.skipPrivateIps -and ($Ip -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|::1|fe80)')) {
    $profile.Classification.InfraType = "private"
    return $profile
  }

  if ($Offline) { return $profile }

  # ── ip-api.com (no key, free tier) ──
  $fields = "status,message,country,countryCode,region,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
  $geo = Invoke-RoninSafeRest -Uri "http://ip-api.com/json/${Ip}?fields=${fields}" -Evidence $Evidence
  if ($geo -and $geo.status -eq 'success') {
    $profile.Geolocation.Country     = $geo.country
    $profile.Geolocation.CountryCode = $geo.countryCode
    $profile.Geolocation.Region      = $geo.region
    $profile.Geolocation.City        = $geo.city
    $profile.Geolocation.Lat         = $geo.lat
    $profile.Geolocation.Lon         = $geo.lon
    $profile.Geolocation.Timezone    = $geo.timezone
    $profile.Network.Isp             = $geo.isp
    $profile.Network.Org             = $geo.org
    $profile.Network.AsName          = $geo.asname
    # Extract AS number from "AS12345 OrgName" format
    $geoAs = if ($geo.as) { $geo.as } else { "" }
    $asMatch = [regex]::Match($geoAs, '^(AS\d+)')
    if ($asMatch.Success) { $profile.Network.Asn = $asMatch.Groups[1].Value }
    $profile.Classification.IsHosting = [bool]$geo.hosting
    $profile.Classification.IsProxy   = [bool]$geo.proxy
    $profile.Classification.IsMobile  = [bool]$geo.mobile
  }

  $delayMs = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
  Start-Sleep -Milliseconds $delayMs

  # ── Reverse DNS ──
  try {
    $dns = Resolve-DnsName -Name $Ip -Type PTR -ErrorAction SilentlyContinue
    if ($dns -and $dns.NameHost) { $profile.ReverseDns = $dns.NameHost }
  } catch {
    try {
      $entry = [System.Net.Dns]::GetHostEntry($Ip)
      if ($entry.HostName) { $profile.ReverseDns = $entry.HostName }
    } catch {}
  }

  # ── AbuseIPDB (optional, needs key) ──
  if ($osintCfg.abuseIpDbKey) {
    $abuseResp = Invoke-RoninSafeRest -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=${Ip}&maxAgeInDays=90" `
      -Headers @{ "Key" = $osintCfg.abuseIpDbKey; "Accept" = "application/json" } `
      -Evidence $Evidence
    if ($abuseResp -and $abuseResp.data) {
      $profile.AbuseIpDb.Score        = [int]$(if ($null -ne $abuseResp.data.abuseConfidenceScore) { $abuseResp.data.abuseConfidenceScore } else { 0 })
      $profile.AbuseIpDb.Reports      = [int]$(if ($null -ne $abuseResp.data.totalReports) { $abuseResp.data.totalReports } else { 0 })
      $profile.AbuseIpDb.LastReported  = $(if ($abuseResp.data.lastReportedAt) { $abuseResp.data.lastReportedAt } else { "" })
    }
    $delayMs2 = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
    Start-Sleep -Milliseconds $delayMs2
  }

  # ── Shodan (optional, needs key) ──
  if ($osintCfg.shodanKey) {
    $shodanResp = Invoke-RoninSafeRest -Uri "https://api.shodan.io/shodan/host/${Ip}?key=$($osintCfg.shodanKey)" `
      -Evidence $Evidence
    if ($shodanResp) {
      $profile.Shodan.Ports = @($(if ($shodanResp.ports) { $shodanResp.ports } else { @() }))
      $profile.Shodan.Vulns = @($(if ($shodanResp.vulns) { $shodanResp.vulns } else { @() }))
      $profile.Shodan.Os    = $(if ($shodanResp.os) { $shodanResp.os } else { "" })
    }
    $delayMs3 = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
    Start-Sleep -Milliseconds $delayMs3
  }

  # ── VirusTotal IP (optional, needs key) ──
  if ($osintCfg.virusTotalKey) {
    $vtResp = Invoke-RoninSafeRest -Uri "https://www.virustotal.com/api/v3/ip_addresses/${Ip}" `
      -Headers @{ "x-apikey" = $osintCfg.virusTotalKey } `
      -Evidence $Evidence
    if ($vtResp -and $vtResp.data -and $vtResp.data.attributes.last_analysis_stats) {
      $stats = $vtResp.data.attributes.last_analysis_stats
      $profile.VirusTotal.Malicious  = [int]$(if ($null -ne $stats.malicious) { $stats.malicious } else { 0 })
      $profile.VirusTotal.Suspicious = [int]$(if ($null -ne $stats.suspicious) { $stats.suspicious } else { 0 })
      $profile.VirusTotal.Harmless   = [int]$(if ($null -ne $stats.harmless) { $stats.harmless } else { 0 })
    }
    $delayMs4 = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
    Start-Sleep -Milliseconds $delayMs4
  }

  # ── Censys Platform API v3 (Bearer PAT auth) ──
  if ($osintCfg.censysSecret) {
    $censysResp = Invoke-RoninSafeRest -Uri "https://api.platform.censys.io/v3/global/asset/host/${Ip}" `
      -Headers @{ "Authorization" = "Bearer $($osintCfg.censysSecret)"; "Accept" = "application/json" } `
      -Evidence $Evidence
    # v3 schema: result.resource.services[] with port, protocol, transport_protocol
    $censysResult = $null
    if ($censysResp -and $censysResp.PSObject.Properties['result']) {
      $r = $censysResp.result
      if ($r.PSObject.Properties['resource']) { $censysResult = $r.resource } else { $censysResult = $r }
    }
    if ($censysResult) {
      $svcList = @()
      $hasSvcs = $censysResult.PSObject.Properties['services'] -and $null -ne $censysResult.services
      if ($hasSvcs) {
        foreach ($svc in $censysResult.services) {
          $svcPort = if ($svc.PSObject.Properties['port']) { [int]$svc.port } else { 0 }
          $svcName = if ($svc.PSObject.Properties['protocol'] -and $svc.protocol) { $svc.protocol } `
                     elseif ($svc.PSObject.Properties['service_name'] -and $svc.service_name) { $svc.service_name } `
                     else { "UNKNOWN" }
          $svcTrans = if ($svc.PSObject.Properties['transport_protocol'] -and $svc.transport_protocol) { $svc.transport_protocol } else { "TCP" }
          $svcList += [PSCustomObject]@{ Port = $svcPort; ServiceName = $svcName; Transport = $svcTrans }
        }
      }
      $profile.Censys.Services      = @($svcList)
      $profile.Censys.TotalServices = @($svcList).Count
      # v3 has per-service scan_time; use the most recent one
      $latestScan = ""
      if ($hasSvcs) {
        $scanTimes = @($censysResult.services | Where-Object { $_.PSObject.Properties['scan_time'] -and $_.scan_time } | ForEach-Object { $_.scan_time }) | Sort-Object -Descending
        if (@($scanTimes).Count -gt 0) { $latestScan = $scanTimes[0] }
      }
      $profile.Censys.LastUpdated = $latestScan
    }
    # Censys free tier: 1 concurrent action — use longer delay
    $delayMs5 = [math]::Max(2500, $(if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }))
    Start-Sleep -Milliseconds $delayMs5
  }

  return $profile
}

# ── Domain Profiling ─────────────────────────────────────────────────────────

function Get-RoninDomainProfile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][object]$Evidence,
    [switch]$Offline
  )

  $config = $Evidence.Config
  $osintCfg = $config.osint

  $profile = [PSCustomObject]@{
    Domain     = $Domain
    Whois      = @{ Registrar=""; CreatedDate=""; UpdatedDate=""; ExpiresDate=""; AgeInDays=-1 }
    VirusTotal = @{ Malicious=0; Suspicious=0; Harmless=0 }
    Notes      = @()
  }

  if ($Offline) { return $profile }

  # ── RDAP lookup (structured JSON WHOIS, no key needed) ──
  $rdap = Invoke-RoninSafeRest -Uri "https://rdap.org/domain/${Domain}" -Evidence $Evidence
  if ($rdap) {
    # Registrar from entities
    if ($rdap.entities) {
      foreach ($ent in $rdap.entities) {
        if ($ent.roles -contains 'registrar') {
          $profile.Whois.Registrar = ($ent.vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] }) -join ''
          if (-not $profile.Whois.Registrar -and $ent.handle) { $profile.Whois.Registrar = $ent.handle }
        }
      }
    }
    # Dates from events
    if ($rdap.events) {
      foreach ($evt in $rdap.events) {
        switch ($evt.eventAction) {
          'registration'   { $profile.Whois.CreatedDate = $evt.eventDate }
          'last changed'   { $profile.Whois.UpdatedDate = $evt.eventDate }
          'expiration'     { $profile.Whois.ExpiresDate = $evt.eventDate }
        }
      }
    }
    # Calculate age
    if ($profile.Whois.CreatedDate) {
      try {
        $created = [datetime]::Parse($profile.Whois.CreatedDate)
        $profile.Whois.AgeInDays = [int]((Get-Date) - $created).TotalDays
      } catch {
        $profile.Notes += "Could not parse creation date for $Domain"
      }
    }
  }

  $delayMs5 = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
  Start-Sleep -Milliseconds $delayMs5

  # ── VirusTotal domain (optional, needs key) ──
  if ($osintCfg.virusTotalKey) {
    $vtResp = Invoke-RoninSafeRest -Uri "https://www.virustotal.com/api/v3/domains/${Domain}" `
      -Headers @{ "x-apikey" = $osintCfg.virusTotalKey } `
      -Evidence $Evidence
    if ($vtResp -and $vtResp.data -and $vtResp.data.attributes.last_analysis_stats) {
      $stats = $vtResp.data.attributes.last_analysis_stats
      $profile.VirusTotal.Malicious  = [int]$(if ($null -ne $stats.malicious) { $stats.malicious } else { 0 })
      $profile.VirusTotal.Suspicious = [int]$(if ($null -ne $stats.suspicious) { $stats.suspicious } else { 0 })
      $profile.VirusTotal.Harmless   = [int]$(if ($null -ne $stats.harmless) { $stats.harmless } else { 0 })
    }
    $delayMs6 = if ($osintCfg.rateLimitDelayMs) { $osintCfg.rateLimitDelayMs } else { 1500 }
    Start-Sleep -Milliseconds $delayMs6
  }

  return $profile
}

# ── Threat Infrastructure Classification ─────────────────────────────────────

function Get-RoninThreatClassification {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$IpProfiles,
    [Parameter(Mandatory)][object]$Config
  )

  $osintCfg = $Config.osint
  $result = [PSCustomObject]@{
    OverallType = "unknown"
    Confidence  = "low"
    Indicators  = @()
  }

  $indicators = New-Object System.Collections.Generic.List[string]
  $types = @()

  foreach ($ip in $IpProfiles) {
    if ($ip.Classification.InfraType -eq 'private') { continue }
    $asn = $ip.Network.Asn
    $org = $ip.Network.Org
    $isp = $ip.Network.Isp

    # Bulletproof hosting (highest priority)
    if ($asn -and $osintCfg.knownBulletproofAsns -contains $asn) {
      $types += "bulletproof"
      $indicators.Add("$($ip.Ip) ASN $asn matches known bulletproof hosting")
    }
    # Tor exit
    elseif ($ip.ReverseDns -match '(?i)tor|exit|relay' -or $org -match '(?i)tor\s*project|tor\s*exit') {
      $types += "tor"
      $indicators.Add("$($ip.Ip) reverse DNS or org indicates Tor infrastructure")
    }
    # Known VPS/Cloud
    elseif ($asn -and $osintCfg.knownVpsAsns -contains $asn) {
      $types += "vps"
      $indicators.Add("$($ip.Ip) ASN $asn matches known VPS/cloud provider")
    }
    elseif ($org -match '(?i)amazon|aws|google\s*cloud|microsoft|azure|digitalocean|linode|vultr|ovh|hetzner|choopa|contabo') {
      $types += "vps"
      $indicators.Add("$($ip.Ip) org '$org' matches known cloud provider")
    }
    # CDN
    elseif ($org -match '(?i)cloudflare|akamai|fastly|incapsula|sucuri') {
      $types += "cdn"
      $indicators.Add("$($ip.Ip) org '$org' is a CDN provider")
    }
    # ip-api hosting flag
    elseif ($ip.Classification.IsHosting) {
      $types += "vps"
      $indicators.Add("$($ip.Ip) flagged as hosting infrastructure by ip-api.com")
    }
    # Mobile
    elseif ($ip.Classification.IsMobile) {
      $types += "mobile"
      $indicators.Add("$($ip.Ip) flagged as mobile network")
    }
    # Residential
    else {
      $types += "residential"
      $indicators.Add("$($ip.Ip) appears to be residential infrastructure")
    }

    # Proxy flag (additive, regardless of other classification)
    if ($ip.Classification.IsProxy) {
      $indicators.Add("$($ip.Ip) flagged as proxy/VPN by ip-api.com")
    }

    # AbuseIPDB high score
    if ($ip.AbuseIpDb.Score -gt 50) {
      $indicators.Add("$($ip.Ip) AbuseIPDB confidence: $($ip.AbuseIpDb.Score)% ($($ip.AbuseIpDb.Reports) reports)")
    }
  }

  # Determine overall type
  $uniqueTypes = @($types | Select-Object -Unique)
  if ($uniqueTypes.Count -eq 0) {
    $result.OverallType = "unknown"
    $result.Confidence = "low"
  } elseif ($uniqueTypes.Count -eq 1) {
    $result.OverallType = $uniqueTypes[0]
    $result.Confidence = "high"
  } else {
    # Priority: bulletproof > tor > vps > cdn > mobile > residential
    $priority = @('bulletproof','tor','vps','cdn','mobile','residential')
    foreach ($p in $priority) {
      if ($uniqueTypes -contains $p) { $result.OverallType = $p; break }
    }
    $result.Confidence = "medium"
  }

  $result.Indicators = $indicators.ToArray()
  return $result
}

# ── Pivot Link Generation (works offline) ────────────────────────────────────

function New-RoninOsintLinks {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$Evidence)

  $links = @()

  # IP pivot links
  $ips = @($Evidence.Iocs.Ips | Select-Object -Unique)
  if ($Evidence.Received.OriginIp -and $ips -notcontains $Evidence.Received.OriginIp) {
    $ips = @($Evidence.Received.OriginIp) + $ips
  }
  foreach ($ip in $ips) {
    if (-not $ip -or $ip -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)') { continue }
    $links += [PSCustomObject]@{
      Ioc  = $ip
      Type = "ip"
      Links = [ordered]@{
        VirusTotal = "https://www.virustotal.com/gui/ip-address/$ip"
        AbuseIPDB  = "https://www.abuseipdb.com/check/$ip"
        Shodan     = "https://www.shodan.io/host/$ip"
        Censys     = "https://search.censys.io/hosts/$ip"
        UrlScan    = "https://urlscan.io/search/#ip:$ip"
        ThreatBook = "https://threatbook.io/ip/$ip"
      }
    }
  }

  # Domain pivot links
  $domains = @($Evidence.Iocs.Domains | Select-Object -Unique)
  $filter = @($(if ($Evidence.Config.osint.infrastructureDomainFilter) { $Evidence.Config.osint.infrastructureDomainFilter } else { @() }))
  foreach ($domain in $domains) {
    if (-not $domain) { continue }
    $skip = $false
    foreach ($f in $filter) { if ($domain -match [regex]::Escape($f)) { $skip = $true; break } }
    if ($skip) { continue }
    $links += [PSCustomObject]@{
      Ioc  = $domain
      Type = "domain"
      Links = [ordered]@{
        VirusTotal    = "https://www.virustotal.com/gui/domain/$domain"
        UrlScan       = "https://urlscan.io/search/#domain:$domain"
        Censys        = "https://search.censys.io/search?resource_type=hosts&q=$domain"
        SecurityTrails = "https://securitytrails.com/domain/$domain"
        Whois         = "https://who.is/whois/$domain"
      }
    }
  }

  # Hash pivot links
  $hashes = @($Evidence.Iocs.Hashes | Select-Object -Unique)
  foreach ($hash in $hashes) {
    if (-not $hash) { continue }
    $links += [PSCustomObject]@{
      Ioc  = $hash
      Type = "hash"
      Links = [ordered]@{
        VirusTotal    = "https://www.virustotal.com/gui/file/$hash"
        MalwareBazaar = "https://bazaar.abuse.ch/sample/$hash/"
        JoeSandbox    = "https://www.joesandbox.com/search?q=$hash"
      }
    }
  }

  # URL pivot links
  $urls = @($Evidence.Iocs.Urls | Select-Object -Unique | Select-Object -First 20)
  foreach ($url in $urls) {
    if (-not $url) { continue }
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($url)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $links += [PSCustomObject]@{
      Ioc  = $url
      Type = "url"
      Links = [ordered]@{
        VirusTotal = "https://www.virustotal.com/gui/url/$b64"
        UrlScan    = "https://urlscan.io/search/#page.url:$url"
      }
    }
  }

  return $links
}

# ── Main Orchestrator ────────────────────────────────────────────────────────

function Invoke-RoninOsint {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$Evidence,
    [switch]$Offline
  )

  $osintCfg = $Evidence.Config.osint

  # Check if module is configured
  if (-not $osintCfg -or $osintCfg.enabled -eq $false) {
    $Evidence.Osint.Notes += "OSINT module disabled in config."
    return $Evidence
  }

  # Always generate pivot links (zero network calls)
  $Evidence.Osint.PivotLinks = @(New-RoninOsintLinks -Evidence $Evidence)

  if ($Offline) {
    $Evidence.Osint.Notes += "Offline mode: OSINT API lookups skipped. Pivot links generated for manual investigation."
    return $Evidence
  }

  # Collect IPs to profile (origin IP first, then IOCs)
  $ipList = @()
  if ($Evidence.Received.OriginIp) { $ipList += $Evidence.Received.OriginIp }
  foreach ($ip in ($Evidence.Iocs.Ips | Select-Object -Unique)) {
    if ($ip -and $ipList -notcontains $ip) { $ipList += $ip }
  }
  $maxIps = [int]$(if ($null -ne $osintCfg.maxIpProfiles) { $osintCfg.maxIpProfiles } else { 10 })
  if ($ipList.Count -gt $maxIps) { $ipList = $ipList[0..($maxIps - 1)] }

  # Profile each IP
  $ipProfileList = [System.Collections.Generic.List[object]]::new()
  foreach ($ip in $ipList) {
    $ipProfile = Get-RoninIpProfile -Ip $ip -Evidence $Evidence -Offline:$Offline
    $ipProfileList.Add($ipProfile)
  }
  $Evidence.Osint.IpProfiles = @($ipProfileList)

  # Collect domains to profile (filter out infrastructure)
  $domainList = @()
  $filter = @($(if ($osintCfg.infrastructureDomainFilter) { $osintCfg.infrastructureDomainFilter } else { @() }))
  foreach ($domain in ($Evidence.Iocs.Domains | Select-Object -Unique)) {
    if (-not $domain) { continue }
    $skip = $false
    foreach ($f in $filter) { if ($domain -match [regex]::Escape($f)) { $skip = $true; break } }
    if (-not $skip) { $domainList += $domain }
  }
  $maxDomains = [int]$(if ($null -ne $osintCfg.maxDomainProfiles) { $osintCfg.maxDomainProfiles } else { 5 })
  if ($domainList.Count -gt $maxDomains) { $domainList = $domainList[0..($maxDomains - 1)] }

  # Profile each domain
  $domProfileList = [System.Collections.Generic.List[object]]::new()
  foreach ($domain in $domainList) {
    $domainProfile = Get-RoninDomainProfile -Domain $domain -Evidence $Evidence -Offline:$Offline
    $domProfileList.Add($domainProfile)
  }
  $Evidence.Osint.DomainProfiles = @($domProfileList)

  # Classify threat infrastructure
  if (@($Evidence.Osint.IpProfiles).Count -gt 0) {
    $Evidence.Osint.ThreatClassification = Get-RoninThreatClassification -IpProfiles @($Evidence.Osint.IpProfiles) -Config $Evidence.Config
  }

  return $Evidence
}

# ── Console Display ──────────────────────────────────────────────────────────

function Show-RoninOsint {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$Evidence)

  "=== RoninOsint ==="
  ""

  $tc = $Evidence.Osint.ThreatClassification
  if ($tc.OverallType -ne 'unknown') {
    "Threat Classification: {0} ({1} confidence)" -f $tc.OverallType.ToUpper(), $tc.Confidence
    foreach ($ind in $tc.Indicators) { "  - $ind" }
    ""
  }

  if ($Evidence.Osint.IpProfiles.Count -gt 0) {
    "IP Profiles:"
    foreach ($ip in $Evidence.Osint.IpProfiles) {
      if ($ip.Classification.InfraType -eq 'private') { continue }
      "  {0}" -f $ip.Ip
      if ($ip.Geolocation.Country) {
        "    Location:    {0}, {1}, {2}" -f $ip.Geolocation.City, $ip.Geolocation.Region, $ip.Geolocation.Country
      }
      if ($ip.Network.Isp) {
        "    ISP:         {0} ({1})" -f $ip.Network.Isp, $ip.Network.Asn
      }
      if ($ip.ReverseDns) {
        "    Reverse DNS: {0}" -f $ip.ReverseDns
      }
      "    Hosting: {0} | Proxy: {1} | Mobile: {2}" -f $ip.Classification.IsHosting, $ip.Classification.IsProxy, $ip.Classification.IsMobile
      if ($ip.AbuseIpDb.Score -gt 0) {
        "    AbuseIPDB:   Score {0}%, {1} reports" -f $ip.AbuseIpDb.Score, $ip.AbuseIpDb.Reports
      }
      if ($ip.Shodan.Ports.Count -gt 0) {
        "    Shodan:      Ports [{0}]" -f ($ip.Shodan.Ports -join ", ")
      }
      if (@($ip.Censys.Services).Count -gt 0) {
        $cenPorts = @($ip.Censys.Services | ForEach-Object { "$($_.Port)/$($_.ServiceName)" })
        "    Censys:      {0} service(s) [{1}]" -f $ip.Censys.TotalServices, ($cenPorts -join ", ")
      }
      if ($ip.VirusTotal.Malicious -gt 0 -or $ip.VirusTotal.Suspicious -gt 0) {
        "    VirusTotal:  {0} malicious, {1} suspicious" -f $ip.VirusTotal.Malicious, $ip.VirusTotal.Suspicious
      }
      ""
    }
  }

  if ($Evidence.Osint.DomainProfiles.Count -gt 0) {
    "Domain Profiles:"
    foreach ($dp in $Evidence.Osint.DomainProfiles) {
      "  {0}" -f $dp.Domain
      if ($dp.Whois.Registrar) { "    Registrar:  {0}" -f $dp.Whois.Registrar }
      if ($dp.Whois.AgeInDays -ge 0) {
        "    Created:    {0} (age: {1} days)" -f $dp.Whois.CreatedDate, $dp.Whois.AgeInDays
      }
      if ($dp.VirusTotal.Malicious -gt 0) {
        "    VirusTotal: {0} malicious detections" -f $dp.VirusTotal.Malicious
      }
      ""
    }
  }

  if ($Evidence.Osint.PivotLinks.Count -gt 0) {
    "Pivot Links: {0} IOCs with investigation links (see HTML report for clickable links)" -f $Evidence.Osint.PivotLinks.Count
    ""
  }

  if ($Evidence.Osint.Notes.Count -gt 0) {
    "Notes:"
    foreach ($n in $Evidence.Osint.Notes) { "  - $n" }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# THINKPOL EXPANSION — Phase 3: Identity Pivot
# Added: Username variants, Sherlock, WhatsMyName, Reddit/THINKPOL persona
# Author: HoneyBadger (HoneyBadger Vanguard, LLC) | Version: 2.0.0
# Attribution: Sherlock Project (github.com/sherlock-project/sherlock),
#              WhatsMyName/WebBreacher (github.com/WebBreacher/WhatsMyName),
#              THINKPOL (think-pol.com) — Reddit OSINT Platform (@101R00M)
# ═══════════════════════════════════════════════════════════════════════════════

$script:IdentityConfig = @{
  Sherlock = @{
    PythonExe  = 'python3'
    TimeoutSec = 180
    OutputDir  = "$env:TEMP\ronin_sherlock"
  }
  WhatsMyName = @{
    DbUrl     = 'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
    LocalDb   = "$env:APPDATA\PhishRonin\wmn-data.json"
    MaxWorkers = 20
  }
  Reddit = @{
    BaseUrl   = 'https://www.reddit.com'
    UserAgent = 'PhishRonin/2.0 OSINT-Research (HoneyBadgerVanguard)'
    PostLimit = 100
  }
  Scoring = @{
    UsernameFound      = 5
    RedditAccountFound = 15
    ThreatActorKeyword = 30
    InfostealerKeyword = 40
    NewAccount         = 10
  }
}

$script:ThreatKeywords = @(
  'phish','carding','credential','combo list','fullz','logs','stealer',
  'rat ','c2 ','payload','loader','crypter','account for sale','drops',
  'money mule','cashout','cvv','darkweb','onion','telegram shop',
  'escrow','verified seller','infostealer','redline','raccoon','vidar'
)

function Invoke-UsernameVariants {
  <#
  .SYNOPSIS
      Generate probable username permutations from an email address.
  .DESCRIPTION
      Extracts the local part of an email and produces common username
      variants for use with Sherlock and WhatsMyName.
  .EXAMPLE
      Invoke-UsernameVariants -Email "john.doe@gmail.com"
  #>
  [CmdletBinding()]
  [OutputType([string[]])]
  param([Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Email)
  process {
    $local    = ($Email -split '@')[0].ToLower()
    $variants = [System.Collections.Generic.HashSet[string]]::new()
    [void]$variants.Add($local)
    $clean = $local -replace '[._\-]', ''
    [void]$variants.Add($clean)
    $parts = $local -split '[._\-]'
    if ($parts.Count -ge 2) {
      $first = $parts[0]; $last = $parts[-1]
      foreach ($v in @("$first$last","$first.$last","$first`_$last",
                       "$($first[0])$last","$first$($last[0])")) {
        [void]$variants.Add($v)
      }
      if ($first.Length -ge 3) { [void]$variants.Add($first) }
      if ($last.Length  -ge 3) { [void]$variants.Add($last)  }
    }
    $noNums = $local -replace '\d+', ''
    if ($noNums -ne $local -and $noNums.Length -ge 3) { [void]$variants.Add($noNums) }
    return $variants.ToArray() | Where-Object { $_.Length -ge 3 }
  }
}

function Invoke-Sherlock {
  <#
  .SYNOPSIS
      Hunt username across 400+ social sites via Sherlock (Python subprocess).
  .DESCRIPTION
      Wraps the Sherlock tool, parses output, and returns structured account
      findings. Install with: pip install sherlock-project --break-system-packages
      Credit: Sherlock Project — https://github.com/sherlock-project/sherlock
  .PARAMETER Username
      Username(s) to search for. Accepts pipeline input.
  .EXAMPLE
      Invoke-Sherlock -Username "suspicious_user"
  .EXAMPLE
      Invoke-UsernameVariants -Email "bad@evil.com" | Invoke-Sherlock
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Username,
    [Parameter()][int]$TimeoutPerSite = 15,
    [Parameter()][string]$PythonExe = $script:IdentityConfig.Sherlock.PythonExe
  )
  begin {
    $outputDir = $script:IdentityConfig.Sherlock.OutputDir
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
  }
  process {
    $sid        = [System.Guid]::NewGuid().ToString('N').Substring(0,8)
    $outputFile = Join-Path $outputDir "$Username`_$sid.csv"
    $stdoutFile = "$outputDir\stdout_$sid.txt"
    $stderrFile = "$outputDir\stderr_$sid.txt"
    Write-Verbose "Sherlock: $Username"
    try {
      Start-Process -FilePath $PythonExe `
        -ArgumentList @('-m','sherlock',$Username,'--csv','--output',$outputFile,'--timeout',$TimeoutPerSite,'--print-found') `
        -Wait -NoNewWindow -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile | Out-Null
      $accounts = [System.Collections.Generic.List[PSCustomObject]]::new()
      if (Test-Path $outputFile) {
        foreach ($row in (Import-Csv $outputFile)) {
          if ($row.exists -eq 'True' -or $row.status -eq 'Claimed') {
            $accounts.Add([PSCustomObject]@{ Site=$row.siteName ?? $row.site; URL=$row.link ?? $row.url; Status='FOUND' })
          }
        }
      } else {
        foreach ($line in (Get-Content $stdoutFile -ErrorAction SilentlyContinue)) {
          if ($line -match '\[\+\]\s+(.+?):\s+(https?://\S+)') {
            $accounts.Add([PSCustomObject]@{ Site=$Matches[1].Trim(); URL=$Matches[2].Trim(); Status='FOUND' })
          }
        }
      }
      return [PSCustomObject]@{
        PSTypeName        = 'PhishRonin.SherlockResult'
        Username          = $Username
        AccountsFound     = $accounts.Count
        Accounts          = $accounts.ToArray()
        ScoreContribution = $accounts.Count * $script:IdentityConfig.Scoring.UsernameFound
        Source            = 'Sherlock'
        Timestamp         = Get-Date -Format 'o'
      }
    } finally {
      Remove-Item $outputFile,$stdoutFile,$stderrFile -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-WhatsMyName {
  <#
  .SYNOPSIS
      Check username across sites using the WhatsMyName database (pure PowerShell).
  .DESCRIPTION
      Downloads/uses cached WhatsMyName JSON DB and probes each site directly.
      No Python dependency — runs entirely in PowerShell via parallel HTTP tasks.
      Credit: WebBreacher — https://github.com/WebBreacher/WhatsMyName
  .PARAMETER Username
      Username to enumerate.
  .PARAMETER UpdateDb
      Force re-download of the WhatsMyName database.
  .PARAMETER Categories
      Limit to specific categories (e.g. 'social', 'gaming', 'tech').
  .EXAMPLE
      Invoke-WhatsMyName -Username "target_user"
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Username,
    [Parameter()][switch]$UpdateDb,
    [Parameter()][string[]]$Categories,
    [Parameter()][int]$MaxWorkers = $script:IdentityConfig.WhatsMyName.MaxWorkers
  )
  process {
    $dbPath = $script:IdentityConfig.WhatsMyName.LocalDb
    $dbDir  = Split-Path $dbPath -Parent
    if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory $dbDir -Force | Out-Null }
    if ($UpdateDb -or -not (Test-Path $dbPath)) {
      Write-Verbose "Downloading WhatsMyName database..."
      Invoke-WebRequest -Uri $script:IdentityConfig.WhatsMyName.DbUrl -OutFile $dbPath -UseBasicParsing
    }
    $db    = (Get-Content $dbPath -Raw | ConvertFrom-Json).websites
    $sites = if ($Categories) { $db | Where-Object { $_.category -in $Categories } } else { $db }
    Write-Verbose "WhatsMyName: $Username across $($sites.Count) sites"
    $found     = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
    $semaphore = [System.Threading.SemaphoreSlim]::new($MaxWorkers, $MaxWorkers)
    $jobs = $sites | ForEach-Object -ThrottleLimit $MaxWorkers -Parallel {
      $site      = $_
      $found     = $using:found
      $semaphore = $using:semaphore
      $Username  = $using:Username
      $semaphore.Wait()
      try {
        $checkUrl = $site.uri_check -replace '{account}', $Username
        $resp = Invoke-WebRequest -Uri $checkUrl -Method GET -UserAgent 'PhishRonin/2.0' `
                  -TimeoutSec 10 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($resp) {
          $falseStr = if ($site.m_string_false) { $site.m_string_false } else { '###NOMATCH###' }
          $hit = if ($site.e_code -gt 0) {
            $resp.StatusCode -eq $site.e_code
          } else {
            ($resp.Content -match [regex]::Escape($site.m_string)) -and
            -not ($resp.Content -match [regex]::Escape($falseStr))
          }
          if ($hit) {
            $prettyUrl = $site.uri_pretty -replace '{account}', $Username
            $found.Add([PSCustomObject]@{
              Site     = $site.name
              URL      = $prettyUrl
              Category = $site.category
              Status   = 'FOUND'
            })
          }
        }
      } catch {}
      finally { $semaphore.Release() | Out-Null }
    }
    $results = $found.ToArray() | Sort-Object Site
    return [PSCustomObject]@{
      PSTypeName        = 'PhishRonin.WMNResult'
      Username          = $Username
      AccountsFound     = $results.Count
      Accounts          = $results
      ScoreContribution = $results.Count * $script:IdentityConfig.Scoring.UsernameFound
      Source            = 'WhatsMyName'
      Timestamp         = Get-Date -Format 'o'
    }
  }
}

function Invoke-RedditPersona {
  <#
  .SYNOPSIS
      Deep behavioral analysis of a Reddit account via public JSON API.
  .DESCRIPTION
      Builds a behavioral profile including: account age, karma, top subreddits,
      posting time patterns (timezone inference), threat keyword detection,
      and personality indicators. No API key required.

      Methodology credit: THINKPOL (think-pol.com) | @101R00M
      Concept credit: reddit_persona (github.com/n2itn/reddit_persona)
  .PARAMETER Username
      Reddit username to profile.
  .EXAMPLE
      Invoke-RedditPersona -Username "suspicious_redditor"
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Username,
    [Parameter()][int]$PostLimit = $script:IdentityConfig.Reddit.PostLimit
  )
  process {
    $headers = @{ 'User-Agent' = $script:IdentityConfig.Reddit.UserAgent; 'Accept' = 'application/json' }
    Write-Verbose "Reddit persona: u/$Username"
    try {
      $about = Invoke-RestMethod -Uri "$($script:IdentityConfig.Reddit.BaseUrl)/user/$Username/about.json" `
                 -Headers $headers -TimeoutSec 15
    } catch {
      if ($_.Exception.Response?.StatusCode -eq 404) {
        return [PSCustomObject]@{ PSTypeName='PhishRonin.RedditPersonaResult'; Username=$Username; Exists=$false; Error='Account not found' }
      }
      throw
    }
    $acct       = $about.data
    $created    = [DateTimeOffset]::FromUnixTimeSeconds($acct.created_utc).UtcDateTime
    $accountAge = (Get-Date) - $created

    # Fetch posts and comments
    $allContent = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($type in @('submitted','comments')) {
      $after = $null
      do {
        $uri  = "$($script:IdentityConfig.Reddit.BaseUrl)/user/$Username/$type.json?limit=100"
        if ($after) { $uri += "&after=$after" }
        $resp = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 15 -ErrorAction SilentlyContinue
        if (-not $resp) { break }
        foreach ($item in $resp.data.children) { $allContent.Add($item.data) }
        $after = $resp.data.after
      } while ($after -and $allContent.Count -lt $PostLimit)
    }

    $subreddits = $allContent | Group-Object subreddit | Sort-Object Count -Descending |
                  Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ Subreddit=$_.Name; Count=$_.Count } }

    $postHours  = $allContent | ForEach-Object { [DateTimeOffset]::FromUnixTimeSeconds($_.created_utc).Hour } |
                  Group-Object | Sort-Object Count -Descending
    $peakHour   = ($postHours | Select-Object -First 1).Name
    $inferredTZ = if ($peakHour) { "Peak UTC hour: $peakHour (inferred local ~$(($peakHour + 8) % 24) EST)" } else { 'Insufficient data' }

    $allText     = ($allContent | ForEach-Object { $_.body ?? $_.selftext ?? $_.title ?? '' }) -join ' '
    $allTextLow  = $allText.ToLower()
    $threatHits  = $script:ThreatKeywords | Where-Object { $allTextLow -match [regex]::Escape($_) }

    $scoreAdd = 0; $flags = [System.Collections.Generic.List[string]]::new()
    if ($acct.total_karma -gt 100)    { $scoreAdd += $script:IdentityConfig.Scoring.RedditAccountFound }
    if ($threatHits.Count -gt 0)      { $scoreAdd += $script:IdentityConfig.Scoring.ThreatActorKeyword * [Math]::Min($threatHits.Count, 3)
                                         $flags.Add("THREAT_KW:$($threatHits -join ',')") }
    if ($accountAge.TotalDays -lt 30) { $scoreAdd += $script:IdentityConfig.Scoring.NewAccount; $flags.Add('NEW_ACCOUNT') }
    if ($acct.is_suspended)           { $scoreAdd += 15; $flags.Add('SUSPENDED') }

    return [PSCustomObject]@{
      PSTypeName         = 'PhishRonin.RedditPersonaResult'
      Username           = $Username
      Exists             = $true
      AccountCreated     = $created
      AccountAgeDays     = [int]$accountAge.TotalDays
      TotalKarma         = $acct.total_karma
      PostKarma          = $acct.link_karma
      CommentKarma       = $acct.comment_karma
      IsSuspended        = [bool]$acct.is_suspended
      PostCount          = ($allContent | Where-Object { $_.selftext -ne $null }).Count
      CommentCount       = ($allContent | Where-Object { $_.body    -ne $null }).Count
      TopSubreddits      = $subreddits
      InferredTimezone   = $inferredTZ
      PeakActivityHour   = $peakHour
      ThreatKeywordHits  = $threatHits.Count
      ThreatKeywords     = @($threatHits)
      Flags              = $flags.ToArray()
      ScoreContribution  = $scoreAdd
      MethodologyCredit  = 'THINKPOL (think-pol.com) @101R00M + reddit_persona (github.com/n2itn/reddit_persona)'
      Source             = 'Reddit Public API'
      Timestamp          = Get-Date -Format 'o'
    }
  }
}

function Invoke-RoninIdentityPivot {
  <#
  .SYNOPSIS
      Full Phase 3 identity pivot — email to social graph.
  .DESCRIPTION
      Given a phishing sender email:
        1. Derives username variants from email local part
        2. Hunts usernames across 400+ sites (Sherlock — requires Python)
        3. Enumerates accounts (WhatsMyName — pure PowerShell)
        4. Pivots to Reddit for behavioral profiling (THINKPOL methodology)
      Returns unified identity intelligence for the PhishRonin Evidence pipeline.
  .PARAMETER Email
      Sender email address from phishing investigation.
  .PARAMETER SkipSherlock
      Skip Sherlock (if Python / sherlock-project not installed).
  .PARAMETER SkipWhatsMyName
      Skip WhatsMyName probing (faster triage).
  .PARAMETER RedditUsername
      Explicitly specify Reddit username (overrides auto-detection).
  .EXAMPLE
      Invoke-RoninIdentityPivot -Email "attacker@protonmail.com"
  .EXAMPLE
      Invoke-RoninIdentityPivot -Email "evil@example.com" -SkipSherlock
  #>
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$Email,
    [Parameter()][switch]$SkipSherlock,
    [Parameter()][switch]$SkipWhatsMyName,
    [Parameter()][string]$RedditUsername
  )
  process {
    Write-Host "  [*] Identity Pivot: $Email" -ForegroundColor Magenta

    Write-Host "  [->] Username variants..." -ForegroundColor DarkMagenta
    $usernames = Invoke-UsernameVariants -Email $Email
    Write-Host "      $($usernames -join ', ')" -ForegroundColor DarkGray

    $sherlockResults = @(); $wmnResults = @(); $redditResult = $null

    if (-not $SkipSherlock) {
      Write-Host "  [->] Sherlock ($($usernames.Count) variants)..." -ForegroundColor DarkMagenta
      try { $sherlockResults = $usernames | ForEach-Object { Invoke-Sherlock -Username $_ -ErrorAction SilentlyContinue } }
      catch { Write-Warning "Sherlock skipped: $_" }
    }

    if (-not $SkipWhatsMyName) {
      Write-Host "  [->] WhatsMyName..." -ForegroundColor DarkMagenta
      try { $wmnResults = $usernames | Select-Object -First 3 | ForEach-Object { Invoke-WhatsMyName -Username $_ -ErrorAction SilentlyContinue } }
      catch { Write-Warning "WhatsMyName skipped: $_" }
    }

    # Reddit — auto-detect from Sherlock hits or try primary variant
    $redditUser = $RedditUsername
    if (-not $redditUser) {
      $redditAccount = @($sherlockResults | ForEach-Object { $_.Accounts }) |
                       Where-Object { $_.Site -match 'reddit' } | Select-Object -First 1
      $redditUser = if ($redditAccount) {
        ($redditAccount.URL -split '/user/')[1] -replace '/$',''
      } else { $usernames[0] }
    }

    if ($redditUser) {
      Write-Host "  [->] THINKPOL Reddit behavioral analysis: u/$redditUser" -ForegroundColor DarkMagenta
      try { $redditResult = Invoke-RedditPersona -Username $redditUser -ErrorAction SilentlyContinue }
      catch { Write-Warning "Reddit analysis skipped: $_" }
    }

    $allAccounts = @(@($sherlockResults | ForEach-Object { $_.Accounts }); @($wmnResults | ForEach-Object { $_.Accounts }))
    $totalScore  = ((@($sherlockResults) + @($wmnResults) | ForEach-Object { $_.ScoreContribution ?? 0 }) + ($redditResult?.ScoreContribution ?? 0) | Measure-Object -Sum).Sum
    $riskLevel   = switch ($totalScore) {
      { $_ -ge 75 } { 'CRITICAL' }
      { $_ -ge 50 } { 'HIGH' }
      { $_ -ge 25 } { 'MEDIUM' }
      default       { 'LOW' }
    }

    Write-Host "  [+] Identity: $($allAccounts.Count) accounts | Reddit: $(if($redditResult?.Exists){'PROFILED'}else{'N/A'}) | Risk: $riskLevel" -ForegroundColor $(
      switch ($riskLevel) { 'CRITICAL' { 'Red' } 'HIGH' { 'Yellow' } 'MEDIUM' { 'Magenta' } default { 'Green' } }
    )

    return [PSCustomObject]@{
      PSTypeName         = 'PhishRonin.IdentityPivotResult'
      Email              = $Email
      UsernameVariants   = $usernames
      ThreatScore        = [Math]::Min($totalScore, 100)
      RiskLevel          = $riskLevel
      TotalAccountsFound = $allAccounts.Count
      AllAccounts        = $allAccounts
      SherlockResults    = $sherlockResults
      WMNResults         = $wmnResults
      RedditUsername     = $redditUser
      RedditProfile      = $redditResult
      TopCommunities     = ($redditResult?.TopSubreddits | Select-Object -First 5 | ForEach-Object { "r/$($_.Subreddit)" }) -join ', '
      ThreatKeywords     = $redditResult?.ThreatKeywords ?? @()
      Attribution        = @{
        Sherlock    = 'https://github.com/sherlock-project/sherlock'
        WhatsMyName = 'https://github.com/WebBreacher/WhatsMyName'
        ThinkPol    = 'https://think-pol.com (@101R00M)'
      }
      Timestamp          = Get-Date -Format 'o'
    }
  }
}

Export-ModuleMember -Function `
  Invoke-RoninOsint, Get-RoninIpProfile, Get-RoninDomainProfile, `
  Get-RoninThreatClassification, New-RoninOsintLinks, Show-RoninOsint, `
  Invoke-UsernameVariants, Invoke-Sherlock, Invoke-WhatsMyName, `
  Invoke-RedditPersona, Invoke-RoninIdentityPivot

