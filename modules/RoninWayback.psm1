Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Common phishing kit paths to flag when found in Wayback snapshots
$script:PhishPaths = @(
  '/login','/signin','/sign-in','/auth','/verify','/secure',
  '/office365','/office','/microsoft','/outlook','/owa',
  '/wp-admin','/admin','/panel','/dashboard','/cpanel',
  '/update','/account','/billing','/payment','/invoice',
  '/dropbox','/onedrive','/sharepoint','/wetransfer',
  '/.env','/config.php','/config.json','/web.config',
  '/.git','/debug','/phpinfo','/server-status',
  '/robots.txt','/sitemap.xml'
)

# ── Main entry point ─────────────────────────────────────────────────────────

function Invoke-RoninWayback {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [int]$DelayMs        = 1200,   # polite rate-limit between CDX calls
    [int]$SnapshotLimit  = 500,    # max snapshots per domain query
    [switch]$IncludeSubdomains,
    [switch]$IncludeSenderDomain
  )

  $results = [PSCustomObject]@{
    Domains        = @()
    Timeline       = @()
    PhishingPaths  = @()
    Subdomains     = @()
    TotalSnapshots = 0
    Summary        = ''
  }

  # ── Collect target domains from evidence ──────────────────────────────────

  $targetDomains = [System.Collections.Generic.List[string]]::new()

  # QR code payload URLs (highest value -- these are the phish landing pages)
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'image' -and $a.Findings.HasQrCode -and $a.Findings.QrPayloadType -eq 'url') {
      $d = Get-WaybackDomainFromUrl $a.Findings.QrPayload
      if ($d -and -not $targetDomains.Contains($d)) { $targetDomains.Add($d) }
    }
    if ($a.Type -eq 'docx' -and $a.Findings.ContainsKey('QrCodesFound') -and $a.Findings.QrCodesFound -gt 0) {
      foreach ($img in $a.Findings.Images) {
        # RoninDoc image entries use 'HasQR' (not 'HasQrCode') and 'QrPayload'
        if ($img.HasQR -and $img.QrPayload) {
          $d = Get-WaybackDomainFromUrl $img.QrPayload
          if ($d -and -not $targetDomains.Contains($d)) { $targetDomains.Add($d) }
        }
      }
    }
  }

  # IOC URLs extracted from headers/body
  foreach ($url in @($Evidence.Iocs.Urls)) {
    if (-not $url) { continue }
    $d = Get-WaybackDomainFromUrl $url
    if ($d -and -not $targetDomains.Contains($d)) { $targetDomains.Add($d) }
  }

  # Extracted URLs from document artifacts
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'docx') {
      foreach ($u in @($a.Artifacts.Urls)) {
        if (-not $u) { continue }
        $d = Get-WaybackDomainFromUrl $u
        if ($d -and -not $targetDomains.Contains($d)) { $targetDomains.Add($d) }
      }
    }
  }

  # Sender domain (optional -- useful for domain age/history but could be legit spoofed domain)
  if ($IncludeSenderDomain -and $Evidence.Message.From) {
    $m = [regex]::Match($Evidence.Message.From, '(?i)@([a-z0-9.\-]+\.[a-z]{2,63})')
    if ($m.Success) {
      $sd = $m.Groups[1].Value.ToLowerInvariant()
      if (-not $targetDomains.Contains($sd)) { $targetDomains.Add($sd) }
    }
  }

  # Filter out known-safe infrastructure domains (we don't need Wayback for microsoft.com)
  $safeDomains = @(
    'microsoft.com','outlook.com','live.com','office.com','office365.com',
    'google.com','gmail.com','googleapis.com','gstatic.com',
    'windowsupdate.com','windows.net','azure.com','cloudflare.com',
    'akamai.net','amazonaws.com','cloudfront.net'
  )
  $filteredDomains = @($targetDomains | Where-Object {
    $domain = $_
    $dominated = $false
    foreach ($safe in $safeDomains) {
      if ($domain -eq $safe -or $domain.EndsWith(".$safe")) { $dominated = $true; break }
    }
    -not $dominated
  })

  if ($filteredDomains.Count -eq 0) {
    Write-Host "[RoninWayback] No target domains to query (all filtered or none found)"
    $results.Summary = "Wayback: 0 domains queried"
    $Evidence | Add-Member -NotePropertyName 'Wayback' -NotePropertyValue $results -Force
    return $Evidence
  }

  Write-Host "[RoninWayback] Querying Internet Archive for $($filteredDomains.Count) domain(s): $($filteredDomains -join ', ')"

  # ── Query CDX API for each domain ─────────────────────────────────────────

  foreach ($domain in $filteredDomains) {
    $domainResult = [PSCustomObject]@{
      Domain           = $domain
      Snapshots        = @()
      FirstSeen        = ''
      LastSeen         = ''
      TotalSnapshots   = 0
      PhishPagesFound  = @()
      SubdomainsFound  = @()
      DirectoryListing = $false
      ConfigExposed    = $false
    }

    # ── Primary CDX query: all URLs under this domain ──
    $cdxUrl = "https://web.archive.org/cdx/search/cdx?url={0}/*&output=json&fl=timestamp,original,statuscode,mimetype&limit={1}&collapse=urlkey" -f $domain, $SnapshotLimit
    $snapshots = Invoke-WaybackCdx -Url $cdxUrl
    Start-Sleep -Milliseconds $DelayMs

    # ── Also query the bare domain (root page) ──
    $cdxRoot = "https://web.archive.org/cdx/search/cdx?url={0}&output=json&fl=timestamp,original,statuscode,mimetype&limit=50&collapse=timestamp:8" -f $domain
    $rootSnaps = Invoke-WaybackCdx -Url $cdxRoot
    Start-Sleep -Milliseconds $DelayMs

    # Merge, dedup by timestamp+url
    $allSnaps = @($snapshots) + @($rootSnaps)
    $seen = @{}
    $deduped = @()
    foreach ($s in $allSnaps) {
      if (-not $s) { continue }
      $key = "{0}|{1}" -f $s.Timestamp, $s.Original
      if (-not $seen.ContainsKey($key)) {
        $seen[$key] = $true
        $deduped += $s
      }
    }

    $domainResult.Snapshots = $deduped
    $domainResult.TotalSnapshots = $deduped.Count

    if ($deduped.Count -gt 0) {
      $sorted = @($deduped | Sort-Object { $_.Timestamp })
      $domainResult.FirstSeen = $sorted[0].Timestamp
      $domainResult.LastSeen  = $sorted[-1].Timestamp

      Write-Host "[RoninWayback]   $domain : $($deduped.Count) snapshot(s), first=$(Format-WaybackDate $domainResult.FirstSeen), last=$(Format-WaybackDate $domainResult.LastSeen)"

      # ── Scan snapshots for phishing paths and interesting artifacts ──
      foreach ($snap in $deduped) {
        $urlPath = Get-WaybackUrlPath $snap.Original

        # Check against known phishing paths
        foreach ($pp in $script:PhishPaths) {
          if ($urlPath.ToLowerInvariant() -like "*$pp*") {
            $domainResult.PhishPagesFound += [PSCustomObject]@{
              Path           = $urlPath
              Timestamp      = $snap.Timestamp
              Date           = Format-WaybackDate $snap.Timestamp
              StatusCode     = $snap.StatusCode
              MimeType       = $snap.MimeType
              WaybackUrl     = "https://web.archive.org/web/{0}/{1}" -f $snap.Timestamp, $snap.Original
              MatchedPattern = $pp
            }
            break  # one match per snapshot is enough
          }
        }

        # Detect directory listings (Index of /)
        if ($snap.MimeType -match 'text/html' -and $urlPath -eq '/') {
          # We can't see the content from CDX alone, but flag for manual review
        }

        # Detect exposed config/env files
        if ($urlPath -match '(?i)\.(env|config|json|php\.bak|sql|log)$') {
          $domainResult.ConfigExposed = $true
        }
      }
    } else {
      Write-Host "[RoninWayback]   $domain : no snapshots found"
    }

    # ── Subdomain discovery via wildcard CDX query ──
    if ($IncludeSubdomains) {
      $subCdxUrl = "https://web.archive.org/cdx/search/cdx?url=*.{0}&output=json&fl=timestamp,original&collapse=urlkey&limit=200" -f $domain
      $subSnaps = Invoke-WaybackCdx -Url $subCdxUrl
      Start-Sleep -Milliseconds $DelayMs

      $subdomains = [System.Collections.Generic.List[string]]::new()
      foreach ($ss in $subSnaps) {
        if (-not $ss) { continue }
        $sd = Get-WaybackDomainFromUrl $ss.Original
        if ($sd -and $sd -ne $domain -and -not $subdomains.Contains($sd)) {
          $subdomains.Add($sd)
        }
      }
      $domainResult.SubdomainsFound = @($subdomains)
      if ($subdomains.Count -gt 0) {
        Write-Host "[RoninWayback]   $domain : $($subdomains.Count) subdomain(s) discovered"
        $results.Subdomains += @($subdomains)
      }
    }

    $results.Domains += $domainResult
    $results.PhishingPaths += @($domainResult.PhishPagesFound)
  }

  # ── Build unified timeline ──────────────────────────────────────────────

  $allTimeline = @()
  foreach ($d in $results.Domains) {
    foreach ($s in $d.Snapshots) {
      $allTimeline += [PSCustomObject]@{
        Date   = Format-WaybackDate $s.Timestamp
        Domain = $d.Domain
        Url    = $s.Original
        Status = $s.StatusCode
        Type   = $s.MimeType
      }
    }
  }
  $results.Timeline = @($allTimeline | Sort-Object { $_.Date })

  # ── Summary ─────────────────────────────────────────────────────────────

  $totalSnaps = 0
  foreach ($d in $results.Domains) { $totalSnaps += $d.TotalSnapshots }
  $results.TotalSnapshots = $totalSnaps

  $phishHits = $results.PhishingPaths.Count
  $subCount  = $results.Subdomains.Count
  $results.Summary = "Wayback: {0} domain(s), {1} snapshot(s), {2} phish path hit(s), {3} subdomain(s)" -f $filteredDomains.Count, $totalSnaps, $phishHits, $subCount

  Write-Host "[RoninWayback] $($results.Summary)"

  $Evidence | Add-Member -NotePropertyName 'Wayback' -NotePropertyValue $results -Force
  return $Evidence
}

# ── CDX API helper ──────────────────────────────────────────────────────────

function Invoke-WaybackCdx {
  [CmdletBinding()]
  param([string]$Url)

  try {
    # Use basic WebClient for PS5.1 compat -- Invoke-RestMethod sometimes chokes on JSON arrays
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'phishRonin/2.0 (OSINT research; +https://github.com/phishRonin)')
    $raw = $wc.DownloadString($Url)
    $wc.Dispose()

    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

    $data = $raw | ConvertFrom-Json

    if (-not $data -or $data.Count -le 1) { return @() }

    # First row is column headers; remaining rows are data
    $rows = @()
    for ($i = 1; $i -lt $data.Count; $i++) {
      $r = $data[$i]
      $rows += [PSCustomObject]@{
        Timestamp  = if ($r.Count -gt 0) { $r[0] } else { '' }
        Original   = if ($r.Count -gt 1) { $r[1] } else { '' }
        StatusCode = if ($r.Count -gt 2) { $r[2] } else { '' }
        MimeType   = if ($r.Count -gt 3) { $r[3] } else { '' }
      }
    }
    return $rows
  }
  catch {
    Write-Host "[RoninWayback] CDX query failed for: $Url"
    Write-Host "[RoninWayback]   Error: $_"
    return @()
  }
}

# ── URL / Domain helpers ────────────────────────────────────────────────────

function Get-WaybackDomainFromUrl {
  param([string]$Url)
  if (-not $Url) { return '' }
  $m = [regex]::Match($Url, '(?i)(?:https?://)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,63})')
  if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
  return ''
}

function Get-WaybackUrlPath {
  param([string]$Url)
  if (-not $Url) { return '/' }
  $m = [regex]::Match($Url, '(?i)https?://[^/]+(/.*)$')
  if ($m.Success) { return $m.Groups[1].Value }
  return '/'
}

function Format-WaybackDate {
  param([string]$WbTimestamp)
  if (-not $WbTimestamp) { return '' }
  if ($WbTimestamp.Length -ge 8) {
    return "{0}-{1}-{2}" -f $WbTimestamp.Substring(0,4), $WbTimestamp.Substring(4,2), $WbTimestamp.Substring(6,2)
  }
  return $WbTimestamp
}

# ── Display ─────────────────────────────────────────────────────────────────

function Show-RoninWayback {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  if (-not ($Evidence.PSObject.Properties.Name -contains 'Wayback')) {
    "No Wayback data available."
    return
  }

  $wb = $Evidence.Wayback
  "=== RoninWayback (Internet Archive) ==="
  $wb.Summary
  ""

  foreach ($d in $wb.Domains) {
    "Domain: {0}" -f $d.Domain
    "  Total snapshots: {0}" -f $d.TotalSnapshots
    if ($d.FirstSeen) { "  First seen:      {0}" -f (Format-WaybackDate $d.FirstSeen) }
    if ($d.LastSeen)  { "  Last seen:       {0}" -f (Format-WaybackDate $d.LastSeen) }
    if ($d.ConfigExposed) { "  [!] Config/env files exposed in archive!" }
    ""

    if (@($d.PhishPagesFound).Count -gt 0) {
      "  Phishing paths detected ({0}):" -f @($d.PhishPagesFound).Count
      foreach ($pp in $d.PhishPagesFound) {
        "    [{0}] {1} (HTTP {2})" -f $pp.Date, $pp.Path, $pp.StatusCode
        "      -> {0}" -f $pp.WaybackUrl
      }
      ""
    }

    if (@($d.SubdomainsFound).Count -gt 0) {
      "  Subdomains discovered ({0}):" -f @($d.SubdomainsFound).Count
      foreach ($sd in $d.SubdomainsFound) { "    $sd" }
      ""
    }
  }
}

Export-ModuleMember -Function Invoke-RoninWayback, Show-RoninWayback, Format-WaybackDate
