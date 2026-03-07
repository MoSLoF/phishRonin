Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-RoninEvidence {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Config)
  $now = Get-Date
  return [PSCustomObject]@{
    Meta        = @{ CaseId = ([guid]::NewGuid().ToString()); Timestamp = $now.ToString("s"); Analyst = $env:USERNAME }
    Message     = @{ Subject=""; From=""; To=@(); Cc=@(); Bcc=@(); Date=""; MessageId=""; ReplyTo=""; ReturnPath="" }
    Auth        = @{ Spf="unknown"; Dkim="unknown"; Dmarc="unknown"; Align="unknown"; AuthResultsRaw=@(); Notes=@() }
    Received    = @{ Hops=@(); OriginIp=""; OriginHost=""; }
    Urls        = @()
    Domains     = @()
    Attachments = @()
    Iocs        = @{ Ips=@(); Hashes=@(); Urls=@(); Domains=@() }
    Osint       = @{
      IpProfiles           = @()
      DomainProfiles       = @()
      ThreatClassification = @{ OverallType="unknown"; Confidence="low"; Indicators=@() }
      PivotLinks           = @()
      Notes                = @()
    }
    Score       = @{ Total=0; Verdict="unknown"; Reasons=@() }
    Actions     = @{ Suggested=@(); Taken=@() }
    Raw         = @{ Headers=""; Body=""; EmlPath=""; BodyText=""; BodyHtml=""; ExtractedAttachments=@(); MimeBoundaries=@(); IsEmptyHtmlBody=$false; IsEmptyTextBody=$false }
    Config      = $Config
  }
}

function Import-RoninEml {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][string]$Path
  )
  if (!(Test-Path $Path)) { throw "EML not found: $Path" }
  $raw = Get-Content -Raw -Path $Path
  $Evidence.Raw.EmlPath = (Resolve-Path $Path).Path

  # split headers/body at first blank line (non-capturing group to avoid split pollution)
  $split = $raw -split "(?:\r?\n){2}", 2
  if ($split.Count -ge 2) {
    $Evidence.Raw.Headers = $split[0]
    $Evidence.Raw.Body    = $split[1]
  } else {
    $Evidence.Raw.Headers = $raw
    $Evidence.Raw.Body    = ""
  }

  # quick parse for convenience
  $Evidence.Message.Subject    = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Subject')
  $Evidence.Message.From       = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'From')
  $Evidence.Message.Date       = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Date')
  $Evidence.Message.MessageId  = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Message-ID')
  $Evidence.Message.ReplyTo    = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Reply-To')
  $Evidence.Message.ReturnPath = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Return-Path')

  # Parse To/Cc/Bcc recipient lists
  $toRaw = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'To')
  if ($toRaw) {
    $Evidence.Message.To = @([regex]::Matches($toRaw, '(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63})') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
  }
  $ccRaw = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Cc')
  if ($ccRaw) {
    $Evidence.Message.Cc = @([regex]::Matches($ccRaw, '(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63})') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
  }
  $bccRaw = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Bcc')
  if ($bccRaw) {
    $Evidence.Message.Bcc = @([regex]::Matches($bccRaw, '(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63})') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
  }

  # --- MIME multipart extraction ---
  $contentType = (Get-RoninHeaderValue -RawHeaders $Evidence.Raw.Headers -Name 'Content-Type')
  if ($contentType -match '(?i)multipart/' -and $Evidence.Raw.Body) {
    $boundary = Get-RoninMimeBoundary -ContentType $contentType -RawHeaders $Evidence.Raw.Headers
    if ($boundary) {
      # Store all MIME boundaries for forensic analysis
      $allBounds = @($boundary)
      $bMatches = [regex]::Matches($Evidence.Raw.Headers + "`n" + $Evidence.Raw.Body, '(?i)boundary\s*=\s*"?([^"\s;]+)"?')
      foreach ($bm in $bMatches) {
        $bVal = $bm.Groups[1].Value
        if ($allBounds -notcontains $bVal) { $allBounds += $bVal }
      }
      $Evidence.Raw.MimeBoundaries = $allBounds

      $parts = Split-RoninMimeParts -Body $Evidence.Raw.Body -Boundary $boundary
      $extractDir = Join-Path ([IO.Path]::GetTempPath()) ("ronin-mime-" + [guid]::NewGuid().ToString())
      New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
      $Evidence = Read-RoninMimeParts -Parts $parts -Evidence $Evidence -ExtractDir $extractDir
    }
  }

  # Set empty body flags for downstream modules
  $Evidence.Raw.IsEmptyHtmlBody = [string]::IsNullOrWhiteSpace($Evidence.Raw.BodyHtml)
  $Evidence.Raw.IsEmptyTextBody = [string]::IsNullOrWhiteSpace($Evidence.Raw.BodyText)

  return $Evidence
}

# ── MIME helpers ──────────────────────────────────────────────────────────────

function Get-RoninMimeBoundary {
  [CmdletBinding()]
  param([string]$ContentType, [string]$RawHeaders)
  $m = [regex]::Match($ContentType, '(?i)boundary\s*=\s*"?([^"\s;]+)"?')
  if ($m.Success) { return $m.Groups[1].Value }
  # Fallback: boundary might be on a folded continuation line
  $norm = ($RawHeaders -replace "(\r?\n)[\t ]+", " ")
  $ctLine = [regex]::Match($norm, '(?im)^\s*Content-Type\s*:\s*(.+)$')
  if ($ctLine.Success) {
    $m2 = [regex]::Match($ctLine.Groups[1].Value, '(?i)boundary\s*=\s*"?([^"\s;]+)"?')
    if ($m2.Success) { return $m2.Groups[1].Value }
  }
  return $null
}

function Split-RoninMimeParts {
  [CmdletBinding()]
  param([string]$Body, [string]$Boundary)
  $delim = "--$Boundary"
  $segments = $Body -split [regex]::Escape($delim)
  $parts = @()
  foreach ($seg in $segments) {
    $trimmed = $seg.TrimStart("`r","`n")
    if (-not $trimmed -or $trimmed.StartsWith('--')) { continue }
    $partSplit = $trimmed -split "(?:\r?\n){2}", 2
    if ($partSplit.Count -ge 2) {
      $parts += [PSCustomObject]@{ Headers = $partSplit[0]; Body = $partSplit[1] }
    }
  }
  return $parts
}

function Read-RoninMimeParts {
  [CmdletBinding()]
  param([object[]]$Parts, [object]$Evidence, [string]$ExtractDir)

  foreach ($part in $Parts) {
    $pCt  = (Get-RoninHeaderValue -RawHeaders $part.Headers -Name 'Content-Type')
    $pCte = (Get-RoninHeaderValue -RawHeaders $part.Headers -Name 'Content-Transfer-Encoding')
    $pCd  = (Get-RoninHeaderValue -RawHeaders $part.Headers -Name 'Content-Disposition')

    # Recurse into nested multipart
    if ($pCt -match '(?i)multipart/') {
      $nestedBoundary = Get-RoninMimeBoundary -ContentType $pCt -RawHeaders $part.Headers
      if ($nestedBoundary) {
        $nested = Split-RoninMimeParts -Body $part.Body -Boundary $nestedBoundary
        $Evidence = Read-RoninMimeParts -Parts $nested -Evidence $Evidence -ExtractDir $ExtractDir
      }
      continue
    }

    # Extract text body parts
    if ($pCt -match '(?i)text/plain' -and -not $Evidence.Raw.BodyText) {
      $Evidence.Raw | Add-Member -NotePropertyName 'BodyText' -NotePropertyValue (Decode-RoninMimeText -Encoded $part.Body -Encoding $pCte) -Force
    }
    if ($pCt -match '(?i)text/html' -and -not $Evidence.Raw.BodyHtml) {
      $Evidence.Raw | Add-Member -NotePropertyName 'BodyHtml' -NotePropertyValue (Decode-RoninMimeText -Encoded $part.Body -Encoding $pCte) -Force
    }

    # Extract attachments (base64-encoded files)
    $isAttachment = ($pCd -match '(?i)attachment') -or ($pCt -match '(?i)application/')
    if ($isAttachment -and $pCte -match '(?i)base64') {
      $filename = Get-RoninMimeFilename -ContentDisposition $pCd -ContentType $pCt
      if (-not $filename) { $filename = "attachment-" + [guid]::NewGuid().ToString().Substring(0,8) }
      $outPath = Join-Path $ExtractDir $filename
      try {
        $clean = ($part.Body -replace '[\r\n\s]', '')
        [IO.File]::WriteAllBytes($outPath, [Convert]::FromBase64String($clean))
        # Initialize ExtractedAttachments array if not present
        if (-not ($Evidence.Raw.PSObject.Properties.Name -contains 'ExtractedAttachments')) {
          $Evidence.Raw | Add-Member -NotePropertyName 'ExtractedAttachments' -NotePropertyValue @() -Force
        }
        $Evidence.Raw.ExtractedAttachments += [PSCustomObject]@{
          Filename = $filename
          Path     = $outPath
          MimeType = $pCt
          Size     = (Get-Item $outPath).Length
        }
      } catch {
        $Evidence.Auth.Notes += "Failed to decode attachment '$filename': $_"
      }
    }
  }
  return $Evidence
}

function Decode-RoninMimeText {
  [CmdletBinding()]
  param([string]$Encoded, [string]$Encoding)
  switch -Regex ($Encoding) {
    '(?i)base64' {
      try {
        $clean = ($Encoded -replace '[\r\n\s]', '')
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($clean))
      } catch { return $Encoded }
    }
    '(?i)quoted-printable' {
      $text = $Encoded -replace '=\r?\n', ''
      $text = [regex]::Replace($text, '=([0-9A-Fa-f]{2})', { param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16) })
      return $text
    }
    default { return $Encoded }
  }
}

function Get-RoninMimeFilename {
  [CmdletBinding()]
  param([string]$ContentDisposition, [string]$ContentType)
  # Try quoted value first (handles spaces in filenames), then unquoted
  $m = [regex]::Match($ContentDisposition, '(?i)filename\s*=\s*"([^"]+)"')
  if ($m.Success) { return $m.Groups[1].Value }
  $m = [regex]::Match($ContentDisposition, '(?i)filename\s*=\s*([^\s;]+)')
  if ($m.Success) { return $m.Groups[1].Value }
  $m = [regex]::Match($ContentType, '(?i)name\s*=\s*"([^"]+)"')
  if ($m.Success) { return $m.Groups[1].Value }
  $m = [regex]::Match($ContentType, '(?i)name\s*=\s*([^\s;]+)')
  if ($m.Success) { return $m.Groups[1].Value }
  return $null
}

# ── Header parsing ───────────────────────────────────────────────────────────

function Get-RoninHeaderValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$RawHeaders,
    [Parameter(Mandatory=$true)][string]$Name
  )
  # Handle folded headers (RFC 5322): lines starting with whitespace are continuations
  $normalized = ($RawHeaders -replace "(\r?\n)[\t ]+", " ")
  $pattern = "(?im)^\s*{0}\s*:\s*(.+)$" -f [regex]::Escape($Name)
  $m = [regex]::Match($normalized, $pattern)
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ""
}

function Get-RoninConfig {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$Path)
  if (!(Test-Path $Path)) { throw "Config not found: $Path" }
  $json = Get-Content -Raw -Path $Path | ConvertFrom-Json
  return $json
}

# ── Header analysis engine ───────────────────────────────────────────────────

function Invoke-RoninHeaders {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][object]$Config,
    [switch]$Offline,
    [switch]$Strict
  )

  if (-not $Evidence.Raw.Headers) {
    if ($Strict) { throw "No headers present. Provide -Eml or -HeadersFile." }
    $Evidence.Auth.Notes += "No headers provided."
    return $Evidence
  }

  $raw = $Evidence.Raw.Headers
  $Evidence.Auth.AuthResultsRaw = @()

  # Collect Authentication-Results lines (may be multiple)
  $norm = ($raw -replace "(\r?\n)[\t ]+", " ")
  $authLines = [regex]::Matches($norm, "(?im)^\s*Authentication-Results\s*:\s*(.+)$")
  foreach ($m in $authLines) { $Evidence.Auth.AuthResultsRaw += $m.Groups[1].Value.Trim() }

  # Basic SPF/DKIM/DMARC extraction (best-effort)
  $ar = ($Evidence.Auth.AuthResultsRaw -join " ")
  if ($ar) {
    $Evidence.Auth.Spf   = (Get-RoninAuthToken -Text $ar -Token 'spf')
    $Evidence.Auth.Dkim  = (Get-RoninAuthToken -Text $ar -Token 'dkim')
    $Evidence.Auth.Dmarc = (Get-RoninAuthToken -Text $ar -Token 'dmarc')
    $Evidence.Auth.Align = (Get-RoninAuthToken -Text $ar -Token 'dmarc')
  } else {
    $Evidence.Auth.Notes += "No Authentication-Results header found."
  }

  # Received chain
  $receivedMatches = [regex]::Matches($norm, "(?im)^\s*Received\s*:\s*(.+)$")
  $hops = @()
  foreach ($m in $receivedMatches) {
    $line = $m.Groups[1].Value.Trim()
    $hop = [PSCustomObject]@{
      Raw     = $line
      From    = (Get-RoninReceivedPart -Line $line -Key 'from')
      By      = (Get-RoninReceivedPart -Line $line -Key 'by')
      With    = (Get-RoninReceivedPart -Line $line -Key 'with')
      Id      = (Get-RoninReceivedPart -Line $line -Key 'id')
      For     = (Get-RoninReceivedFor  -Line $line)
      Date    = (Get-RoninReceivedDate -Line $line)
      Ips     = (Get-RoninExtractIps   -Text $line)
      Domains = (Get-RoninExtractDomains -Text $line)
    }
    $hops += $hop
  }
  $Evidence.Received.Hops = $hops

  # Origin heuristic
  if ($hops.Count -gt 0) {
    $last = $hops[-1]
    if (@($last.Ips).Count -gt 0) { $Evidence.Received.OriginIp = $last.Ips[0] }
    if ($last.From) { $Evidence.Received.OriginHost = $last.From }
  }

  # Extract URLs/domains/IPs from headers
  $Evidence.Urls       = @(Get-RoninExtractUrls    -Text $raw | Select-Object -Unique)
  $Evidence.Domains    = @(Get-RoninExtractDomains  -Text $raw | Select-Object -Unique)
  $Evidence.Iocs.Ips   = @(Get-RoninExtractIps     -Text $raw | Select-Object -Unique)

  # Also extract URLs/domains from body text if available
  if ($Evidence.Raw.BodyText) {
    $Evidence.Iocs.Urls    += @(Get-RoninExtractUrls    -Text $Evidence.Raw.BodyText | Select-Object -Unique)
    $Evidence.Iocs.Domains += @(Get-RoninExtractDomains -Text $Evidence.Raw.BodyText | Select-Object -Unique)
  }
  if ($Evidence.Raw.BodyHtml) {
    $Evidence.Iocs.Urls    += @(Get-RoninExtractUrls    -Text $Evidence.Raw.BodyHtml | Select-Object -Unique)
    $Evidence.Iocs.Domains += @(Get-RoninExtractDomains -Text $Evidence.Raw.BodyHtml | Select-Object -Unique)
  }

  if ($Strict) {
    if ($Evidence.Auth.Spf -eq 'unknown' -and $Evidence.Auth.Dkim -eq 'unknown' -and $Evidence.Auth.Dmarc -eq 'unknown') {
      throw "Strict mode: no SPF/DKIM/DMARC evidence found."
    }
  }

  return $Evidence
}

# ── Auth / Received helpers ──────────────────────────────────────────────────

function Get-RoninAuthToken {
  param([string]$Text, [string]$Token)
  $m = [regex]::Match($Text, "(?i)\b$Token\s*=\s*([a-z]+)")
  if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
  return "unknown"
}

function Get-RoninReceivedPart {
  param([string]$Line, [string]$Key)
  $m = [regex]::Match($Line, "(?i)\b{0}\s+([^;]+)" -f [regex]::Escape($Key))
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ""
}

function Get-RoninReceivedFor {
  param([string]$Line)
  $m = [regex]::Match($Line, "(?i)\bfor\s+([^;]+)")
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ""
}

function Get-RoninReceivedDate {
  param([string]$Line)
  $m = [regex]::Match($Line, ";\s*(.+)$")
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ""
}

# ── IOC extraction helpers ───────────────────────────────────────────────────

function Get-RoninExtractIps {
  param([string]$Text)
  $ips = [regex]::Matches($Text, "(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)") | ForEach-Object { $_.Value }
  return ,$ips
}

function Get-RoninExtractUrls {
  param([string]$Text)
  $urls = [regex]::Matches($Text, "(?i)\bhttps?://[^\s<>\]`"']+") | ForEach-Object { $_.Value.TrimEnd(')','.',';',',') }
  return ,$urls
}

function Get-RoninExtractDomains {
  param([string]$Text)
  $domains = [regex]::Matches($Text, "(?i)\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b") | ForEach-Object { $_.Value.ToLowerInvariant() }
  return ,$domains
}

# ── Display ──────────────────────────────────────────────────────────────────

function Show-RoninHeaders {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  "=== RoninHeaders ==="
  "From:    {0}" -f $Evidence.Message.From
  if (@($Evidence.Message.To).Count -gt 0) { "To:      {0}" -f ($Evidence.Message.To -join ', ') }
  if (@($Evidence.Message.Cc).Count -gt 0) { "Cc:      {0}" -f ($Evidence.Message.Cc -join ', ') }
  "Subject: {0}" -f $Evidence.Message.Subject
  "MsgId:   {0}" -f $Evidence.Message.MessageId
  ""
  if ($Evidence.Raw.IsEmptyHtmlBody -or $Evidence.Raw.IsEmptyTextBody) {
    "Body Status:"
    "  HTML body empty:  {0}" -f $Evidence.Raw.IsEmptyHtmlBody
    "  Text body empty:  {0}" -f $Evidence.Raw.IsEmptyTextBody
    ""
  }
  if ($Evidence.Raw.MimeBoundaries.Count -gt 0) {
    "MIME Boundaries: {0}" -f $Evidence.Raw.MimeBoundaries.Count
    foreach ($b in $Evidence.Raw.MimeBoundaries) { "  $b" }
    ""
  }
  "Auth:"
  "  SPF:   {0}" -f $Evidence.Auth.Spf
  "  DKIM:  {0}" -f $Evidence.Auth.Dkim
  "  DMARC: {0}" -f $Evidence.Auth.Dmarc
  ""
  "Received hops: {0}" -f $Evidence.Received.Hops.Count
  foreach ($h in $Evidence.Received.Hops) {
    "- from: {0} | by: {1} | date: {2}" -f $h.From, $h.By, $h.Date
  }
  ""
  # Show extracted attachments if any
  if ($Evidence.Raw.ExtractedAttachments) {
    "Extracted attachments: {0}" -f $Evidence.Raw.ExtractedAttachments.Count
    foreach ($a in $Evidence.Raw.ExtractedAttachments) {
      "  - {0} ({1:N0} bytes) -> {2}" -f $a.Filename, $a.Size, $a.Path
    }
  }
}

Export-ModuleMember -Function `
  New-RoninEvidence, Import-RoninEml, Get-RoninHeaderValue, Get-RoninConfig, `
  Invoke-RoninHeaders, Show-RoninHeaders
