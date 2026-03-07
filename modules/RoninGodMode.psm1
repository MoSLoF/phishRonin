Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
  RoninGodMode - Bridge between phishRonin and OSINT-GodMode phone intelligence framework.

.DESCRIPTION
  Extracts phone numbers from phishing evidence (body text, QR payloads, DOCX content,
  email signatures) and runs them through OSINT-GodMode for carrier intel, reputation
  scoring, social media discovery, and breach detection.

  Requires: Python 3.8+ and OSINT-GodMode installed at the configured path.
#>

# Default path to OSINT-GodMode installation
$script:DefaultGodModePath = 'H:\Development\Repos\OSINT-GodMode'

# Phone number regex patterns (E.164, US, international with various separators)
$script:PhonePatterns = @(
  # E.164 format: +1234567890
  '\+\d{10,15}'
  # US format: (123) 456-7890, 123-456-7890, 123.456.7890
  '\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}'
  # International with country code: +1 (123) 456-7890, +44 20 7946 0958
  '\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{0,4}'
  # Toll-free: 1-800-123-4567
  '1[\-.]?8[0-9]{2}[\-.]?\d{3}[\-.]?\d{4}'
)

# ── Main entry point ─────────────────────────────────────────────────────────

function Invoke-RoninGodMode {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [string]$GodModePath   = $script:DefaultGodModePath,
    [string]$PythonPath    = 'python',
    [ValidateSet('quick','standard','comprehensive')]
    [string]$Depth         = 'quick',
    [string[]]$Categories  = @('phone_intel','reputation','carrier'),
    [switch]$IncludeBreach,
    [int]$TimeoutSeconds   = 120
  )

  $results = [PSCustomObject]@{
    PhoneNumbers      = @()
    Investigations    = @()
    Summary           = ''
    ExtractedFrom     = @()
    TotalFound        = 0
    TotalInvestigated = 0
    Errors            = @()
  }

  # ── Validate OSINT-GodMode installation ───────────────────────────────────

  $mainPy = Join-Path $GodModePath 'main.py'
  if (-not (Test-Path $mainPy)) {
    $msg = "OSINT-GodMode not found at: $GodModePath"
    Write-Host "[RoninGodMode] $msg" -ForegroundColor Yellow
    $results.Errors += $msg
    $results.Summary = "GodMode: not available ($msg)"
    $Evidence | Add-Member -NotePropertyName 'GodMode' -NotePropertyValue $results -Force
    return $Evidence
  }

  # ── Extract phone numbers from evidence ───────────────────────────────────

  $phones = [System.Collections.Generic.List[PSCustomObject]]::new()

  # From email body text
  if ($Evidence.Raw.BodyText) {
    $found = Find-PhoneNumbers -Text $Evidence.Raw.BodyText -Source 'email-body-text'
    foreach ($p in $found) { $phones.Add($p) }
  }

  # From email HTML body (strip tags first)
  if ($Evidence.Raw.BodyHtml) {
    $stripped = $Evidence.Raw.BodyHtml -replace '<[^>]+>', ' '
    $found = Find-PhoneNumbers -Text $stripped -Source 'email-body-html'
    foreach ($p in $found) { $phones.Add($p) }
  }

  # From QR code payloads
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'image' -and $a.Findings.HasQrCode) {
      $found = Find-PhoneNumbers -Text $a.Findings.QrPayload -Source "qr-payload:$([IO.Path]::GetFileName($a.Path))"
      foreach ($p in $found) { $phones.Add($p) }
    }
    if ($a.Type -eq 'docx' -and $a.Findings.ContainsKey('QrCodesFound')) {
      foreach ($img in $a.Findings.Images) {
        if ($img.HasQR -and $img.QrPayload) {
          $found = Find-PhoneNumbers -Text $img.QrPayload -Source "qr-in-docx:$($img.Name)"
          foreach ($p in $found) { $phones.Add($p) }
        }
      }
    }
  }

  # From DOCX document text
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'docx' -and $a.Findings.ContainsKey('DocumentText')) {
      $found = Find-PhoneNumbers -Text $a.Findings.DocumentText -Source "docx-text:$([IO.Path]::GetFileName($a.Path))"
      foreach ($p in $found) { $phones.Add($p) }
    }
  }

  # NOTE: We intentionally skip raw email headers for phone extraction.
  # Headers contain too many numeric false positives (MIME boundaries, IP addresses,
  # message IDs, server version strings, timestamps) that match phone patterns.

  # Deduplicate by normalized number
  $uniquePhones = @{}
  foreach ($p in $phones) {
    $norm = Normalize-PhoneNumber $p.Raw
    if ($norm -and -not $uniquePhones.ContainsKey($norm)) {
      $uniquePhones[$norm] = [PSCustomObject]@{
        Raw        = $p.Raw
        Normalized = $norm
        Source     = $p.Source
      }
    }
  }

  $results.PhoneNumbers = @($uniquePhones.Values)
  $results.TotalFound = $uniquePhones.Count
  $results.ExtractedFrom = @($uniquePhones.Values | ForEach-Object { $_.Source } | Select-Object -Unique)

  if ($uniquePhones.Count -eq 0) {
    Write-Host "[RoninGodMode] No phone numbers found in evidence"
    $results.Summary = "GodMode: 0 phone numbers found"
    $Evidence | Add-Member -NotePropertyName 'GodMode' -NotePropertyValue $results -Force
    return $Evidence
  }

  Write-Host "[RoninGodMode] Found $($uniquePhones.Count) unique phone number(s): $($uniquePhones.Keys -join ', ')"

  # ── Run OSINT-GodMode for each phone number ──────────────────────────────

  foreach ($phone in $uniquePhones.Values) {
    Write-Host "[RoninGodMode] Investigating: $($phone.Normalized) (from $($phone.Source))"

    $investigation = Invoke-GodModeQuery `
      -PhoneNumber $phone.Normalized `
      -GodModePath $GodModePath `
      -PythonPath $PythonPath `
      -Depth $Depth `
      -Categories $Categories `
      -IncludeBreach:$IncludeBreach `
      -TimeoutSeconds $TimeoutSeconds

    if ($investigation.Success) {
      $results.TotalInvestigated++

      $investigation | Add-Member -NotePropertyName 'PhoneNumber' -NotePropertyValue $phone.Normalized -Force
      $investigation | Add-Member -NotePropertyName 'Source' -NotePropertyValue $phone.Source -Force
      $results.Investigations += $investigation

      # Display key findings
      $rep = $investigation.Data.reputation
      if ($rep) {
        $spamScore = if ($rep.spam_score) { $rep.spam_score } else { 'N/A' }
        $fraudRisk = if ($rep.fraud_risk) { $rep.fraud_risk } else { 'unknown' }
        Write-Host "[RoninGodMode]   Spam: $spamScore/10  |  Fraud risk: $fraudRisk"
        if ($rep.is_scam) { Write-Host "[RoninGodMode]   [!] SCAM NUMBER DETECTED" -ForegroundColor Red }
      }

      $carrier = $investigation.Data.carrier_info
      if ($carrier -and $carrier.carrier) {
        $lineType = if ($carrier.line_type) { $carrier.line_type } else { 'unknown' }
        Write-Host "[RoninGodMode]   Carrier: $($carrier.carrier) ($lineType)"
      }

      $social = $investigation.Data.social_media
      if ($social -and $social.total_found -gt 0) {
        Write-Host "[RoninGodMode]   Social profiles: $($social.total_found) found"
      }

      $breach = $investigation.Data.breach_data
      if ($breach -and $breach.found_in_breaches) {
        Write-Host "[RoninGodMode]   [!] Found in $($breach.breach_count) data breach(es)" -ForegroundColor Yellow
      }
    } else {
      $results.Errors += "Failed to investigate $($phone.Normalized): $($investigation.Error)"
      Write-Host "[RoninGodMode]   Investigation failed: $($investigation.Error)" -ForegroundColor Yellow
    }
  }

  # ── Summary ────────────────────────────────────────────────────────────────

  $scamCount = @($results.Investigations | Where-Object {
    $_.Data -and $_.Data.reputation -and $_.Data.reputation.is_scam
  }).Count
  $voipCount = @($results.Investigations | Where-Object {
    $_.Data -and $_.Data.carrier_info -and $_.Data.carrier_info.line_type -match '(?i)voip'
  }).Count
  $breachCount = @($results.Investigations | Where-Object {
    $_.Data -and $_.Data.breach_data -and $_.Data.breach_data.found_in_breaches
  }).Count

  $results.Summary = "GodMode: {0} phone(s), {1} investigated, {2} scam, {3} VoIP, {4} breached" -f `
    $results.TotalFound, $results.TotalInvestigated, $scamCount, $voipCount, $breachCount

  Write-Host "[RoninGodMode] $($results.Summary)"

  $Evidence | Add-Member -NotePropertyName 'GodMode' -NotePropertyValue $results -Force
  return $Evidence
}

# ── GodMode execution helper ────────────────────────────────────────────────

function Invoke-GodModeQuery {
  [CmdletBinding()]
  param(
    [string]$PhoneNumber,
    [string]$GodModePath,
    [string]$PythonPath,
    [string]$Depth,
    [string[]]$Categories,
    [switch]$IncludeBreach,
    [int]$TimeoutSeconds
  )

  $result = [PSCustomObject]@{
    Success      = $false
    Data         = $null
    Error        = ''
    Duration     = 0
    ToolsUsed    = 0
    SuccessRate  = 0
  }

  $mainPy = Join-Path $GodModePath 'main.py'

  # Build argument list
  $args = @(
    $mainPy
    $PhoneNumber
    '--depth', $Depth
    '--categories'
  )
  $args += $Categories
  $args += '--json-output'
  $args += '--no-report'
  $args += '--quiet'

  if (-not $IncludeBreach) {
    $args += '--no-breach'
  }

  try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $procInfo = New-Object System.Diagnostics.ProcessStartInfo
    $procInfo.FileName = $PythonPath
    $procInfo.Arguments = ($args | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $procInfo.WorkingDirectory = $GodModePath
    $procInfo.RedirectStandardOutput = $true
    $procInfo.RedirectStandardError = $true
    $procInfo.UseShellExecute = $false
    $procInfo.CreateNoWindow = $true

    # Set PYTHONPATH to include the GodMode directory
    $procInfo.EnvironmentVariables['PYTHONPATH'] = $GodModePath

    $proc = [System.Diagnostics.Process]::Start($procInfo)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $completed = $proc.WaitForExit($TimeoutSeconds * 1000)

    $sw.Stop()
    $result.Duration = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    if (-not $completed) {
      try { $proc.Kill() } catch { }
      $result.Error = "Timed out after ${TimeoutSeconds}s"
      return $result
    }

    if ($proc.ExitCode -ne 0) {
      $result.Error = "Exit code $($proc.ExitCode): $stderr"
      return $result
    }

    # Parse JSON output
    if ($stdout) {
      $jsonData = $stdout | ConvertFrom-Json
      $result.Data = $jsonData
      $result.Success = $true

      # Extract stats if available
      $stats = $jsonData.statistics
      if ($stats) {
        $result.ToolsUsed = if ($stats.total_tools) { $stats.total_tools } else { 0 }
        $result.SuccessRate = if ($stats.success_rate) { $stats.success_rate } else { 0 }
      }
    } else {
      $result.Error = 'No output from GodMode'
    }
  }
  catch {
    $result.Error = $_.Exception.Message
  }

  return $result
}

# ── Phone number extraction ─────────────────────────────────────────────────

function Find-PhoneNumbers {
  [CmdletBinding()]
  param(
    [string]$Text,
    [string]$Source
  )

  if (-not $Text) { return @() }

  $found = [System.Collections.Generic.List[PSCustomObject]]::new()
  $seen = @{}

  foreach ($pattern in $script:PhonePatterns) {
    $matches = [regex]::Matches($Text, $pattern)
    foreach ($m in $matches) {
      $raw = $m.Value.Trim()
      # Skip very short matches (likely false positives like dates)
      $digitsOnly = $raw -replace '[^\d]', ''
      if ($digitsOnly.Length -lt 7 -or $digitsOnly.Length -gt 15) { continue }

      # Skip common false positives (years, zip codes in context)
      if ($raw -match '^\d{4}$') { continue }
      if ($raw -match '^(19|20)\d{2}$') { continue }

      # Skip IP address octets (e.g., 10.167.242.105 matching as phone)
      if ($raw -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { continue }

      # Skip matches embedded in longer digit runs (MIME boundaries, message IDs)
      $preIdx  = $m.Index - 1
      $postIdx = $m.Index + $m.Length
      if ($preIdx -ge 0 -and $Text[$preIdx] -match '\d') { continue }
      if ($postIdx -lt $Text.Length -and $Text[$postIdx] -match '\d') { continue }

      # Skip if surrounded by = signs (MIME boundary fragments)
      if ($preIdx -ge 0 -and $Text[$preIdx] -eq '=') { continue }
      if ($postIdx -lt $Text.Length -and $Text[$postIdx] -eq '=') { continue }

      if (-not $seen.ContainsKey($digitsOnly)) {
        $seen[$digitsOnly] = $true
        $found.Add([PSCustomObject]@{
          Raw    = $raw
          Source = $Source
        })
      }
    }
  }

  return @($found)
}

function Normalize-PhoneNumber {
  param([string]$Raw)
  if (-not $Raw) { return '' }

  # Strip all non-digit characters except leading +
  $hasPlus = $Raw.StartsWith('+')
  $digits = $Raw -replace '[^\d]', ''

  if ($digits.Length -lt 7 -or $digits.Length -gt 15) { return '' }

  # If starts with +, keep E.164 format
  if ($hasPlus) { return "+$digits" }

  # If 10 digits, assume US and prepend +1
  if ($digits.Length -eq 10) { return "+1$digits" }

  # If 11 digits starting with 1, assume US
  if ($digits.Length -eq 11 -and $digits.StartsWith('1')) { return "+$digits" }

  # Otherwise, return with + prefix
  return "+$digits"
}

# ── Display ─────────────────────────────────────────────────────────────────

function Show-RoninGodMode {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  if (-not ($Evidence.PSObject.Properties.Name -contains 'GodMode')) {
    "No GodMode data available."
    return
  }

  $gm = $Evidence.GodMode
  "=== RoninGodMode (OSINT-GodMode Integration) ==="
  $gm.Summary
  ""

  if ($gm.TotalFound -gt 0) {
    "Phone numbers extracted:"
    foreach ($p in $gm.PhoneNumbers) {
      "  {0} (from {1})" -f $p.Normalized, $p.Source
    }
    ""
  }

  foreach ($inv in $gm.Investigations) {
    "Investigation: {0} ({1}s, {2} tools)" -f $inv.PhoneNumber, $inv.Duration, $inv.ToolsUsed
    ""

    if ($inv.Data.reputation) {
      $rep = $inv.Data.reputation
      "  Reputation:"
      "    Spam score:  {0}/10" -f $(if($rep.spam_score){$rep.spam_score}else{'N/A'})
      "    Fraud risk:  {0}" -f $(if($rep.fraud_risk){$rep.fraud_risk}else{'unknown'})
      if ($rep.is_scam) { "    [!] SCAM NUMBER" }
      ""
    }

    if ($inv.Data.carrier_info -and $inv.Data.carrier_info.carrier) {
      $c = $inv.Data.carrier_info
      "  Carrier:"
      "    Name:      {0}" -f $c.carrier
      "    Line type: {0}" -f $(if($c.line_type){$c.line_type}else{'unknown'})
      "    Country:   {0}" -f $(if($c.country){$c.country}else{'N/A'})
      ""
    }

    if ($inv.Data.social_media -and $inv.Data.social_media.total_found -gt 0) {
      $s = $inv.Data.social_media
      "  Social Media: {0} profile(s)" -f $s.total_found
      if ($s.platforms) {
        $s.platforms.PSObject.Properties | ForEach-Object {
          "    - {0}" -f $_.Name
        }
      }
      ""
    }

    if ($inv.Data.breach_data -and $inv.Data.breach_data.found_in_breaches) {
      $b = $inv.Data.breach_data
      "  [!] Breach Data: found in {0} breach(es)" -f $b.breach_count
      ""
    }

    if ($inv.Data.identity -and $inv.Data.identity.names) {
      "  Identity:"
      foreach ($n in $inv.Data.identity.names) {
        "    {0} (confidence: {1:P0})" -f $n.name, $n.confidence
      }
      ""
    }
  }

  if ($gm.Errors.Count -gt 0) {
    "Errors:"
    foreach ($e in $gm.Errors) { "  $e" }
  }
}

Export-ModuleMember -Function Invoke-RoninGodMode, Show-RoninGodMode
