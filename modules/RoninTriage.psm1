Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-RoninTriage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][object]$Config
  )

  $score = 0
  $reasons = New-Object System.Collections.Generic.List[string]

  # ── 1. Authentication Signals ──────────────────────────────────────────────
  switch ($Evidence.Auth.Dmarc) {
    'fail' { $score += 30; $reasons.Add("DMARC fail (+30)") }
    'pass' { $score -= 5;  $reasons.Add("DMARC pass (-5)") }
    default { $reasons.Add("DMARC unknown (+0)") }
  }
  switch ($Evidence.Auth.Dkim) {
    'fail' { $score += 15; $reasons.Add("DKIM fail (+15)") }
    'pass' { $score -= 3;  $reasons.Add("DKIM pass (-3)") }
  }
  switch ($Evidence.Auth.Spf) {
    'fail' { $score += 15; $reasons.Add("SPF fail (+15)") }
    'pass' { $score -= 3;  $reasons.Add("SPF pass (-3)") }
  }

  # Reply-To mismatch heuristic
  if ($Evidence.Message.ReplyTo -and $Evidence.Message.From) {
    $fromDomain = (Get-RoninDomainFromAddress $Evidence.Message.From)
    $rtDomain   = (Get-RoninDomainFromAddress $Evidence.Message.ReplyTo)
    if ($fromDomain -and $rtDomain -and ($fromDomain -ne $rtDomain)) {
      $score += 20
      $reasons.Add("Reply-To domain differs from From (+20)")
    }
  }

  # ── 2. Subject Lure Keywords ───────────────────────────────────────────────
  $subject = if ($Evidence.Message.Subject) { $Evidence.Message.Subject } else { "" }
  $lureWords = @("layoff","lay-off","termination","severance","hr","urgent","payroll","meeting","review","suspend","locked","verify")
  foreach ($w in $lureWords) {
    if ($subject.ToLowerInvariant().Contains($w)) {
      $score += 5
      $reasons.Add("Subject contains '$w' (+5)")
    }
  }

  # ── 3. DOCX Attachment Signals ─────────────────────────────────────────────
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'docx') {
      if ($a.Findings.ExternalRelationships -gt 0) {
        $score += 25
        $reasons.Add("DOCX has external relationships (+25)")
      }
      if ($a.Findings.EmbeddedObjects -gt 0) {
        $score += 20
        $reasons.Add("DOCX contains embedded objects (+20)")
      }
      if ($a.Findings.SuspiciousUrls -gt 0) {
        $score += 15
        $reasons.Add("DOCX contains payload URLs (+15)")
      }

      # -- QR code signals (quishing) --
      if ($a.Findings.ContainsKey('QrCodesFound')) {
        if ($a.Findings.QrCodesFound -gt 0) {
          $score += 25
          $reasons.Add("QR code found in DOCX image (+25)")
        }
        if ($a.Findings.QrCodesFound -gt 1) {
          $score += 5
          $reasons.Add("Multiple QR codes in document (+5)")
        }
      }

      # -- Zeroed metadata --
      if ($a.Findings.ContainsKey('MetadataZeroed')) {
        if ($a.Findings.MetadataZeroed) {
          $score += 10
          $reasons.Add("DOCX metadata zeroed (Pages=0, Words=0) -- deliberately sanitized (+10)")
        }
      }

      # -- ZIP overlay --
      if ($a.Findings.ContainsKey('ZipStructure')) {
        if ($a.Findings.ZipStructure -and $a.Findings.ZipStructure.OverlayBytes -gt 0) {
          $score += 15
          $reasons.Add("ZIP overlay: $($a.Findings.ZipStructure.OverlayBytes) bytes after expected end (+15)")
        }
      }

      # -- Tracking pixels --
      if ($a.Findings.ContainsKey('TrackingPixels')) {
        if ($a.Findings.TrackingPixels.Count -gt 0) {
          $score += 10
          $reasons.Add("DOCX has $($a.Findings.TrackingPixels.Count) external image ref(s) / tracking pixel(s) (+10)")
        }
      }

      # -- Lure keywords in document text --
      if ($a.Findings.ContainsKey('LureKeywords')) {
        if ($a.Findings.LureKeywords.Count -gt 0) {
          $categories = @($a.Findings.LureKeywords | ForEach-Object { $_.Category } | Select-Object -Unique)
          $score += 5
          $reasons.Add("Doc text contains lure keywords [$($categories -join ', ')] (+5)")
        }
      }
    }

    # ── 4. Image / QR Code Signals ─────────────────────────────────────────
    if ($a.Type -eq 'image') {
      $f = $a.Findings

      # QR code URL payload
      if ($f.HasQrCode -and $f.QrPayloadType -eq 'url') {
        $score += 10
        $reasons.Add("QR code payload is a URL (+10)")
      }

      # QR domain mismatch
      if ($f.QrDomainMismatch) {
        $score += 10
        $reasons.Add("QR URL domain differs from sender domain (+10)")
      }

      # Valid PE embedded in image (CRITICAL)
      $validPe = @($f.MzSignatures | Where-Object { $_.IsValidPE })
      if ($validPe.Count -gt 0) {
        $score += 30
        $reasons.Add("CRITICAL: Valid PE executable embedded in image (+30)")
      }

      # Trailing data (steganography)
      if ($f.HasTrailingData) {
        $score += 20
        $reasons.Add("Image has $($f.TrailingDataBytes) bytes trailing data (magic: $($f.TrailingDataMagic)) (+20)")
      }

      # Suspicious PNG text chunks
      if ($f.SuspiciousPngChunks.Count -gt 0) {
        $score += 10
        $reasons.Add("PNG has $($f.SuspiciousPngChunks.Count) suspicious text chunk(s) (+10)")
      }

      # Malware strings in binary
      if ($f.MalwareStrings.Count -gt 0) {
        $score += 25
        $reasons.Add("Known malware signature(s) in image binary: $($f.MalwareStrings.Count) hit(s) (+25)")
      }

      # Script execution patterns
      if ($f.ScriptPatterns.Count -gt 0) {
        $score += 20
        $reasons.Add("Script execution pattern(s) in image binary: $($f.ScriptPatterns.Count) hit(s) (+20)")
      }
    }
  }

  # ── 5. MIME Forensics Signals ──────────────────────────────────────────────
  if ($Evidence.PSObject.Properties.Name -contains 'MimeForensics') {
    $mf = $Evidence.MimeForensics

    # Empty body evasion
    if ($mf.IsBodylessEmail) {
      $score += 15
      $reasons.Add("Bodyless email: both HTML and text empty (evasion) (+15)")
    } elseif ($mf.IsEmptyHtmlBody -and -not $mf.IsEmptyTextBody) {
      $score += 10
      $reasons.Add("HTML body declared but empty (scanner evasion) (+10)")
    }

    # Attachment-only delivery
    if ($mf.AttachmentOnlyDelivery) {
      $score += 10
      $reasons.Add("Attachment-only delivery: payload isolated from body scanners (+10)")
    }

    # Image-only HTML body
    if ($mf.HasImageOnlyBody) {
      $score += 10
      $reasons.Add("HTML body contains only image tags -- no text content (+10)")
    }

    # MIME boundary fingerprint (phishing kit)
    foreach ($bf in $mf.BoundaryFingerprints) {
      if ($bf.Classification -notin @('standard','exchange')) {
        $score += 10
        $reasons.Add("MIME boundary fingerprint: '$($bf.Classification)' (phishing kit indicator) (+10)")
        break  # only score once
      }
    }

    # Hidden data after MIME boundary
    if ($mf.HiddenDataAfterBoundary) {
      $score += 15
      $reasons.Add("Hidden data after MIME boundary: $($mf.HiddenDataBytes) bytes (content stuffing) (+15)")
    }

    # Self-addressed / intra-domain spoofing
    if ($mf.SelfAddressed) {
      $score += 10
      $reasons.Add("Self-addressed or intra-domain spoofing detected (+10)")
    }

    # HTML body findings (scripts, iframes, forms)
    if ($mf.HtmlFindings.Count -gt 0) {
      foreach ($hf in $mf.HtmlFindings) {
        if ($hf -match 'script') {
          $score += 15
          $reasons.Add("HTML body contains script tag(s) (+15)")
          break
        }
      }
      foreach ($hf in $mf.HtmlFindings) {
        if ($hf -match 'iframe') {
          $score += 10
          $reasons.Add("HTML body contains iframe(s) (+10)")
          break
        }
      }
      foreach ($hf in $mf.HtmlFindings) {
        if ($hf -match 'form action') {
          $score += 10
          $reasons.Add("HTML body contains form with external action (+10)")
          break
        }
      }
      foreach ($hf in $mf.HtmlFindings) {
        if ($hf -match 'javascript:') {
          $score += 10
          $reasons.Add("HTML body contains javascript: links (+10)")
          break
        }
      }
    }

    # Compauth failure (confirmed spoofing)
    if ($mf.Compauth.Result -and $mf.Compauth.Reason -match '^0') {
      $score += 15
      $reasons.Add("EOP compauth failure (reason=$($mf.Compauth.Reason)): confirmed spoofing (+15)")
    }

    # Exchange AuthAs=Anonymous
    foreach ($finding in $mf.Findings) {
      if ($finding -match 'AuthAs=Anonymous') {
        $score += 5
        $reasons.Add("Exchange AuthAs=Anonymous (unauthenticated sender) (+5)")
        break
      }
    }
  }

  # ── 6. Received Chain Heuristic ────────────────────────────────────────────
  if ($Evidence.Received.Hops.Count -gt 0) {
    $firstBy = $Evidence.Received.Hops[0].By
    if ($firstBy -and ($firstBy -notmatch "(?i)microsoft|outlook|protection\.outlook\.com|prod\.outlook|hotmail")) {
      $score += 10
      $reasons.Add("Top Received hop 'by' not clearly Microsoft (+10)")
    }
  }

  # ── 7. OSINT-Derived Signals ───────────────────────────────────────────────
  if ($Evidence.Osint -and @($Evidence.Osint.IpProfiles).Count -gt 0) {
    $originProfile = $Evidence.Osint.IpProfiles | Where-Object { $_.Ip -eq $Evidence.Received.OriginIp } | Select-Object -First 1
    if ($originProfile -and $originProfile.Classification.InfraType -ne 'private') {
      if ($originProfile.Classification.IsHosting -eq $true) {
        $score += 10
        $reasons.Add("Sender IP is classified as hosting/VPS infrastructure (+10)")
      }
      if ($originProfile.Classification.IsProxy -eq $true) {
        $score += 15
        $reasons.Add("Sender IP flagged as proxy/VPN (+15)")
      }
      if ($originProfile.AbuseIpDb.Score -gt 50) {
        $score += 15
        $reasons.Add("AbuseIPDB abuse confidence $($originProfile.AbuseIpDb.Score)% > 50% (+15)")
      }
      if ($originProfile.VirusTotal.Malicious -gt 0) {
        $vtMal = $originProfile.VirusTotal.Malicious
        $vtAdd = if ($vtMal -ge 5) { 15 } else { 10 }
        $score += $vtAdd
        $reasons.Add("VirusTotal: sender IP flagged malicious by $vtMal engine(s) (+$vtAdd)")
      }
      $expectedCountry = $Config.osint.expectedOrgCountryCode
      if ($expectedCountry -and $originProfile.Geolocation.CountryCode -and
          ($originProfile.Geolocation.CountryCode -ne $expectedCountry)) {
        $score += 5
        $reasons.Add("Sender IP country '$($originProfile.Geolocation.CountryCode)' differs from expected '$expectedCountry' (+5)")
      }
    }
    if ($Evidence.Osint.ThreatClassification.OverallType -eq 'bulletproof') {
      $score += 20
      $reasons.Add("Sender infrastructure classified as bulletproof hosting (+20)")
    }
  }

  # Domain age
  if ($Evidence.Osint -and @($Evidence.Osint.DomainProfiles).Count -gt 0) {
    foreach ($dp in $Evidence.Osint.DomainProfiles) {
      if ($dp.Whois.AgeInDays -ge 0 -and $dp.Whois.AgeInDays -lt 30) {
        $score += 10
        $reasons.Add("Domain '$($dp.Domain)' is only $($dp.Whois.AgeInDays) days old (<30) (+10)")
        break
      }
    }
  }

  # ── 8. OSINT-GodMode Phone Intelligence ──────────────────────────────────
  if ($Evidence.PSObject.Properties.Name -contains 'GodMode') {
    $gm = $Evidence.GodMode
    foreach ($inv in $gm.Investigations) {
      if (-not $inv.Success -or -not $inv.Data) { continue }

      # Scam phone number
      if ($inv.Data.reputation -and $inv.Data.reputation.is_scam) {
        $score += 15
        $reasons.Add("Phone $($inv.PhoneNumber) flagged as SCAM by GodMode (+15)")
      }
      # High spam score
      elseif ($inv.Data.reputation -and $inv.Data.reputation.spam_score -and $inv.Data.reputation.spam_score -gt 7) {
        $score += 10
        $reasons.Add("Phone $($inv.PhoneNumber) spam score $($inv.Data.reputation.spam_score)/10 (+10)")
      }

      # VoIP / burner line
      if ($inv.Data.carrier_info -and $inv.Data.carrier_info.line_type -match '(?i)voip') {
        $score += 10
        $reasons.Add("Phone $($inv.PhoneNumber) is VoIP/burner line ($($inv.Data.carrier_info.carrier)) (+10)")
      }

      # Found in breaches
      if ($inv.Data.breach_data -and $inv.Data.breach_data.found_in_breaches) {
        $score += 5
        $reasons.Add("Phone $($inv.PhoneNumber) found in $($inv.Data.breach_data.breach_count) data breach(es) (+5)")
      }
    }
  }

  # ── Clamp and Verdict ──────────────────────────────────────────────────────
  if ($score -lt 0) { $score = 0 }
  if ($score -gt 100) { $score = 100 }

  $verdict = "unknown"
  if ($score -ge $Config.scoring.maliciousThreshold) { $verdict = "malicious" }
  elseif ($score -ge $Config.scoring.suspiciousThreshold) { $verdict = "suspicious" }
  else { $verdict = "likely-benign" }

  $Evidence.Score.Total = $score
  $Evidence.Score.Verdict = $verdict
  $Evidence.Score.Reasons = $reasons.ToArray()

  # ── Suggested Actions ──────────────────────────────────────────────────────
  $suggested = New-Object System.Collections.Generic.List[string]

  if ($Evidence.Auth.Dmarc -eq 'fail') {
    $suggested.Add("Review/lock down DMARC/SPF/DKIM for sender domain")
  }

  if ($Evidence.Score.Verdict -in @('suspicious','malicious')) {
    $suggested.Add("Do not open attachments; isolate for analysis")
    $suggested.Add("Search org mailboxes for similar subject/sender")
    $suggested.Add("Quarantine message in M365 (RoninQuarantine)")
  }

  # Quishing-specific actions
  $hasQr = $false
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'image' -and $a.Findings.HasQrCode) { $hasQr = $true; break }
    if ($a.Type -eq 'docx' -and $a.Findings.ContainsKey('QrCodesFound') -and $a.Findings.QrCodesFound -gt 0) { $hasQr = $true; break }
  }
  if ($hasQr) {
    $suggested.Add("QR code detected -- decode and inspect target URL before any interaction")
    $suggested.Add("Block QR payload domain at web proxy / DNS filter")
    $suggested.Add("Alert SOC: quishing campaign -- QR code in DOCX attachment")
  }

  # Binary forensics actions
  foreach ($a in $Evidence.Attachments) {
    if ($a.Type -eq 'image') {
      $validPe = @($a.Findings.MzSignatures | Where-Object { $_.IsValidPE })
      if ($validPe.Count -gt 0) {
        $suggested.Add("CRITICAL: Embedded executable detected in image -- isolate immediately")
        $suggested.Add("Submit extracted PE to sandbox for dynamic analysis")
        $suggested.Add("Engage incident response: potential malware delivery")
        break
      }
      if ($a.Findings.MalwareStrings.Count -gt 0) {
        $suggested.Add("Known malware tool signatures found -- submit to sandbox")
        break
      }
    }
  }

  # MIME evasion actions
  if ($Evidence.PSObject.Properties.Name -contains 'MimeForensics') {
    $mf = $Evidence.MimeForensics
    $hasMimeEvasion = $mf.IsBodylessEmail -or $mf.AttachmentOnlyDelivery
    $hasKitFingerprint = @($mf.BoundaryFingerprints | Where-Object { $_.Classification -notin @('standard','exchange') }).Count -gt 0
    if ($hasMimeEvasion -or $hasKitFingerprint) {
      $suggested.Add("Email uses phishing kit delivery patterns (empty body + kit MIME boundaries)")
    }
    if ($Evidence.Auth.Dmarc -eq 'fail') {
      $suggested.Add("Review DMARC policy -- enforce p=reject to block sender spoofing")
    }
  }

  if ($Evidence.Osint -and $Evidence.Osint.ThreatClassification.OverallType -in @('bulletproof','tor')) {
    $suggested.Add("Block sender IP range at perimeter firewall")
  }
  if ($Evidence.Osint -and $Evidence.Osint.PivotLinks.Count -gt 0) {
    $suggested.Add("Review OSINT pivot links for deeper investigation")
  }

  $Evidence.Actions.Suggested = $suggested.ToArray()

  return $Evidence
}

function Get-RoninDomainFromAddress {
  param([string]$Addr)
  $m = [regex]::Match($Addr, "(?i)[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,63})")
  if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
  return ""
}

function Show-RoninTriage {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  "=== phishRonin Triage ==="
  $verdictUpper = $Evidence.Score.Verdict.ToUpper()
  "Verdict: {0} | Score: {1}/100" -f $verdictUpper, $Evidence.Score.Total
  ""
  "Reasons:"
  foreach ($r in $Evidence.Score.Reasons) { " - $r" }
  ""
  "Suggested actions:"
  foreach ($a in $Evidence.Actions.Suggested) { " - $a" }
}

function New-RoninHtmlReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][object]$Evidence,
    [Parameter(Mandatory=$true)][string]$TemplatePath,
    [Parameter(Mandatory=$true)][string]$OutPath
  )

  if (!(Test-Path $TemplatePath)) { throw "Template not found: $TemplatePath" }
  $tpl = Get-Content -Raw -Path $TemplatePath

  $json = $Evidence | ConvertTo-Json -Depth 12
  $safeJson = $json -replace "</", "<\/"

  $out = $tpl.Replace("{{EVIDENCE_JSON}}", $safeJson)

  $logoPath = Join-Path (Split-Path -Parent $TemplatePath) "logo_b64.txt"
  if ((Test-Path $logoPath) -and $out.Contains("{{LOGO_B64}}")) {
    $logoB64 = (Get-Content -Raw -Path $logoPath).Trim()
    $out = $out.Replace("{{LOGO_B64}}", $logoB64)
  }

  $dir = Split-Path -Parent $OutPath
  if ($dir -and !(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
  Set-Content -Path $OutPath -Value $out -Encoding UTF8
  return $OutPath
}

Export-ModuleMember -Function Invoke-RoninTriage, Show-RoninTriage, New-RoninHtmlReport
