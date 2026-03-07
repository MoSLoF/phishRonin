Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Known boundary patterns by toolkit ────────────────────────────────────────

$script:BoundaryPatterns = @(
  @{ Pattern = '^={15,}\d{18,22}={2}$';    Name = 'python-email' }
  @{ Pattern = '----=_Part_';              Name = 'php-mailer' }
  @{ Pattern = '----=_NextPart_';          Name = 'exchange' }
  @{ Pattern = '^[0-9a-f]{8}-[0-9a-f]{4}'; Name = 'guid-dotnet' }
  @{ Pattern = '_=_';                      Name = 'lotus-notes' }
)

# ── Main Entry Point ─────────────────────────────────────────────────────────

function Invoke-RoninMimeForensics {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  $result = @{
    BoundaryFingerprints    = @()
    IsEmptyHtmlBody         = $false
    IsEmptyTextBody         = $false
    IsBodylessEmail         = $false
    HasImageOnlyBody        = $false
    AttachmentOnlyDelivery  = $false
    HiddenDataAfterBoundary = $false
    HiddenDataBytes         = 0
    PreambleContent         = ''
    HtmlFindings            = @()
    Base64Blobs             = @()
    SelfAddressed           = $false
    EopScl                  = -2  # -2 = not parsed
    EopCategory             = ''
    EopSfv                  = ''
    EopAraRules             = @()
    Compauth                = @{ Result=''; Reason=''; Description='' }
    Findings                = New-Object System.Collections.Generic.List[string]
  }

  # ── 1. Boundary Fingerprinting ─────────────────────────────────────────
  $allBoundaries = @()
  if ($Evidence.Raw.Body) {
    $bMatches = [regex]::Matches($Evidence.Raw.Headers + "`n" + $Evidence.Raw.Body, '(?i)boundary\s*=\s*"?([^"\s;]+)"?')
    foreach ($bm in $bMatches) {
      $bVal = $bm.Groups[1].Value
      if ($allBoundaries -notcontains $bVal) { $allBoundaries += $bVal }
    }
  }

  foreach ($b in $allBoundaries) {
    $classification = 'standard'
    foreach ($bp in $script:BoundaryPatterns) {
      if ($b -match $bp.Pattern) {
        $classification = $bp.Name
        break
      }
    }
    $result.BoundaryFingerprints += [PSCustomObject]@{
      Boundary       = $b
      Classification = $classification
    }
    if ($classification -ne 'standard' -and $classification -ne 'exchange') {
      $result.Findings.Add("MIME boundary '$b' classified as '$classification' (potential phishing kit)")
    }
  }

  # ── 2. Empty Body Detection ────────────────────────────────────────────
  $htmlBody = ''
  $textBody = ''
  if ($Evidence.Raw.PSObject.Properties.Name -contains 'BodyHtml') { $htmlBody = $Evidence.Raw.BodyHtml }
  if ($Evidence.Raw.PSObject.Properties.Name -contains 'BodyText') { $textBody = $Evidence.Raw.BodyText }

  $result.IsEmptyHtmlBody = [string]::IsNullOrWhiteSpace($htmlBody)
  $result.IsEmptyTextBody = [string]::IsNullOrWhiteSpace($textBody)
  $result.IsBodylessEmail = $result.IsEmptyHtmlBody -and $result.IsEmptyTextBody

  if ($result.IsBodylessEmail) {
    $result.Findings.Add("Bodyless email: both HTML and text parts are empty (evasion technique)")
  }
  elseif ($result.IsEmptyHtmlBody -and -not $result.IsEmptyTextBody) {
    $result.Findings.Add("HTML body declared but empty (scanner evasion)")
  }

  # Check for image-only HTML body
  if (-not $result.IsEmptyHtmlBody -and $htmlBody) {
    $stripped = $htmlBody -replace '<img[^>]*>', '' -replace '<[^>]+>', '' -replace '\s+', ''
    if ([string]::IsNullOrWhiteSpace($stripped) -and $htmlBody -match '(?i)<img') {
      $result.HasImageOnlyBody = $true
      $result.Findings.Add("HTML body contains only image tag(s) -- no text content")
    }
  }

  # Attachment-only delivery
  $hasAttachments = $false
  if ($Evidence.Raw.PSObject.Properties.Name -contains 'ExtractedAttachments') {
    $hasAttachments = ($Evidence.Raw.ExtractedAttachments.Count -gt 0)
  }
  if (($result.IsBodylessEmail -or $result.IsEmptyHtmlBody) -and $hasAttachments) {
    $result.AttachmentOnlyDelivery = $true
    $result.Findings.Add("Attachment-only delivery: payload isolated from body scanners")
  }

  # ── 3. Hidden Data After MIME Boundary ─────────────────────────────────
  if ($Evidence.Raw.Body -and $allBoundaries.Count -gt 0) {
    $outerBoundary = $allBoundaries[0]
    $terminator = "--$outerBoundary--"
    $termIdx = $Evidence.Raw.Body.IndexOf($terminator)
    if ($termIdx -ge 0) {
      $afterTerm = $Evidence.Raw.Body.Substring($termIdx + $terminator.Length).Trim()
      if ($afterTerm.Length -gt 10) {
        $result.HiddenDataAfterBoundary = $true
        $result.HiddenDataBytes = $afterTerm.Length
        $result.Findings.Add("Hidden data after final MIME boundary: $($afterTerm.Length) bytes (content stuffing)")
      }
    }

    # Check preamble (content before first boundary)
    $firstBoundaryIdx = $Evidence.Raw.Body.IndexOf("--$outerBoundary")
    if ($firstBoundaryIdx -gt 0) {
      $preamble = $Evidence.Raw.Body.Substring(0, $firstBoundaryIdx).Trim()
      if ($preamble.Length -gt 10) {
        $result.PreambleContent = $preamble.Substring(0, [Math]::Min(200, $preamble.Length))
      }
    }
  }

  # ── 4. Self-Addressed Detection ────────────────────────────────────────
  if ($Evidence.Message.From -and $Evidence.Message.To) {
    $fromAddr = ''
    $toStr = ''
    $fm = [regex]::Match($Evidence.Message.From, '(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63})')
    if ($fm.Success) { $fromAddr = $fm.Groups[1].Value.ToLowerInvariant() }

    # To might be string or array
    if ($Evidence.Message.To -is [string]) { $toStr = $Evidence.Message.To }
    elseif ($Evidence.Message.To -is [array] -and $Evidence.Message.To.Count -gt 0) { $toStr = $Evidence.Message.To[0] }

    $tm = [regex]::Match($toStr, '(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63})')
    if ($tm.Success -and $fromAddr) {
      $toAddr = $tm.Groups[1].Value.ToLowerInvariant()
      # Check if same domain (spoofed from within org)
      $fromDomain = ($fromAddr -split '@')[1]
      $toDomain = ($toAddr -split '@')[1]
      if ($fromDomain -eq $toDomain) {
        $result.SelfAddressed = $true
        if ($fromAddr -eq $toAddr) {
          $result.Findings.Add("Self-addressed email: From and To are identical ($fromAddr)")
        } else {
          $result.Findings.Add("Intra-domain spoofing: From ($fromAddr) and To ($toAddr) share domain $fromDomain")
        }
      }
    }
  }

  # ── 5. HTML Content Inspection ─────────────────────────────────────────
  if (-not $result.IsEmptyHtmlBody -and $htmlBody) {
    # Scripts
    $scripts = [regex]::Matches($htmlBody, '(?i)<script[^>]*>.*?</script>')
    if ($scripts.Count -gt 0) {
      $result.HtmlFindings += "Found $($scripts.Count) <script> tag(s)"
    }
    # Iframes
    $iframes = [regex]::Matches($htmlBody, '(?i)<iframe[^>]*src\s*=\s*"?([^"\s>]+)')
    foreach ($if in $iframes) {
      $result.HtmlFindings += "iframe src: $($if.Groups[1].Value)"
    }
    # Forms
    $forms = [regex]::Matches($htmlBody, '(?i)<form[^>]*action\s*=\s*"?([^"\s>]+)')
    foreach ($f in $forms) {
      $result.HtmlFindings += "form action: $($f.Groups[1].Value)"
    }
    # Meta refresh
    $metaRefresh = [regex]::Matches($htmlBody, '(?i)<meta[^>]*http-equiv\s*=\s*"refresh"[^>]*content\s*=\s*"([^"]+)"')
    foreach ($mr in $metaRefresh) {
      $result.HtmlFindings += "meta refresh: $($mr.Groups[1].Value)"
    }
    # javascript: links
    $jsLinks = [regex]::Matches($htmlBody, '(?i)href\s*=\s*"?javascript:')
    if ($jsLinks.Count -gt 0) {
      $result.HtmlFindings += "Found $($jsLinks.Count) javascript: link(s)"
    }
    # Base64 data URIs
    $dataUris = [regex]::Matches($htmlBody, '(?i)data:[^;]+;base64,([A-Za-z0-9+/]{50,})')
    if ($dataUris.Count -gt 0) {
      $result.HtmlFindings += "Found $($dataUris.Count) base64 data URI(s)"
    }

    if ($result.HtmlFindings.Count -gt 0) {
      $result.Findings.Add("HTML body analysis: $($result.HtmlFindings.Count) finding(s)")
    }
  }

  # ── 6. Exchange/EOP Header Deep Parse ──────────────────────────────────
  if ($Evidence.Raw.Headers) {
    $norm = ($Evidence.Raw.Headers -replace "(\r?\n)[\t ]+", " ")

    # SCL
    $sclMatch = [regex]::Match($norm, '(?im)^\s*X-MS-Exchange-Organization-SCL\s*:\s*(-?\d+)')
    if ($sclMatch.Success) {
      $result.EopScl = [int]$sclMatch.Groups[1].Value
    }

    # X-Forefront-Antispam-Report
    $ffMatch = [regex]::Match($norm, '(?im)^\s*X-Forefront-Antispam-Report\s*:\s*(.+)$')
    if ($ffMatch.Success) {
      $ffVal = $ffMatch.Groups[1].Value
      $catM = [regex]::Match($ffVal, '(?i)CAT:([A-Z]+)')
      if ($catM.Success) { $result.EopCategory = $catM.Groups[1].Value }
      $sfvM = [regex]::Match($ffVal, '(?i)SFV:([A-Z]+)')
      if ($sfvM.Success) { $result.EopSfv = $sfvM.Groups[1].Value }
      $sclM2 = [regex]::Match($ffVal, '(?i)SCL:(-?\d+)')
      if ($sclM2.Success -and $result.EopScl -eq -2) {
        $result.EopScl = [int]$sclM2.Groups[1].Value
      }
    }

    # X-Microsoft-Antispam ARA rules
    $msAsMatch = [regex]::Match($norm, '(?im)^\s*X-Microsoft-Antispam\s*:\s*(.+)$')
    if ($msAsMatch.Success) {
      $araMatches = [regex]::Matches($msAsMatch.Groups[1].Value, '(\d{5,})')
      foreach ($am in $araMatches) {
        $result.EopAraRules += $am.Groups[1].Value
      }
    }

    # Compauth
    $compMatch = [regex]::Match($norm, '(?i)compauth=([a-z]+)\s+reason=(\d+)')
    if ($compMatch.Success) {
      $result.Compauth.Result = $compMatch.Groups[1].Value
      $result.Compauth.Reason = $compMatch.Groups[2].Value
      $reasonCode = $compMatch.Groups[2].Value
      $result.Compauth.Description = switch -Regex ($reasonCode) {
        '^000$' { "Explicit authentication failure (spoofed)" }
        '^001$' { "Implicit authentication failure" }
        '^002$' { "Sender denied; prohibited from sending unauthenticated" }
        '^1\d\d$' { "Implicit authentication pass" }
        '^2\d\d$' { "Soft pass (authenticated partially)" }
        '^3\d\d$' { "Explicit authentication pass" }
        '^4\d\d$' { "Could not resolve authentication (no record)" }
        '^451$' { "Authentication none - no records found" }
        '^9\d\d$' { "Internal error" }
        default { "Unknown reason code" }
      }
      if ($reasonCode -match '^0') {
        $result.Findings.Add("Compauth: explicit authentication failure (reason=$reasonCode) -- confirmed spoofing")
      }
    }

    # AuthAs
    $authAs = [regex]::Match($norm, '(?im)^\s*X-MS-Exchange-Organization-AuthAs\s*:\s*(\S+)')
    if ($authAs.Success -and $authAs.Groups[1].Value -eq 'Anonymous') {
      $result.Findings.Add("Exchange AuthAs=Anonymous (unauthenticated sender)")
    }
  }

  # Store results on Evidence
  if (-not ($Evidence.PSObject.Properties.Name -contains 'MimeForensics')) {
    $Evidence | Add-Member -NotePropertyName 'MimeForensics' -NotePropertyValue $result -Force
  } else {
    $Evidence.MimeForensics = $result
  }

  return $Evidence
}

# ── Console Display ──────────────────────────────────────────────────────────

function Show-RoninMimeForensics {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Evidence)

  if (-not ($Evidence.PSObject.Properties.Name -contains 'MimeForensics')) {
    "=== RoninMimeForensics: No data ==="
    return
  }
  $mf = $Evidence.MimeForensics

  "=== RoninMimeForensics ==="
  ""
  if ($mf.BoundaryFingerprints.Count -gt 0) {
    "MIME Boundaries:"
    foreach ($bf in $mf.BoundaryFingerprints) {
      "  [{0}] {1}" -f $bf.Classification, $bf.Boundary
    }
    ""
  }

  "Body Analysis:"
  "  HTML body empty:  {0}" -f $mf.IsEmptyHtmlBody
  "  Text body empty:  {0}" -f $mf.IsEmptyTextBody
  "  Bodyless email:   {0}" -f $mf.IsBodylessEmail
  "  Image-only body:  {0}" -f $mf.HasImageOnlyBody
  "  Attachment-only:  {0}" -f $mf.AttachmentOnlyDelivery
  "  Self-addressed:   {0}" -f $mf.SelfAddressed
  ""

  if ($mf.HiddenDataAfterBoundary) {
    "  [ALERT] Hidden data after MIME boundary: {0} bytes" -f $mf.HiddenDataBytes
  }

  if ($mf.EopScl -ne -2) {
    "EOP/Exchange:"
    "  SCL: {0}" -f $mf.EopScl
    "  Category: {0}" -f $mf.EopCategory
    "  SFV: {0}" -f $mf.EopSfv
    if ($mf.Compauth.Result) {
      "  Compauth: {0} (reason={1}: {2})" -f $mf.Compauth.Result, $mf.Compauth.Reason, $mf.Compauth.Description
    }
    if ($mf.EopAraRules.Count -gt 0) {
      "  ARA Rules: {0}" -f ($mf.EopAraRules -join ', ')
    }
    ""
  }

  if ($mf.HtmlFindings.Count -gt 0) {
    "HTML Findings:"
    foreach ($hf in $mf.HtmlFindings) { "  - $hf" }
    ""
  }

  if ($mf.Findings.Count -gt 0) {
    "Forensic Findings:"
    foreach ($f in $mf.Findings) { "  - $f" }
  }
}

Export-ModuleMember -Function Invoke-RoninMimeForensics, Show-RoninMimeForensics
